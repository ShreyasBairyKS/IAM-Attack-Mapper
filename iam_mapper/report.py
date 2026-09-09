"""Render an :class:`~iam_mapper.analyzer.AnalysisResult` as text or JSON.

Deliberately dependency-free (no ``rich``) so the CLI has nothing to
install beyond ``click`` and ``networkx``.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .analyzer import AnalysisResult, Finding
from .diff import FindingsDiff

_COLOR = {
    "Critical": "\033[1;91m",
    "High": "\033[91m",
    "Medium": "\033[93m",
    "Low": "\033[94m",
    "Info": "\033[90m",
}
_RESET = "\033[0m"

_KIND_LABEL = {
    "self_escalation": "SELF-ESCALATION",
    "path": "ESCALATION PATH",
    "already_admin": "EXISTING ADMIN",
    "external_trust": "TRUST POLICY HYGIENE",
    "external_resource_trust": "RESOURCE POLICY HYGIENE",
}


def _colorize(text: str, severity: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_COLOR.get(severity, '')}{text}{_RESET}"


def render_text(result: AnalysisResult, use_color: bool = True) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append("IAM Attack-Path Mapper -- Report")
    lines.append("=" * 72)
    lines.append(f"Principals analyzed : {result.total_principals}")
    lines.append(f"Already admin        : {result.admin_count}")
    lines.append(f"Findings             : {len(result.findings)}")
    lines.append("")

    if not result.findings:
        lines.append("No findings. (Either the account is clean, or nothing was loaded.)")
        return "\n".join(lines)

    for finding in result.findings:
        header = f"[{finding.severity}] {_KIND_LABEL.get(finding.kind, finding.kind)}"
        lines.append(_colorize(header, finding.severity, use_color))
        if finding.hops:
            lines.append("  " + finding.render_path())
            for hop in finding.hops:
                cond = "  (conditional -- depends on IAM Condition keys)" if hop.conditional else ""
                lines.append(f"    - {hop.technique}: {hop.detail}{cond}")
        else:
            lines.append("  " + finding.summary)
        lines.append("")

    return "\n".join(lines)


def _finding_to_dict(finding: Finding) -> dict:
    return {
        **{k: v for k, v in asdict(finding).items() if k != "hops"},
        "hops": [asdict(h) for h in finding.hops],
    }


def render_json(result: AnalysisResult) -> str:
    payload = {
        "total_principals": result.total_principals,
        "admin_count": result.admin_count,
        "findings": [_finding_to_dict(f) for f in result.findings],
    }
    return json.dumps(payload, indent=2)


def _finding_line(finding: Finding) -> str:
    return finding.render_path() if finding.hops else finding.summary


def render_diff_text(diff: FindingsDiff, use_color: bool = True) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append("IAM Attack-Path Mapper -- Diff Report")
    lines.append("=" * 72)
    lines.append(f"New findings     : {len(diff.added)}")
    lines.append(f"Changed findings : {len(diff.changed)}")
    lines.append(f"Resolved findings: {len(diff.removed)}")
    lines.append("")

    if not diff.has_changes:
        lines.append("No changes between the two snapshots.")
        return "\n".join(lines)

    if diff.added:
        lines.append("-- NEW " + "-" * 64)
        for f in diff.added:
            header = f"[{f.severity}] NEW: {_KIND_LABEL.get(f.kind, f.kind)}"
            lines.append(_colorize(header, f.severity, use_color))
            lines.append("  " + _finding_line(f))
            lines.append("")

    if diff.changed:
        lines.append("-- CHANGED " + "-" * 60)
        for c in diff.changed:
            header = f"[{c.old.severity} -> {c.new.severity}] {_KIND_LABEL.get(c.new.kind, c.new.kind)}"
            lines.append(_colorize(header, c.new.severity, use_color))
            lines.append("  " + _finding_line(c.new))
            lines.append("")

    if diff.removed:
        lines.append("-- RESOLVED " + "-" * 59)
        for f in diff.removed:
            lines.append(f"[{f.severity}] RESOLVED: {_KIND_LABEL.get(f.kind, f.kind)}")
            lines.append("  " + _finding_line(f))
            lines.append("")

    return "\n".join(lines)


def render_diff_json(diff: FindingsDiff) -> str:
    payload = {
        "added": [_finding_to_dict(f) for f in diff.added],
        "removed": [_finding_to_dict(f) for f in diff.removed],
        "changed": [
            {"old": _finding_to_dict(c.old), "new": _finding_to_dict(c.new)}
            for c in diff.changed
        ],
    }
    return json.dumps(payload, indent=2)


# --------------------------------------------------------------------------
# SARIF 2.1.0, for GitHub code scanning / any SARIF-consuming tool.
# --------------------------------------------------------------------------

_TOOL_VERSION = "0.1.0"
_TOOL_INFO_URI = "https://github.com/ShreyasBairyKS/IAM-Attack-Mapper"

# error/warning/note per GitHub's recommended severity->level mapping.
_SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
# GitHub's "Security severity" badge (0.0-10.0, CVSS-like).
_SARIF_SECURITY_SEVERITY = {"Critical": "9.5", "High": "7.5", "Medium": "5.0", "Low": "3.0", "Info": "0.0"}

_SARIF_RULES = {
    "self_escalation": ("SelfEscalation", "Principal can directly escalate its own privileges to admin-equivalent access."),
    "path": ("EscalationPath", "Principal can reach admin-equivalent access via one or more privilege-escalation techniques."),
    "already_admin": ("ExistingAdmin", "Principal already has admin-equivalent (\"*\"/\"*\" or iam:*) access."),
    "external_trust": ("TrustPolicyHygiene", "Role's trust policy trusts an external AWS account or a wildcard principal."),
    "external_resource_trust": ("ResourcePolicyHygiene", "A resource's policy (e.g. S3 bucket policy) trusts an external AWS account or a wildcard principal."),
}


def _sarif_rule(kind: str) -> dict:
    name, description = _SARIF_RULES.get(kind, (kind, kind))
    return {
        "id": kind,
        "name": name,
        "shortDescription": {"text": description},
        "defaultConfiguration": {"level": "warning"},
    }


def _sarif_result(finding: Finding, artifact_uri: str) -> dict:
    return {
        "ruleId": finding.kind,
        "level": _SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {"text": _finding_line(finding)},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": artifact_uri},
                "region": {"startLine": 1},
            },
        }],
        "properties": {
            "security-severity": _SARIF_SECURITY_SEVERITY.get(finding.severity, "0.0"),
            "tags": ["security", finding.kind],
        },
    }


def _sarif_document(findings: list[Finding], artifact_uri: str) -> dict:
    kinds_present = sorted({f.kind for f in findings}) or list(_SARIF_RULES)
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "iam-attack-mapper",
                    "informationUri": _TOOL_INFO_URI,
                    "version": _TOOL_VERSION,
                    "rules": [_sarif_rule(k) for k in kinds_present],
                },
            },
            "results": [_sarif_result(f, artifact_uri) for f in findings],
        }],
    }


def render_sarif(result: AnalysisResult, source_path: str = "account.json") -> str:
    """SARIF has no notion of "principal"/"account" -- results are anchored
    to the account snapshot file that was analyzed (line 1), same as other
    non-file-based scanners do when there's no real source location."""
    return json.dumps(_sarif_document(result.findings, source_path), indent=2)


def render_diff_sarif(diff: FindingsDiff, source_path: str = "account.json") -> str:
    """Only `added` and `changed` (in their *new* state) are live alerts --
    `removed` findings are resolved and shouldn't show up as active issues."""
    findings = list(diff.added) + [c.new for c in diff.changed]
    return json.dumps(_sarif_document(findings, source_path), indent=2)
