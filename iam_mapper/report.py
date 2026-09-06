"""Render an :class:`~iam_mapper.analyzer.AnalysisResult` as text or JSON.

Deliberately dependency-free (no ``rich``) so the CLI has nothing to
install beyond ``click`` and ``networkx``.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .analyzer import AnalysisResult, Finding

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


def render_json(result: AnalysisResult) -> str:
    payload = {
        "total_principals": result.total_principals,
        "admin_count": result.admin_count,
        "findings": [
            {
                **{k: v for k, v in asdict(f).items() if k != "hops"},
                "hops": [asdict(h) for h in f.hops],
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2)
