"""Diff two :class:`~iam_mapper.analyzer.AnalysisResult`\\ s to find newly
introduced or resolved escalation paths between two account snapshots.

Built for a continuous-scanning workflow: run ``iam-mapper collect`` (or
hand-maintain JSON snapshots) at two points in time, ``analyze()`` each,
and diff the results. "Did this deploy open a new escalation path?" is
the question CI actually wants answered -- re-flagging every
pre-existing finding on every run would make that signal useless.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .analyzer import SEVERITY_ORDER, AnalysisResult, Finding


def _finding_key(f: Finding) -> Tuple:
    """A stable identity for a finding across two analysis runs.

    Principal-scoped findings (``self_escalation``/``path``/``already_admin``)
    key on the source alone: a principal has at most one such finding per
    run, so this tracks "did this principal's escalation status change?"
    even if the *technique* or hop count changed too. Trust-hygiene
    findings have no source, so they key on the role + the (deterministic,
    code-generated) summary text instead.
    """
    if f.source is not None:
        return ("principal", f.source)
    return ("trust", f.target, f.summary)


@dataclass
class FindingChange:
    old: Finding
    new: Finding


@dataclass
class FindingsDiff:
    added: List[Finding] = field(default_factory=list)
    removed: List[Finding] = field(default_factory=list)
    changed: List[FindingChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def has_regression(self) -> bool:
        """True if anything got *worse*: a brand-new finding, or an
        existing one whose severity increased (lower index = more severe)."""
        if self.added:
            return True
        return any(
            SEVERITY_ORDER.index(c.new.severity) < SEVERITY_ORDER.index(c.old.severity)
            for c in self.changed
        )


def diff_results(old: AnalysisResult, new: AnalysisResult) -> FindingsDiff:
    old_by_key: Dict[Tuple, Finding] = {_finding_key(f): f for f in old.findings}
    new_by_key: Dict[Tuple, Finding] = {_finding_key(f): f for f in new.findings}

    diff = FindingsDiff()
    for key, new_finding in new_by_key.items():
        old_finding: Optional[Finding] = old_by_key.get(key)
        if old_finding is None:
            diff.added.append(new_finding)
        elif old_finding.kind != new_finding.kind or old_finding.severity != new_finding.severity:
            diff.changed.append(FindingChange(old=old_finding, new=new_finding))

    for key, old_finding in old_by_key.items():
        if key not in new_by_key:
            diff.removed.append(old_finding)

    diff.added.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    diff.removed.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    diff.changed.sort(key=lambda c: SEVERITY_ORDER.index(c.new.severity))
    return diff
