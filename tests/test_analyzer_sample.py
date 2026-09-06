"""End-to-end: every escalation path planted in the synthetic demo account
must be found, and principals with no path must NOT produce a finding.
"""

from iam_mapper.analyzer import analyze
from iam_mapper.synthetic import build_sample_organization


def _findings_by_source(result):
    by_source = {}
    for f in result.findings:
        if f.source:
            by_source.setdefault(f.source, []).append(f)
    return by_source


def test_all_planted_paths_are_found():
    org = build_sample_organization()
    result = analyze(org)
    by_source = _findings_by_source(result)

    assert "alice" in by_source and by_source["alice"][0].kind == "self_escalation"
    assert by_source["alice"][0].severity == "Critical"

    assert "bob" in by_source and by_source["bob"][0].kind == "path"
    assert by_source["bob"][0].severity == "Critical"
    assert len(by_source["bob"][0].hops) == 1

    assert "dave" in by_source and by_source["dave"][0].severity == "Critical"
    assert "erin" in by_source and by_source["erin"][0].severity == "Critical"

    assert "frank" in by_source
    frank_finding = by_source["frank"][0]
    assert frank_finding.kind == "path"
    assert len(frank_finding.hops) == 2
    assert frank_finding.severity == "High"

    assert "audit-role" in by_source and by_source["audit-role"][0].kind == "self_escalation"


def test_clean_principal_has_no_escalation_finding():
    org = build_sample_organization()
    result = analyze(org)
    by_source = _findings_by_source(result)
    # grace is a plain developer with no dangerous IAM permissions.
    assert "grace" not in by_source


def test_existing_admins_are_flagged_info_not_as_paths():
    org = build_sample_organization()
    result = analyze(org)
    already_admin_names = {f.source for f in result.findings if f.kind == "already_admin"}
    assert {"carol", "heather", "ci-role", "data-pipeline-role"} == already_admin_names
    # None of them should also show up as a "path" finding (they're already there).
    assert not any(f.kind == "path" and f.source in already_admin_names for f in result.findings)


def test_external_trust_flagged():
    org = build_sample_organization()
    result = analyze(org)
    external = [f for f in result.findings if f.kind == "external_trust"]
    assert any("vendor-role" in f.summary for f in external)


def test_summary_counts():
    org = build_sample_organization()
    result = analyze(org)
    assert result.total_principals == len(org.all_principals())
    assert result.admin_count == 4
