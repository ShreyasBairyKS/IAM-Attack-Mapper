import json

from iam_mapper.analyzer import analyze
from iam_mapper.diff import diff_results
from iam_mapper.report import render_diff_sarif, render_sarif
from iam_mapper.synthetic import build_sample_organization


def test_render_sarif_has_valid_top_level_structure():
    result = analyze(build_sample_organization())
    doc = json.loads(render_sarif(result, source_path="data/sample_org.json"))

    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "iam-attack-mapper"
    assert len(run["results"]) == len(result.findings)


def test_render_sarif_result_shape_and_severity_mapping():
    result = analyze(build_sample_organization())
    doc = json.loads(render_sarif(result, source_path="data/sample_org.json"))
    results = doc["runs"][0]["results"]

    alice_result = next(r for r in results if "alice" in r["message"]["text"])
    assert alice_result["ruleId"] == "self_escalation"
    assert alice_result["level"] == "error"  # Critical -> error
    assert alice_result["properties"]["security-severity"] == "9.5"
    assert alice_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "data/sample_org.json"


def test_render_sarif_rules_catalog_matches_findings_present():
    result = analyze(build_sample_organization())
    doc = json.loads(render_sarif(result, source_path="x.json"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    finding_kinds = {f.kind for f in result.findings}
    assert rule_ids == finding_kinds


def test_render_sarif_empty_findings_still_valid():
    from iam_mapper.models import Organization, User

    org = Organization(account_id="000000000000")
    org.add_user(User(name="grace", arn="arn:aws:iam::000000000000:user/grace"))
    result = analyze(org)

    doc = json.loads(render_sarif(result, source_path="x.json"))
    assert doc["runs"][0]["results"] == []
    # Falls back to the full rule catalog when there are no findings to derive it from.
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 5


def test_render_diff_sarif_excludes_resolved_findings():
    from iam_mapper.models import Organization, Role, TrustStatement, User

    old_org = Organization(account_id="111111111111")
    old_org.add_role(Role(
        name="vendor-role", arn="arn:aws:iam::111111111111:role/vendor-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["*"])],
    ))
    new_org = Organization(account_id="111111111111")
    new_org.add_user(User(name="grace", arn="arn:aws:iam::111111111111:user/grace"))

    d = diff_results(analyze(old_org), analyze(new_org))
    doc = json.loads(render_diff_sarif(d, source_path="current.json"))

    # The vendor-role trust finding was resolved (present in old, gone in new) --
    # it must NOT show up as a live alert.
    assert doc["runs"][0]["results"] == []


def test_render_diff_sarif_includes_added_and_changed():
    from iam_mapper.models import Organization, Policy, Role, Statement, TrustStatement, User

    old_org = Organization(account_id="111111111111")
    old_org.add_user(User(name="grace", arn="arn:aws:iam::111111111111:user/grace"))

    new_org = Organization(account_id="111111111111")
    new_org.add_role(Role(
        name="open-role", arn="arn:aws:iam::111111111111:role/open-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["*"])],
    ))
    new_org.add_policy(Policy(
        name="AppPolicy", arn="arn:aws:iam::111111111111:policy/AppPolicy",
        statements=[Statement(effect="Allow", actions=["s3:*"], resources=["*"])],
    ))
    new_org.add_user(User(
        name="grace", arn="arn:aws:iam::111111111111:user/grace",
        attached_policies=["AppPolicy"],
        inline_policies=[Policy(
            name="mgmt", arn="arn:aws:iam::111111111111:policy/mgmt",
            statements=[Statement(effect="Allow", actions=["iam:CreatePolicyVersion"], resources=["arn:aws:iam::111111111111:policy/AppPolicy"])],
        )],
    ))

    d = diff_results(analyze(old_org), analyze(new_org))
    doc = json.loads(render_diff_sarif(d, source_path="current.json"))

    rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert rule_ids == {"self_escalation", "external_trust"}
