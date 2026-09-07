import json

from iam_mapper.analyzer import analyze
from iam_mapper.diff import diff_results
from iam_mapper.models import Organization, Policy, Role, Statement, TrustStatement, User
from iam_mapper.report import render_diff_json, render_diff_text


def _account():
    return Organization(account_id="111111111111")


def test_diff_no_changes_between_identical_snapshots():
    org = _account()
    org.add_user(User(name="grace", arn="arn:aws:iam::111111111111:user/grace"))

    d = diff_results(analyze(org), analyze(org))

    assert not d.has_changes
    assert not d.has_regression()
    assert d.added == d.removed == d.changed == []


def test_diff_detects_newly_introduced_self_escalation():
    old_org = _account()
    old_org.add_user(User(name="grace", arn="arn:aws:iam::111111111111:user/grace"))

    new_org = _account()
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

    assert d.has_changes
    assert d.has_regression()
    assert len(d.added) == 1
    assert d.added[0].source == "grace"
    assert d.added[0].kind == "self_escalation"
    assert not d.removed
    assert not d.changed


def test_diff_detects_resolved_finding():
    # Same two orgs as above, but reversed: a finding that disappears.
    old_org = _account()
    old_org.add_policy(Policy(
        name="AppPolicy", arn="arn:aws:iam::111111111111:policy/AppPolicy",
        statements=[Statement(effect="Allow", actions=["s3:*"], resources=["*"])],
    ))
    old_org.add_user(User(
        name="grace", arn="arn:aws:iam::111111111111:user/grace",
        attached_policies=["AppPolicy"],
        inline_policies=[Policy(
            name="mgmt", arn="arn:aws:iam::111111111111:policy/mgmt",
            statements=[Statement(effect="Allow", actions=["iam:CreatePolicyVersion"], resources=["arn:aws:iam::111111111111:policy/AppPolicy"])],
        )],
    ))

    new_org = _account()
    new_org.add_user(User(name="grace", arn="arn:aws:iam::111111111111:user/grace"))

    d = diff_results(analyze(old_org), analyze(new_org))

    assert not d.has_regression()  # remediation, not a regression
    assert len(d.removed) == 1
    assert d.removed[0].source == "grace"
    assert not d.added
    assert not d.changed


def test_diff_detects_severity_increase_as_changed_and_regression():
    def _base_org():
        org = _account()
        org.add_policy(Policy(name="SecurityAuditRO", arn="arn:aws:iam::111111111111:policy/SecurityAuditRO",
                               statements=[Statement(effect="Allow", actions=["iam:Get*"], resources=["*"])]))
        org.add_user(User(
            name="u", arn="arn:aws:iam::111111111111:user/u",
            inline_policies=[Policy(
                name="ops", arn="arn:aws:iam::111111111111:policy/ops",
                statements=[Statement(effect="Allow", actions=["iam:UpdateAssumeRolePolicy"], resources=["arn:aws:iam::111111111111:role/mid-role"])],
            )],
        ))
        org.add_role(Role(
            name="mid-role", arn="arn:aws:iam::111111111111:role/mid-role",
            attached_policies=["SecurityAuditRO"],
            inline_policies=[Policy(
                name="self-manage", arn="arn:aws:iam::111111111111:policy/self-manage",
                statements=[Statement(effect="Allow", actions=["iam:AttachRolePolicy"], resources=["arn:aws:iam::111111111111:role/mid-role"])],
            )],
        ))
        return org

    old_org = _base_org()  # u -> mid-role -> self-attach: 2-hop path, High
    new_org = _base_org()
    # u also gains a *direct* self-escalation: 1-hop, Critical -- supersedes the path finding.
    new_org.users["u"].inline_policies.append(Policy(
        name="self-attach", arn="arn:aws:iam::111111111111:policy/self-attach",
        statements=[Statement(effect="Allow", actions=["iam:AttachUserPolicy"], resources=["arn:aws:iam::111111111111:user/u"])],
    ))

    old_result = analyze(old_org)
    new_result = analyze(new_org)
    u_old = next(f for f in old_result.findings if f.source == "u")
    u_new = next(f for f in new_result.findings if f.source == "u")
    assert u_old.kind == "path" and u_old.severity == "High"
    assert u_new.kind == "self_escalation" and u_new.severity == "Critical"

    d = diff_results(old_result, new_result)

    assert not d.added
    assert not d.removed
    assert len(d.changed) == 1
    assert d.changed[0].old.severity == "High"
    assert d.changed[0].new.severity == "Critical"
    assert d.has_regression()


def test_diff_external_trust_added_and_removed():
    old_org = _account()
    old_org.add_role(Role(
        name="vendor-role", arn="arn:aws:iam::111111111111:role/vendor-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["arn:aws:iam::999999999999:root"])],
    ))

    new_org = _account()
    new_org.add_role(Role(
        name="vendor-role", arn="arn:aws:iam::111111111111:role/vendor-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["*"])],
    ))

    d = diff_results(analyze(old_org), analyze(new_org))

    assert len(d.added) == 1 and d.added[0].kind == "external_trust" and "wildcard" in d.added[0].summary
    assert len(d.removed) == 1 and d.removed[0].kind == "external_trust" and "different AWS account" in d.removed[0].summary
    assert d.has_regression()


def test_render_diff_text_reports_counts_and_no_changes_message():
    org = _account()
    org.add_user(User(name="grace", arn="arn:aws:iam::111111111111:user/grace"))
    d = diff_results(analyze(org), analyze(org))

    text = render_diff_text(d, use_color=False)
    assert "Diff Report" in text
    assert "No changes between the two snapshots." in text
    assert "\033[" not in text


def test_render_diff_text_shows_new_finding():
    old_org = _account()
    old_org.add_user(User(name="grace", arn="arn:aws:iam::111111111111:user/grace"))
    new_org = _account()
    new_org.add_role(Role(
        name="open-role", arn="arn:aws:iam::111111111111:role/open-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["*"])],
    ))

    d = diff_results(analyze(old_org), analyze(new_org))
    text = render_diff_text(d, use_color=False)
    assert "New findings     : 1" in text
    assert "open-role" in text


def test_render_diff_text_shows_resolved_finding():
    old_org = _account()
    old_org.add_role(Role(
        name="open-role", arn="arn:aws:iam::111111111111:role/open-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["*"])],
    ))
    new_org = _account()
    new_org.add_user(User(name="grace", arn="arn:aws:iam::111111111111:user/grace"))

    d = diff_results(analyze(old_org), analyze(new_org))
    text = render_diff_text(d, use_color=False)
    assert "Resolved findings: 1" in text
    assert "RESOLVED" in text
    assert "open-role" in text


def test_render_diff_text_shows_changed_finding():
    def _base_org():
        org = _account()
        org.add_policy(Policy(name="SecurityAuditRO", arn="arn:aws:iam::111111111111:policy/SecurityAuditRO",
                               statements=[Statement(effect="Allow", actions=["iam:Get*"], resources=["*"])]))
        org.add_user(User(
            name="u", arn="arn:aws:iam::111111111111:user/u",
            inline_policies=[Policy(
                name="ops", arn="arn:aws:iam::111111111111:policy/ops",
                statements=[Statement(effect="Allow", actions=["iam:UpdateAssumeRolePolicy"], resources=["arn:aws:iam::111111111111:role/mid-role"])],
            )],
        ))
        org.add_role(Role(
            name="mid-role", arn="arn:aws:iam::111111111111:role/mid-role",
            attached_policies=["SecurityAuditRO"],
            inline_policies=[Policy(
                name="self-manage", arn="arn:aws:iam::111111111111:policy/self-manage",
                statements=[Statement(effect="Allow", actions=["iam:AttachRolePolicy"], resources=["arn:aws:iam::111111111111:role/mid-role"])],
            )],
        ))
        return org

    old_org = _base_org()
    new_org = _base_org()
    new_org.users["u"].inline_policies.append(Policy(
        name="self-attach", arn="arn:aws:iam::111111111111:policy/self-attach",
        statements=[Statement(effect="Allow", actions=["iam:AttachUserPolicy"], resources=["arn:aws:iam::111111111111:user/u"])],
    ))

    d = diff_results(analyze(old_org), analyze(new_org))
    text = render_diff_text(d, use_color=False)
    assert "Changed findings : 1" in text
    assert "High -> Critical" in text


def test_render_diff_json_round_trips():
    old_org = _account()
    old_org.add_user(User(name="grace", arn="arn:aws:iam::111111111111:user/grace"))
    new_org = _account()
    new_org.add_role(Role(
        name="open-role", arn="arn:aws:iam::111111111111:role/open-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["*"])],
    ))

    d = diff_results(analyze(old_org), analyze(new_org))
    payload = json.loads(render_diff_json(d))
    assert set(payload) == {"added", "removed", "changed"}
    assert len(payload["added"]) == 1
    assert payload["added"][0]["target"] == "open-role"
