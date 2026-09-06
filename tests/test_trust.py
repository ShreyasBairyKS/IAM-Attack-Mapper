from iam_mapper.models import Organization, Policy, Role, Statement, TrustStatement, User
from iam_mapper.policy_engine import PolicyEngine
from iam_mapper.trust import find_assume_role_edges, find_external_trusts


def _account():
    return Organization(account_id="111111111111")


# --------------------------------------------------------------------------
# find_assume_role_edges
# --------------------------------------------------------------------------


def test_assume_role_edge_found_when_trusted_and_allowed():
    org = _account()
    org.add_user(User(
        name="bob", arn="arn:aws:iam::111111111111:user/bob",
        inline_policies=[Policy(
            name="p", arn="arn:aws:iam::111111111111:policy/p",
            statements=[Statement(effect="Allow", actions=["sts:AssumeRole"], resources=["arn:aws:iam::111111111111:role/target-role"])],
        )],
    ))
    org.add_role(Role(
        name="target-role", arn="arn:aws:iam::111111111111:role/target-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["arn:aws:iam::111111111111:user/bob"])],
    ))

    edges = list(find_assume_role_edges(org, PolicyEngine(org)))
    assert any(e.source == "bob" and e.target == "target-role" and not e.conditional for e in edges)


def test_assume_role_edge_conditional_when_allow_has_condition():
    org = _account()
    org.add_user(User(
        name="bob", arn="arn:aws:iam::111111111111:user/bob",
        inline_policies=[Policy(
            name="p", arn="arn:aws:iam::111111111111:policy/p",
            statements=[Statement(
                effect="Allow", actions=["sts:AssumeRole"], resources=["arn:aws:iam::111111111111:role/target-role"],
                condition={"StringEquals": {"aws:PrincipalTag/mfa": "true"}},
            )],
        )],
    ))
    org.add_role(Role(
        name="target-role", arn="arn:aws:iam::111111111111:role/target-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["arn:aws:iam::111111111111:user/bob"])],
    ))

    edges = list(find_assume_role_edges(org, PolicyEngine(org)))
    assert any(e.source == "bob" and e.conditional for e in edges)


def test_assume_role_not_yielded_when_identity_policy_does_not_allow():
    org = _account()
    # bob is trusted by the role, but never granted sts:AssumeRole himself.
    org.add_user(User(name="bob", arn="arn:aws:iam::111111111111:user/bob"))
    org.add_role(Role(
        name="target-role", arn="arn:aws:iam::111111111111:role/target-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["arn:aws:iam::111111111111:user/bob"])],
    ))

    edges = list(find_assume_role_edges(org, PolicyEngine(org)))
    assert edges == []


def test_trust_statement_with_deny_effect_is_skipped():
    org = _account()
    org.add_user(User(
        name="bob", arn="arn:aws:iam::111111111111:user/bob",
        inline_policies=[Policy(
            name="p", arn="arn:aws:iam::111111111111:policy/p",
            statements=[Statement(effect="Allow", actions=["sts:AssumeRole"], resources=["*"])],
        )],
    ))
    org.add_role(Role(
        name="target-role", arn="arn:aws:iam::111111111111:role/target-role",
        trust_statements=[TrustStatement(effect="Deny", principals=["arn:aws:iam::111111111111:user/bob"])],
    ))

    edges = list(find_assume_role_edges(org, PolicyEngine(org)))
    assert edges == []


def test_trust_statement_without_assume_role_action_is_skipped():
    org = _account()
    org.add_user(User(
        name="bob", arn="arn:aws:iam::111111111111:user/bob",
        inline_policies=[Policy(
            name="p", arn="arn:aws:iam::111111111111:policy/p",
            statements=[Statement(effect="Allow", actions=["sts:AssumeRole"], resources=["*"])],
        )],
    ))
    org.add_role(Role(
        name="target-role", arn="arn:aws:iam::111111111111:role/target-role",
        # Trust policy only permits tagging the session, not assuming the role.
        trust_statements=[TrustStatement(
            effect="Allow", principals=["arn:aws:iam::111111111111:user/bob"], actions=["sts:TagSession"],
        )],
    ))

    edges = list(find_assume_role_edges(org, PolicyEngine(org)))
    assert edges == []


def test_service_principal_in_trust_policy_is_skipped():
    org = _account()
    org.add_role(Role(
        name="target-role", arn="arn:aws:iam::111111111111:role/target-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["lambda.amazonaws.com"])],
    ))

    edges = list(find_assume_role_edges(org, PolicyEngine(org)))
    assert edges == []


# --------------------------------------------------------------------------
# find_external_trusts
# --------------------------------------------------------------------------


def test_wildcard_trust_flagged():
    org = _account()
    org.add_role(Role(
        name="open-role", arn="arn:aws:iam::111111111111:role/open-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["*"])],
    ))

    findings = find_external_trusts(org, "111111111111")
    assert len(findings) == 1
    assert findings[0].role == "open-role"
    assert findings[0].principal_ref == "*"
    assert "wildcard" in findings[0].note


def test_external_account_trust_flagged():
    org = _account()
    org.add_role(Role(
        name="vendor-role", arn="arn:aws:iam::111111111111:role/vendor-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["arn:aws:iam::999999999999:root"])],
    ))

    findings = find_external_trusts(org, "111111111111")
    assert len(findings) == 1
    assert findings[0].role == "vendor-role"
    assert "different AWS account" in findings[0].note


def test_same_account_trust_not_flagged():
    org = _account()
    org.add_role(Role(
        name="internal-role", arn="arn:aws:iam::111111111111:role/internal-role",
        trust_statements=[TrustStatement(effect="Allow", principals=["arn:aws:iam::111111111111:role/some-other-role"])],
    ))

    assert find_external_trusts(org, "111111111111") == []


def test_deny_trust_statement_not_flagged():
    org = _account()
    org.add_role(Role(
        name="guarded-role", arn="arn:aws:iam::111111111111:role/guarded-role",
        trust_statements=[TrustStatement(effect="Deny", principals=["*"])],
    ))

    assert find_external_trusts(org, "111111111111") == []
