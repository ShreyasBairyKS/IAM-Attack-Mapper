from iam_mapper.escalation_rules import all_escalation_edges
from iam_mapper.models import Organization, Policy, Role, Statement, TrustStatement, User
from iam_mapper.policy_engine import PolicyEngine


def _account():
    return Organization(account_id="111111111111")


def test_create_access_key_escalation_detected():
    org = _account()
    org.add_user(User(
        name="attacker", arn="arn:aws:iam::111111111111:user/attacker",
        inline_policies=[Policy(
            name="p", arn="arn:aws:iam::111111111111:policy/p",
            statements=[Statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"])],
        )],
    ))
    org.add_user(User(name="victim-admin", arn="arn:aws:iam::111111111111:user/victim-admin", attached_policies=["Admin"]))
    org.add_policy(Policy(name="Admin", arn="arn:aws:iam::aws:policy/Admin", statements=[Statement(effect="Allow", actions=["*"], resources=["*"])]))

    edges = all_escalation_edges(org)
    techniques = {(e.source, e.target, e.technique) for e in edges}
    assert ("attacker", "victim-admin", "CreateAccessKey") in techniques


def test_create_access_key_scoped_to_self_is_not_escalation():
    org = _account()
    org.add_user(User(
        name="u", arn="arn:aws:iam::111111111111:user/u",
        inline_policies=[Policy(
            name="p", arn="arn:aws:iam::111111111111:policy/p",
            statements=[Statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["arn:aws:iam::111111111111:user/u"])],
        )],
    ))
    org.add_user(User(name="other", arn="arn:aws:iam::111111111111:user/other", attached_policies=["Admin"]))
    org.add_policy(Policy(name="Admin", arn="arn:aws:iam::aws:policy/Admin", statements=[Statement(effect="Allow", actions=["*"], resources=["*"])]))

    edges = all_escalation_edges(org)
    assert not any(e.source == "u" and e.target == "other" for e in edges)


def test_pass_role_lambda_requires_matching_trust():
    org = _account()
    org.add_user(User(
        name="u", arn="arn:aws:iam::111111111111:user/u",
        inline_policies=[Policy(
            name="p", arn="arn:aws:iam::111111111111:policy/p",
            statements=[
                Statement(effect="Allow", actions=["iam:PassRole"], resources=["arn:aws:iam::111111111111:role/target-role"]),
                Statement(effect="Allow", actions=["lambda:CreateFunction", "lambda:InvokeFunction"]),
                Statement(effect="Allow", actions=["ec2:RunInstances"]),
            ],
        )],
    ))
    # Role trusts EC2, not Lambda -- PassRole+Lambda should NOT fire (but
    # PassRole+EC2 should, since the user also holds ec2:RunInstances).
    org.add_role(Role(
        name="target-role", arn="arn:aws:iam::111111111111:role/target-role",
        attached_policies=["Admin"],
        trust_statements=[TrustStatement(effect="Allow", principals=["ec2.amazonaws.com"])],
    ))
    org.add_policy(Policy(name="Admin", arn="arn:aws:iam::aws:policy/Admin", statements=[Statement(effect="Allow", actions=["*"], resources=["*"])]))

    edges = all_escalation_edges(org)
    assert not any(e.technique == "PassRole+Lambda" for e in edges)
    assert any(e.technique == "PassRole+EC2" and e.source == "u" and e.target == "target-role" for e in edges)


def test_policy_version_escalation_self():
    org = _account()
    org.add_policy(Policy(name="AppPolicy", arn="arn:aws:iam::111111111111:policy/AppPolicy", statements=[Statement(effect="Allow", actions=["s3:*"], resources=["*"])]))
    org.add_user(User(
        name="u", arn="arn:aws:iam::111111111111:user/u",
        attached_policies=["AppPolicy"],
        inline_policies=[Policy(
            name="mgmt", arn="arn:aws:iam::111111111111:policy/mgmt",
            statements=[Statement(effect="Allow", actions=["iam:CreatePolicyVersion"], resources=["arn:aws:iam::111111111111:policy/AppPolicy"])],
        )],
    ))
    edges = all_escalation_edges(org)
    assert any(e.source == "u" and e.target == "u" and e.technique == "PolicyVersionEscalation" for e in edges)


def test_aws_managed_policy_cannot_be_versioned():
    org = _account()
    org.add_policy(Policy(name="AdministratorAccess", arn="arn:aws:iam::aws:policy/AdministratorAccess", aws_managed=True, statements=[Statement(effect="Allow", actions=["*"], resources=["*"])]))
    org.add_user(User(
        name="u", arn="arn:aws:iam::111111111111:user/u",
        attached_policies=["AdministratorAccess"],
        inline_policies=[Policy(
            name="mgmt", arn="arn:aws:iam::111111111111:policy/mgmt",
            statements=[Statement(effect="Allow", actions=["iam:CreatePolicyVersion"], resources=["*"])],
        )],
    ))
    edges = all_escalation_edges(org)
    assert not any(e.technique == "PolicyVersionEscalation" for e in edges)
