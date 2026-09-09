from iam_mapper.models import Organization, Policy, Statement, User
from iam_mapper.policy_engine import PolicyEngine


def _org_with_user(statements, boundary_statements=None):
    org = Organization(account_id="111111111111")
    org.add_policy(Policy(name="Inline", arn="arn:aws:iam::111111111111:policy/Inline", statements=statements))
    boundary_name = None
    if boundary_statements is not None:
        org.add_policy(Policy(name="Boundary", arn="arn:aws:iam::111111111111:policy/Boundary", statements=boundary_statements))
        boundary_name = "Boundary"
    org.add_user(User(
        name="u", arn="arn:aws:iam::111111111111:user/u",
        attached_policies=["Inline"], permissions_boundary=boundary_name,
    ))
    return org


def test_simple_allow():
    org = _org_with_user([Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"])])
    engine = PolicyEngine(org)
    assert engine.is_allowed("u", "s3:GetObject").allowed
    assert not engine.is_allowed("u", "s3:PutObject").allowed


def test_wildcard_action_and_resource():
    org = _org_with_user([Statement(effect="Allow", actions=["s3:*"], resources=["arn:aws:s3:::my-bucket/*"])])
    engine = PolicyEngine(org)
    assert engine.is_allowed("u", "s3:GetObject", "arn:aws:s3:::my-bucket/key").allowed
    assert not engine.is_allowed("u", "s3:GetObject", "arn:aws:s3:::other-bucket/key").allowed
    # Asking about "*" (any resource) should NOT match a resource-scoped statement.
    assert not engine.is_allowed("u", "s3:GetObject", "*").allowed


def test_explicit_deny_wins_over_allow():
    org = _org_with_user([
        Statement(effect="Allow", actions=["*"], resources=["*"]),
        Statement(effect="Deny", actions=["iam:*"], resources=["*"]),
    ])
    engine = PolicyEngine(org)
    assert engine.is_allowed("u", "s3:GetObject").allowed
    assert not engine.is_allowed("u", "iam:CreateUser").allowed


def test_permissions_boundary_restricts_but_never_grants():
    allow_all = [Statement(effect="Allow", actions=["*"], resources=["*"])]
    narrow_boundary = [Statement(effect="Allow", actions=["s3:Get*"], resources=["*"])]
    org = _org_with_user(allow_all, boundary_statements=narrow_boundary)
    engine = PolicyEngine(org)
    assert engine.is_allowed("u", "s3:GetObject").allowed
    assert not engine.is_allowed("u", "iam:CreateUser").allowed  # boundary doesn't cover this


def test_not_action_inverts_match():
    org = _org_with_user([Statement(effect="Allow", actions=["iam:*"], resources=["*"], not_action=True)])
    engine = PolicyEngine(org)
    # NotAction "iam:*" means "everything except iam:*"
    assert engine.is_allowed("u", "s3:GetObject").allowed
    assert not engine.is_allowed("u", "iam:CreateUser").allowed


def test_conditional_allow_is_flagged():
    org = _org_with_user([
        Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"], condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}),
    ])
    engine = PolicyEngine(org)
    result = engine.is_allowed("u", "s3:GetObject")
    assert result.allowed
    assert result.conditional


def test_is_admin_true_for_administrator_access_shape():
    org = _org_with_user([Statement(effect="Allow", actions=["*"], resources=["*"])])
    engine = PolicyEngine(org)
    assert engine.is_admin("u")


def test_is_admin_true_for_full_iam_control():
    org = _org_with_user([Statement(effect="Allow", actions=["iam:*"], resources=["*"])])
    engine = PolicyEngine(org)
    assert engine.is_admin("u")


def test_is_admin_false_for_ordinary_access():
    org = _org_with_user([Statement(effect="Allow", actions=["s3:*"], resources=["*"])])
    engine = PolicyEngine(org)
    assert not engine.is_admin("u")


# --------------------------------------------------------------------------
# Service Control Policies -- same "can only narrow, never grant" ceiling
# semantics as a permissions boundary, but applied at the account level.
# --------------------------------------------------------------------------


def test_scp_blocks_action_not_in_its_allow_list():
    org = _org_with_user([Statement(effect="Allow", actions=["*"], resources=["*"])])
    org.scps = [Policy(
        name="DenyIAM", arn="arn:aws:organizations::111111111111:policy/p-1",
        statements=[Statement(effect="Allow", actions=["s3:*", "ec2:*"], resources=["*"])],
    )]
    engine = PolicyEngine(org)
    assert engine.is_allowed("u", "s3:GetObject").allowed
    assert not engine.is_allowed("u", "iam:CreateUser").allowed  # not in the SCP's allow list


def test_scp_explicit_deny_blocks_even_with_full_allow_list():
    org = _org_with_user([Statement(effect="Allow", actions=["*"], resources=["*"])])
    org.scps = [Policy(
        name="DenyIAM", arn="arn:aws:organizations::111111111111:policy/p-1",
        statements=[
            Statement(effect="Allow", actions=["*"], resources=["*"]),
            Statement(effect="Deny", actions=["iam:*"], resources=["*"]),
        ],
    )]
    engine = PolicyEngine(org)
    assert engine.is_allowed("u", "s3:GetObject").allowed
    assert not engine.is_allowed("u", "iam:CreateUser").allowed


def test_scp_full_aws_access_does_not_restrict_anything():
    # The default AWS-managed SCP: Allow */* -- should behave identically
    # to having no SCPs at all.
    org = _org_with_user([Statement(effect="Allow", actions=["iam:*"], resources=["*"])])
    org.scps = [Policy(
        name="FullAWSAccess", arn="arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess",
        statements=[Statement(effect="Allow", actions=["*"], resources=["*"])],
    )]
    engine = PolicyEngine(org)
    assert engine.is_admin("u")


def test_multiple_scps_intersect_not_union():
    org = _org_with_user([Statement(effect="Allow", actions=["*"], resources=["*"])])
    # Root-level SCP allows s3 and iam; account-level SCP allows only s3.
    # The account only gets what BOTH permit: s3 only.
    org.scps = [
        Policy(name="RootSCP", arn="arn:aws:organizations::111111111111:policy/p-root",
               statements=[Statement(effect="Allow", actions=["s3:*", "iam:*"], resources=["*"])]),
        Policy(name="AccountSCP", arn="arn:aws:organizations::111111111111:policy/p-acct",
               statements=[Statement(effect="Allow", actions=["s3:*"], resources=["*"])]),
    ]
    engine = PolicyEngine(org)
    assert engine.is_allowed("u", "s3:GetObject").allowed
    assert not engine.is_allowed("u", "iam:CreateUser").allowed


def test_scp_restricting_iam_prevents_false_admin_positive():
    # Without the SCP this principal would be admin-equivalent; the SCP
    # caps the whole account below full IAM control.
    org = _org_with_user([Statement(effect="Allow", actions=["*"], resources=["*"])])
    org.scps = [Policy(
        name="NoIAM", arn="arn:aws:organizations::111111111111:policy/p-1",
        statements=[Statement(effect="Allow", actions=["s3:*", "ec2:*", "lambda:*"], resources=["*"])],
    )]
    engine = PolicyEngine(org)
    assert not engine.is_admin("u")


def test_group_inherited_policy():
    from iam_mapper.models import Group

    org = Organization(account_id="111111111111")
    org.add_policy(Policy(
        name="GroupPolicy", arn="arn:aws:iam::111111111111:policy/GroupPolicy",
        statements=[Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"])],
    ))
    org.add_group(Group(name="g", arn="arn:aws:iam::111111111111:group/g", attached_policies=["GroupPolicy"], members=["u"]))
    org.add_user(User(name="u", arn="arn:aws:iam::111111111111:user/u", groups=["g"]))
    engine = PolicyEngine(org)
    assert engine.is_allowed("u", "s3:GetObject").allowed
    assert not engine.is_allowed("u", "s3:PutObject").allowed
