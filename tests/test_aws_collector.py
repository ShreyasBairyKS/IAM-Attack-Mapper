"""Tests for iam_mapper.aws_collector.

Policy-document normalization is tested with plain dicts (no AWS calls at
all). Live collection is tested against `moto`'s in-process IAM mock --
no real AWS account, network access, or credentials required.
"""

import json
import pathlib
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from iam_mapper.analyzer import analyze
from iam_mapper.aws_collector import (
    _collect_s3_bucket_policies,
    _collect_scps,
    _permissions_boundary_name,
    collect_organization,
    normalize_policy_document,
    normalize_principals,
    normalize_resource_policy_document,
    normalize_statement,
    normalize_trust_document,
)
from iam_mapper.models import Policy
from iam_mapper.policy_engine import PolicyEngine
from iam_mapper.trust import find_assume_role_edges


class _FakePolicyCache:
    """Stand-in for _PolicyCache -- returns a policy without any AWS calls."""

    def get(self, arn):
        return Policy(name="boundary-policy", arn=arn, statements=[])

pytest.importorskip("boto3")


# --------------------------------------------------------------------------
# Pure normalization helpers
# --------------------------------------------------------------------------


def test_normalize_principals_wildcard_and_string():
    assert normalize_principals("*") == ["*"]
    assert normalize_principals("ec2.amazonaws.com") == ["ec2.amazonaws.com"]


def test_normalize_principals_dict_flattens_all_kinds():
    principal = {
        "AWS": ["arn:aws:iam::111111111111:role/a", "arn:aws:iam::111111111111:role/b"],
        "Service": "lambda.amazonaws.com",
    }
    assert normalize_principals(principal) == [
        "arn:aws:iam::111111111111:role/a",
        "arn:aws:iam::111111111111:role/b",
        "lambda.amazonaws.com",
    ]


def test_normalize_principals_empty_dict():
    assert normalize_principals({}) == []


def test_normalize_principals_unrecognized_type_returns_empty():
    assert normalize_principals(None) == []
    assert normalize_principals(42) == []


def test_normalize_statement_accepts_single_string_action_and_resource():
    stmt = normalize_statement({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"})
    assert stmt.effect == "Allow"
    assert stmt.actions == ["s3:GetObject"]
    assert stmt.resources == ["arn:aws:s3:::bucket/*"]
    assert not stmt.not_action


def test_normalize_statement_not_action():
    stmt = normalize_statement({"Effect": "Deny", "NotAction": ["iam:Get*", "iam:List*"], "Resource": "*"})
    assert stmt.not_action
    assert stmt.actions == ["iam:Get*", "iam:List*"]


def test_normalize_statement_missing_resource_defaults_to_wildcard():
    stmt = normalize_statement({"Effect": "Allow", "Action": "sts:GetCallerIdentity"})
    assert stmt.resources == ["*"]


def test_normalize_policy_document_single_statement_as_dict_not_list():
    doc = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
    statements = normalize_policy_document(doc)
    assert len(statements) == 1
    assert statements[0].actions == ["*"]


def test_normalize_trust_document_defaults_action_to_assume_role():
    doc = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}}]}
    trust_statements = normalize_trust_document(doc)
    assert len(trust_statements) == 1
    assert trust_statements[0].actions == ["sts:AssumeRole"]
    assert trust_statements[0].principals == ["ec2.amazonaws.com"]


def test_normalize_trust_document_single_statement_as_dict_not_list():
    doc = {"Statement": {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}}}
    trust_statements = normalize_trust_document(doc)
    assert len(trust_statements) == 1
    assert trust_statements[0].principals == ["ec2.amazonaws.com"]


def test_normalize_resource_policy_document_single_string_action_and_principal():
    doc = {"Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
    }]}
    statements = normalize_resource_policy_document(doc)
    assert len(statements) == 1
    assert statements[0].principals == ["*"]
    assert statements[0].actions == ["s3:GetObject"]
    assert statements[0].resources == ["arn:aws:s3:::b/*"]


def test_normalize_resource_policy_document_missing_resource_defaults_to_wildcard():
    doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "s3:GetObject"}]}
    statements = normalize_resource_policy_document(doc)
    assert statements[0].resources == ["*"]


def test_normalize_resource_policy_document_single_statement_as_dict_not_list():
    doc = {"Statement": {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}}
    statements = normalize_resource_policy_document(doc)
    assert len(statements) == 1
    assert statements[0].principals == ["*"]


def test_permissions_boundary_name_extracted_when_present():
    # moto doesn't track permissions boundaries end-to-end (see the note in
    # the live-collection tests below), so this is exercised directly
    # against the same {"PermissionsBoundaryArn": ...} shape real boto3
    # returns from list_users/list_roles.
    entity = {"PermissionsBoundary": {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::111111111111:policy/boundary-policy"}}
    assert _permissions_boundary_name(_FakePolicyCache(), entity) == "boundary-policy"


def test_permissions_boundary_name_none_when_absent():
    assert _permissions_boundary_name(_FakePolicyCache(), {}) is None


# --------------------------------------------------------------------------
# Live collection, against moto's mocked IAM
# --------------------------------------------------------------------------


@mock_aws
def test_collect_organization_reflects_users_and_groups():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    devs_policy_arn = iam.create_policy(
        PolicyName="devs-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
        ]}),
    )["Policy"]["Arn"]

    iam.create_user(UserName="alice")
    iam.attach_user_policy(UserName="alice", PolicyArn=devs_policy_arn)
    iam.put_user_policy(
        UserName="alice", PolicyName="inline-ro",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"},
        ]}),
    )
    iam.create_login_profile(UserName="alice", Password="Sup3rSecret!")
    iam.create_access_key(UserName="alice")

    iam.create_group(GroupName="devs")
    iam.add_user_to_group(GroupName="devs", UserName="alice")
    iam.attach_group_policy(GroupName="devs", PolicyArn=devs_policy_arn)

    org = collect_organization(session)

    account_id = session.client("sts").get_caller_identity()["Account"]
    assert org.account_id == account_id

    alice = org.users["alice"]
    assert "devs-policy" in alice.attached_policies
    assert alice.groups == ["devs"]
    assert alice.has_console_password is True
    assert alice.access_keys == 1
    assert any(p.name == "inline-ro" for p in alice.inline_policies)

    devs = org.groups["devs"]
    assert devs.members == ["alice"]
    assert "devs-policy" in devs.attached_policies

    assert "devs-policy" in org.policies


@mock_aws
def test_collect_organization_no_console_password_and_no_access_keys():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="bob")

    org = collect_organization(session)

    bob = org.users["bob"]
    assert bob.has_console_password is False
    assert bob.access_keys == 0
    assert bob.permissions_boundary is None


@mock_aws
def test_collect_organization_role_trust_policy_produces_assume_edge():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    iam.create_user(UserName="alice")
    alice_arn = iam.get_user(UserName="alice")["User"]["Arn"]

    iam.put_user_policy(
        UserName="alice", PolicyName="can-assume",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
        ]}),
    )

    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": alice_arn}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName="audit-role", AssumeRolePolicyDocument=json.dumps(trust_doc))
    ro_arn = iam.create_policy(
        PolicyName="ro-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["iam:Get*", "iam:List*"], "Resource": "*"},
        ]}),
    )["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="audit-role", PolicyArn=ro_arn)

    org = collect_organization(session)

    role = org.roles["audit-role"]
    assert role.trust_statements[0].principals == [alice_arn]
    assert "ro-policy" in role.attached_policies

    edges = list(find_assume_role_edges(org, PolicyEngine(org)))
    assert any(e.source == "alice" and e.target == "audit-role" for e in edges)


@mock_aws
def test_collect_organization_round_trips_through_analyzer_for_self_escalation():
    """End-to-end: a self-escalation planted via moto's mocked IAM should be
    detected by analyze() exactly like the hand-written synthetic fixtures."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    app_policy_arn = iam.create_policy(
        PolicyName="app-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "*"},
        ]}),
    )["Policy"]["Arn"]

    iam.create_user(UserName="alice")
    iam.attach_user_policy(UserName="alice", PolicyArn=app_policy_arn)
    iam.put_user_policy(
        UserName="alice", PolicyName="self-manage",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
                "Resource": app_policy_arn,
            },
        ]}),
    )

    org = collect_organization(session)
    result = analyze(org)

    alice_findings = [f for f in result.findings if f.source == "alice"]
    assert alice_findings and alice_findings[0].kind == "self_escalation"
    assert alice_findings[0].severity == "Critical"


@mock_aws
def test_collect_organization_account_id_override():
    session = boto3.Session(region_name="us-east-1")
    org = collect_organization(session, account_id="999999999999")
    assert org.account_id == "999999999999"


# --------------------------------------------------------------------------
# SCP collection (opt-in, via AWS Organizations), against moto's mock.
# --------------------------------------------------------------------------


def _setup_org_with_scp_hierarchy(orgs, statements_by_level):
    """Creates root -> OU -> account, attaches one SCP per level (root/ou/account)
    from `statements_by_level` (a dict with any of those three keys), and
    returns the account id. The default FullAWSAccess SCP is always present
    at the root too, same as a real AWS Organization."""
    orgs.create_organization(FeatureSet="ALL")
    root_id = orgs.list_roots()["Roots"][0]["Id"]
    account_id = orgs.list_accounts()["Accounts"][0]["Id"]
    orgs.enable_policy_type(RootId=root_id, PolicyType="SERVICE_CONTROL_POLICY")
    ou_id = orgs.create_organizational_unit(ParentId=root_id, Name="eng")["OrganizationalUnit"]["Id"]
    orgs.move_account(AccountId=account_id, SourceParentId=root_id, DestinationParentId=ou_id)

    target_by_level = {"root": root_id, "ou": ou_id, "account": account_id}
    for level, statements in statements_by_level.items():
        policy_id = orgs.create_policy(
            Name=f"scp-{level}", Description="x", Type="SERVICE_CONTROL_POLICY",
            Content=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )["Policy"]["PolicySummary"]["Id"]
        orgs.attach_policy(PolicyId=policy_id, TargetId=target_by_level[level])

    return account_id


@mock_aws
def test_collect_scps_walks_full_hierarchy_and_dedupes():
    session = boto3.Session(region_name="us-east-1")
    orgs = session.client("organizations")
    account_id = _setup_org_with_scp_hierarchy(orgs, {
        "root": [{"Effect": "Allow", "Action": ["s3:*", "iam:*", "ec2:*"], "Resource": "*"}],
        "ou": [{"Effect": "Allow", "Action": ["s3:*", "iam:*"], "Resource": "*"}],
        "account": [{"Effect": "Deny", "Action": "iam:DeleteUser", "Resource": "*"}],
    })

    scps = _collect_scps(session, account_id)
    names = {p.name for p in scps}
    # The 3 explicitly attached SCPs, plus the default FullAWSAccess at root.
    assert names == {"scp-root", "scp-ou", "scp-account", "FullAWSAccess"}


@mock_aws
def test_collect_organization_scp_blocks_self_escalation_end_to_end():
    """The money test: a self-escalation planted via moto's mocked IAM
    should stop being detected once an SCP that blocks IAM entirely is
    attached to the account -- proving SCP intersection actually changes
    analyzer output through the full collect -> analyze pipeline."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    orgs = session.client("organizations")

    app_policy_arn = iam.create_policy(
        PolicyName="app-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "*"},
        ]}),
    )["Policy"]["Arn"]
    iam.create_user(UserName="alice")
    iam.attach_user_policy(UserName="alice", PolicyArn=app_policy_arn)
    iam.put_user_policy(
        UserName="alice", PolicyName="self-manage",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"], "Resource": app_policy_arn},
        ]}),
    )

    # Without an SCP: self-escalation is found (sanity check, matches the
    # equivalent no-SCP test above).
    org_without_scp = collect_organization(session, include_scps=False)
    assert any(f.source == "alice" and f.kind == "self_escalation" for f in analyze(org_without_scp).findings)

    account_id = _setup_org_with_scp_hierarchy(orgs, {
        "account": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}],  # no iam:* at all
    })
    org_with_scp = collect_organization(session, account_id=account_id, include_scps=True)
    assert org_with_scp.scps  # collected something
    assert not any(f.source == "alice" and f.kind == "self_escalation" for f in analyze(org_with_scp).findings)


@mock_aws
def test_collect_organization_include_scps_false_leaves_scps_empty():
    session = boto3.Session(region_name="us-east-1")
    orgs = session.client("organizations")
    _setup_org_with_scp_hierarchy(orgs, {"account": [{"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]})

    org = collect_organization(session, include_scps=False)
    assert org.scps == []


# --------------------------------------------------------------------------
# S3 bucket policy collection (opt-in), against moto's mock.
# --------------------------------------------------------------------------


@mock_aws
def test_collect_s3_bucket_policies_skips_buckets_with_no_policy():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="open-bucket")
    s3.put_bucket_policy(Bucket="open-bucket", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::open-bucket/*"}],
    }))
    s3.create_bucket(Bucket="private-bucket")  # no policy at all

    resource_policies = _collect_s3_bucket_policies(session)

    assert len(resource_policies) == 1
    rp = resource_policies[0]
    assert rp.resource_arn == "arn:aws:s3:::open-bucket"
    assert rp.resource_type == "s3_bucket"
    assert rp.statements[0].principals == ["*"]


@mock_aws
def test_collect_organization_include_s3_buckets_flag_flows_into_analyze():
    session = boto3.Session(region_name="us-east-1")
    session.client("s3").create_bucket(Bucket="open-bucket")
    session.client("s3").put_bucket_policy(Bucket="open-bucket", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::open-bucket/*"}],
    }))

    org = collect_organization(session, include_s3_buckets=True)
    assert org.resource_policies

    findings = [f for f in analyze(org).findings if f.kind == "external_resource_trust"]
    assert len(findings) == 1
    assert "open-bucket" in findings[0].summary


def test_collect_s3_bucket_policies_reraises_unexpected_errors():
    """NoSuchBucketPolicy is the normal "no policy set" case and is
    swallowed; any other error (e.g. AccessDenied) must propagate."""
    s3_client = MagicMock()
    s3_client.list_buckets.return_value = {"Buckets": [{"Name": "some-bucket"}]}
    s3_client.exceptions.ClientError = ClientError
    s3_client.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetBucketPolicy",
    )

    class _FakeSession:
        def client(self, name):
            assert name == "s3"
            return s3_client

    with pytest.raises(ClientError):
        _collect_s3_bucket_policies(_FakeSession())


@mock_aws
def test_collect_organization_include_s3_buckets_false_leaves_it_empty():
    session = boto3.Session(region_name="us-east-1")
    session.client("s3").create_bucket(Bucket="open-bucket")
    session.client("s3").put_bucket_policy(Bucket="open-bucket", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}],
    }))

    org = collect_organization(session, include_s3_buckets=False)
    assert org.resource_policies == []


# --------------------------------------------------------------------------
# The shipped least-privilege policy (data/collect-readonly-policy.json)
# must cover exactly the read-only API calls collect_organization() makes.
# --------------------------------------------------------------------------

_EXPECTED_COLLECT_ACTIONS = {
    "iam:ListUsers",
    "iam:ListRoles",
    "iam:ListGroups",
    "iam:ListGroupsForUser",
    "iam:ListAttachedUserPolicies",
    "iam:ListAttachedRolePolicies",
    "iam:ListAttachedGroupPolicies",
    "iam:ListUserPolicies",
    "iam:ListRolePolicies",
    "iam:ListGroupPolicies",
    "iam:GetUserPolicy",
    "iam:GetRolePolicy",
    "iam:GetGroupPolicy",
    "iam:GetGroup",
    "iam:GetLoginProfile",
    "iam:ListAccessKeys",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "sts:GetCallerIdentity",
}


def test_collect_readonly_policy_matches_expected_actions():
    policy_path = pathlib.Path(__file__).resolve().parent.parent / "data" / "collect-readonly-policy.json"
    policy = json.loads(policy_path.read_text())
    actions = set(policy["Statement"][0]["Action"])
    assert actions == _EXPECTED_COLLECT_ACTIONS
    assert all(s["Effect"] == "Allow" for s in policy["Statement"])
