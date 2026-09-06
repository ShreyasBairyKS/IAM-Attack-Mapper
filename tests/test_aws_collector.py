"""Tests for iam_mapper.aws_collector.

Policy-document normalization is tested with plain dicts (no AWS calls at
all). Live collection is tested against `moto`'s in-process IAM mock --
no real AWS account, network access, or credentials required.
"""

import json

import boto3
import pytest
from moto import mock_aws

from iam_mapper.analyzer import analyze
from iam_mapper.aws_collector import (
    _permissions_boundary_name,
    collect_organization,
    normalize_policy_document,
    normalize_principals,
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
