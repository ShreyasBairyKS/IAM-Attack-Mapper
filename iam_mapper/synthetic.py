"""Generates a synthetic (but realistic-shaped) AWS account for demos/tests.

No real AWS account is required to use this tool -- ``build_sample_organization()``
plants several well-known privilege-escalation techniques so you can see
the analyzer work end to end. Regenerate ``data/sample_org.json`` with::

    python -m iam_mapper.synthetic > data/sample_org.json

Planted scenarios (see README for the full writeup):
  * alice   -- PolicyVersionEscalation (self)
  * bob     -- CreateAccessKey on carol (existing admin)
  * dave    -- PassRole+Lambda onto an over-privileged automation role
  * erin    -- PassRole+EC2 onto a role with full IAM control
  * frank   -- UpdateAssumeRolePolicy -> audit-role -> AttachPolicy (self, 2 hops)
  * grace   -- clean developer, no path (true negative)
  * heather -- already admin (AdministratorAccess attached directly)
  * vendor-role -- external-account trust (informational finding)
"""

from __future__ import annotations

from .models import Group, Organization, Policy, Role, Statement, TrustStatement, User

ACCOUNT_ID = "123456789012"


def _arn_user(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT_ID}:user/{name}"


def _arn_role(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT_ID}:role/{name}"


def _arn_group(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT_ID}:group/{name}"


def _arn_policy(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT_ID}:policy/{name}"


def build_sample_organization() -> Organization:
    org = Organization(account_id=ACCOUNT_ID)

    # ---- managed / customer policies ------------------------------------
    org.add_policy(Policy(
        name="AdministratorAccess", arn="arn:aws:iam::aws:policy/AdministratorAccess", aws_managed=True,
        statements=[Statement(effect="Allow", actions=["*"], resources=["*"])],
    ))
    org.add_policy(Policy(
        name="ReadOnlyAccess", arn="arn:aws:iam::aws:policy/ReadOnlyAccess", aws_managed=True,
        statements=[Statement(effect="Allow", actions=["s3:Get*", "s3:List*", "ec2:Describe*", "iam:Get*", "iam:List*"])],
    ))
    org.add_policy(Policy(
        name="AppDeployPolicy", arn=_arn_policy("AppDeployPolicy"),
        statements=[Statement(effect="Allow", actions=["s3:PutObject", "s3:GetObject", "codedeploy:*"])],
    ))
    org.add_policy(Policy(
        name="DeveloperAccess", arn=_arn_policy("DeveloperAccess"),
        statements=[Statement(effect="Allow", actions=["s3:*", "lambda:InvokeFunction", "logs:*"])],
    ))
    org.add_policy(Policy(
        name="AutomationFullIAM", arn=_arn_policy("AutomationFullIAM"),
        statements=[Statement(effect="Allow", actions=["iam:*"])],
    ))
    org.add_policy(Policy(
        name="SecurityAuditRO", arn=_arn_policy("SecurityAuditRO"),
        statements=[Statement(effect="Allow", actions=["iam:Get*", "iam:List*", "access-analyzer:*"])],
    ))

    # ---- groups -----------------------------------------------------------
    org.add_group(Group(
        name="developers", arn=_arn_group("developers"),
        attached_policies=["DeveloperAccess"], members=["grace", "dave"],
    ))
    org.add_group(Group(
        name="admins", arn=_arn_group("admins"),
        attached_policies=["AdministratorAccess"], members=["heather"],
    ))

    # ---- scenario A: alice can rewrite her own deploy policy's default version
    org.add_user(User(
        name="alice", arn=_arn_user("alice"),
        attached_policies=["AppDeployPolicy"],
        inline_policies=[Policy(
            name="SelfPolicyManage", arn=_arn_policy("SelfPolicyManage-alice"),
            statements=[Statement(
                effect="Allow",
                actions=["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
                resources=[_arn_policy("AppDeployPolicy")],
            )],
        )],
    ))

    # ---- scenario B: bob can mint an access key for carol (an existing admin)
    org.add_user(User(
        name="bob", arn=_arn_user("bob"),
        inline_policies=[Policy(
            name="OpsAccessMgmt", arn=_arn_policy("OpsAccessMgmt-bob"),
            statements=[Statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"])],
        )],
    ))
    org.add_user(User(name="carol", arn=_arn_user("carol"), attached_policies=["AdministratorAccess"]))

    # ---- scenario C: dave (PassRole+Lambda) onto an over-privileged automation role
    org.add_user(User(
        name="dave", arn=_arn_user("dave"), groups=["developers"],
        inline_policies=[Policy(
            name="PipelineOps", arn=_arn_policy("PipelineOps-dave"),
            statements=[
                Statement(effect="Allow", actions=["iam:PassRole"], resources=[_arn_role("data-pipeline-role")]),
                Statement(effect="Allow", actions=["lambda:CreateFunction", "lambda:InvokeFunction", "lambda:CreateEventSourceMapping"]),
            ],
        )],
    ))
    org.add_role(Role(
        name="data-pipeline-role", arn=_arn_role("data-pipeline-role"),
        attached_policies=["AdministratorAccess"],
        trust_statements=[TrustStatement(effect="Allow", principals=["lambda.amazonaws.com"])],
    ))

    # ---- scenario D2: erin (PassRole+EC2) onto a role with full IAM control
    org.add_user(User(
        name="erin", arn=_arn_user("erin"),
        inline_policies=[Policy(
            name="CIOps", arn=_arn_policy("CIOps-erin"),
            statements=[
                Statement(effect="Allow", actions=["iam:PassRole"], resources=[_arn_role("ci-role")]),
                Statement(effect="Allow", actions=["ec2:RunInstances"]),
            ],
        )],
    ))
    org.add_role(Role(
        name="ci-role", arn=_arn_role("ci-role"),
        attached_policies=["AutomationFullIAM"],
        trust_statements=[TrustStatement(effect="Allow", principals=["ec2.amazonaws.com"])],
    ))

    # ---- scenario E: frank -> audit-role (trust rewrite) -> self-attach (2 hops)
    org.add_user(User(
        name="frank", arn=_arn_user("frank"),
        inline_policies=[Policy(
            name="AuditOps", arn=_arn_policy("AuditOps-frank"),
            statements=[Statement(effect="Allow", actions=["iam:UpdateAssumeRolePolicy"], resources=[_arn_role("audit-role")])],
        )],
    ))
    org.add_role(Role(
        name="audit-role", arn=_arn_role("audit-role"),
        attached_policies=["SecurityAuditRO"],
        inline_policies=[Policy(
            name="AuditRoleSelfManage", arn=_arn_policy("AuditRoleSelfManage"),
            statements=[Statement(effect="Allow", actions=["iam:AttachRolePolicy"], resources=[_arn_role("audit-role")])],
        )],
        trust_statements=[TrustStatement(effect="Allow", principals=[_arn_role("ci-cd-service")])],
    ))
    # ci-cd-service role: legitimate, narrowly-trusted, no escalation path
    org.add_role(Role(
        name="ci-cd-service", arn=_arn_role("ci-cd-service"),
        attached_policies=["ReadOnlyAccess"],
        trust_statements=[TrustStatement(effect="Allow", principals=["codebuild.amazonaws.com"])],
    ))

    # ---- scenario F: grace -- clean developer, no escalation path (true negative)
    org.add_user(User(name="grace", arn=_arn_user("grace"), groups=["developers"]))

    # ---- scenario G: heather -- already admin via group membership
    org.add_user(User(name="heather", arn=_arn_user("heather"), groups=["admins"]))

    # ---- scenario H: vendor-role -- external account trust (informational)
    org.add_role(Role(
        name="vendor-role", arn=_arn_role("vendor-role"),
        attached_policies=["DeveloperAccess"],
        trust_statements=[TrustStatement(effect="Allow", principals=["arn:aws:iam::999999999999:root"])],
    ))

    return org


if __name__ == "__main__":
    import sys

    from .serialize import organization_to_dict
    import json

    json.dump(organization_to_dict(build_sample_organization()), sys.stdout, indent=2)
    sys.stdout.write("\n")
