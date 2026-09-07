"""Known AWS IAM privilege-escalation techniques, as graph-edge rules.

Each rule is a function ``rule(org, engine) -> Iterable[EscalationEdge]``.
An edge ``source -> target`` means: "source can, via this technique,
end up with target's effective permissions" (often because target ==
source, i.e. direct self-escalation).

These techniques are the well-known ones documented by Rhino Security
Labs' AWS IAM privilege escalation research
(https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
and re-confirmed by tools like Cloudsplaining and PMapper. This module
implements a representative subset rather than the full list; see
README "Roadmap" for what's not yet covered (SCPs, more service-role
techniques, cross-account resource policies beyond role trust, etc).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from .models import Organization
from .policy_engine import PolicyEngine


@dataclass
class EscalationEdge:
    source: str
    target: str
    technique: str
    detail: str
    conditional: bool = False


def _allowed(engine: PolicyEngine, principal: str, action: str, resource: str = "*"):
    return engine.is_allowed(principal, action, resource)


# --------------------------------------------------------------------------
# 1. Rewrite an existing customer-managed policy's default version
# --------------------------------------------------------------------------

def rule_policy_version_escalation(org: Organization, engine: PolicyEngine) -> Iterable[EscalationEdge]:
    """iam:CreatePolicyVersion / iam:SetDefaultPolicyVersion on a policy.

    If you can push (and activate) a new version of a customer-managed
    policy, you can rewrite it to grant "*"/"*" -- instant admin for
    every principal that has that policy attached.
    """
    for policy in org.policies.values():
        if policy.aws_managed:
            continue  # can't version AWS-managed policies
        targets = engine.principals_with_policy_attached(policy.name)
        if not targets:
            continue
        for principal in org.all_principals():
            for action in ("iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"):
                res = _allowed(engine, principal.name, action, policy.arn)
                if res.allowed:
                    for target in targets:
                        yield EscalationEdge(
                            source=principal.name,
                            target=target.name,
                            technique="PolicyVersionEscalation",
                            detail=f"can {action} on policy '{policy.name}', which is attached to '{target.name}'",
                            conditional=res.conditional,
                        )
                    break  # don't double-report both actions for the same policy


# --------------------------------------------------------------------------
# 2. Create an access key for another user
# --------------------------------------------------------------------------

def rule_create_access_key(org: Organization, engine: PolicyEngine) -> Iterable[EscalationEdge]:
    for source in org.all_principals():
        for target in org.users.values():
            if source.name == target.name:
                continue
            res = _allowed(engine, source.name, "iam:CreateAccessKey", target.arn)
            if res.allowed:
                yield EscalationEdge(
                    source=source.name,
                    target=target.name,
                    technique="CreateAccessKey",
                    detail=f"can create an access key for user '{target.name}'",
                    conditional=res.conditional,
                )


# --------------------------------------------------------------------------
# 3. Set/reset another user's console password
# --------------------------------------------------------------------------

def rule_login_profile(org: Organization, engine: PolicyEngine) -> Iterable[EscalationEdge]:
    for source in org.all_principals():
        for target in org.users.values():
            if source.name == target.name:
                continue
            for action in ("iam:CreateLoginProfile", "iam:UpdateLoginProfile"):
                res = _allowed(engine, source.name, action, target.arn)
                if res.allowed:
                    yield EscalationEdge(
                        source=source.name,
                        target=target.name,
                        technique="LoginProfileTakeover",
                        detail=f"can {action} for user '{target.name}' (set their console password)",
                        conditional=res.conditional,
                    )
                    break


# --------------------------------------------------------------------------
# 4. Attach a (potentially admin) managed policy to a principal or group
# --------------------------------------------------------------------------

_ATTACH_ACTIONS = {
    "iam:AttachUserPolicy": "user",
    "iam:AttachRolePolicy": "role",
    "iam:AttachGroupPolicy": "group",
}


def rule_policy_attachment(org: Organization, engine: PolicyEngine) -> Iterable[EscalationEdge]:
    for source in org.all_principals():
        for action, kind in _ATTACH_ACTIONS.items():
            if kind == "user":
                targets = list(org.users.values())
            elif kind == "role":
                targets = list(org.roles.values())
            else:
                targets = None  # groups handled below

            if targets is not None:
                for target in targets:
                    res = _allowed(engine, source.name, action, target.arn)
                    if res.allowed:
                        yield EscalationEdge(
                            source=source.name,
                            target=target.name,
                            technique="AttachPolicy",
                            detail=f"can {action} on '{target.name}' (attach e.g. AdministratorAccess)",
                            conditional=res.conditional,
                        )
            else:
                for group in org.groups.values():
                    res = _allowed(engine, source.name, action, group.arn)
                    if not res.allowed:
                        continue
                    for member_name in group.members:
                        yield EscalationEdge(
                            source=source.name,
                            target=member_name,
                            technique="AttachPolicy",
                            detail=(
                                f"can {action} on group '{group.name}' "
                                f"(member '{member_name}' inherits it)"
                            ),
                            conditional=res.conditional,
                        )


# --------------------------------------------------------------------------
# 5. Put an inline policy directly on a principal or group
# --------------------------------------------------------------------------

_PUT_ACTIONS = {
    "iam:PutUserPolicy": "user",
    "iam:PutRolePolicy": "role",
    "iam:PutGroupPolicy": "group",
}


def rule_inline_policy(org: Organization, engine: PolicyEngine) -> Iterable[EscalationEdge]:
    for source in org.all_principals():
        for action, kind in _PUT_ACTIONS.items():
            if kind == "user":
                targets = list(org.users.values())
            elif kind == "role":
                targets = list(org.roles.values())
            else:
                targets = None

            if targets is not None:
                for target in targets:
                    res = _allowed(engine, source.name, action, target.arn)
                    if res.allowed:
                        yield EscalationEdge(
                            source=source.name,
                            target=target.name,
                            technique="InlinePolicyInjection",
                            detail=f"can {action} on '{target.name}' (write a fresh admin inline policy)",
                            conditional=res.conditional,
                        )
            else:
                for group in org.groups.values():
                    res = _allowed(engine, source.name, action, group.arn)
                    if not res.allowed:
                        continue
                    for member_name in group.members:
                        yield EscalationEdge(
                            source=source.name,
                            target=member_name,
                            technique="InlinePolicyInjection",
                            detail=(
                                f"can {action} on group '{group.name}' "
                                f"(member '{member_name}' inherits it)"
                            ),
                            conditional=res.conditional,
                        )


# --------------------------------------------------------------------------
# 6. Add a user to a (more privileged) group
# --------------------------------------------------------------------------

def rule_add_user_to_group(org: Organization, engine: PolicyEngine) -> Iterable[EscalationEdge]:
    for source in org.all_principals():
        for group in org.groups.values():
            res = _allowed(engine, source.name, "iam:AddUserToGroup", group.arn)
            if not res.allowed:
                continue
            for target in org.users.values():
                if target.name in group.members:
                    continue
                yield EscalationEdge(
                    source=source.name,
                    target=target.name,
                    technique="AddUserToGroup",
                    detail=f"can add '{target.name}' to group '{group.name}'",
                    conditional=res.conditional,
                )


# --------------------------------------------------------------------------
# 7. Rewrite a role's trust policy to add yourself as a trusted principal
# --------------------------------------------------------------------------

def rule_update_assume_role_policy(org: Organization, engine: PolicyEngine) -> Iterable[EscalationEdge]:
    for source in org.all_principals():
        for role in org.roles.values():
            res = _allowed(engine, source.name, "iam:UpdateAssumeRolePolicy", role.arn)
            if res.allowed:
                yield EscalationEdge(
                    source=source.name,
                    target=role.name,
                    technique="UpdateAssumeRolePolicy",
                    detail=f"can rewrite the trust policy of role '{role.name}' to add itself",
                    conditional=res.conditional,
                )


# --------------------------------------------------------------------------
# 8/9/10. iam:PassRole combined with a service that will assume the role
# --------------------------------------------------------------------------

_PASS_ROLE_SERVICES = {
    "PassRole+Lambda": {
        "companion_actions": ["lambda:CreateFunction", "lambda:InvokeFunction"],
        "trusted_service": "lambda.amazonaws.com",
    },
    "PassRole+EC2": {
        "companion_actions": ["ec2:RunInstances"],
        "trusted_service": "ec2.amazonaws.com",
    },
    "PassRole+GlueDevEndpoint": {
        "companion_actions": ["glue:CreateDevEndpoint"],
        "trusted_service": "glue.amazonaws.com",
    },
    "PassRole+CloudFormation": {
        "companion_actions": ["cloudformation:CreateStack"],
        "trusted_service": "cloudformation.amazonaws.com",
    },
    "PassRole+DataPipeline": {
        "companion_actions": ["datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"],
        "trusted_service": "datapipeline.amazonaws.com",
    },
}


def _role_trusts_service(role, service: str) -> bool:
    return any(service in ts.principals for ts in role.trust_statements)


def rule_pass_role_to_service(org: Organization, engine: PolicyEngine) -> Iterable[EscalationEdge]:
    for source in org.all_principals():
        for role in org.roles.values():
            passrole = _allowed(engine, source.name, "iam:PassRole", role.arn)
            if not passrole.allowed:
                continue
            for technique, spec in _PASS_ROLE_SERVICES.items():
                if not _role_trusts_service(role, spec["trusted_service"]):
                    continue
                companion_results = [
                    _allowed(engine, source.name, a) for a in spec["companion_actions"]
                ]
                if all(r.allowed for r in companion_results):
                    conditional = passrole.conditional or any(r.conditional for r in companion_results)
                    yield EscalationEdge(
                        source=source.name,
                        target=role.name,
                        technique=technique,
                        detail=(
                            f"can PassRole '{role.name}' plus "
                            f"{', '.join(spec['companion_actions'])} "
                            f"to run code/instances as that role"
                        ),
                        conditional=conditional,
                    )


ESCALATION_RULES: List[Callable[[Organization, PolicyEngine], Iterable[EscalationEdge]]] = [
    rule_policy_version_escalation,
    rule_create_access_key,
    rule_login_profile,
    rule_policy_attachment,
    rule_inline_policy,
    rule_add_user_to_group,
    rule_update_assume_role_policy,
    rule_pass_role_to_service,
]


def all_escalation_edges(org: Organization, engine: Optional[PolicyEngine] = None) -> List[EscalationEdge]:
    engine = engine or PolicyEngine(org)
    edges: List[EscalationEdge] = []
    for rule in ESCALATION_RULES:
        edges.extend(rule(org, engine))
    return edges
