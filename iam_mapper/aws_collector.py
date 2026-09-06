"""Pull a live AWS account's IAM state into the same :class:`~iam_mapper.models.Organization`
shape the rest of the tool already works with, via ``boto3``.

Requires the ``aws`` extra (``pip install iam-attack-mapper[aws]``) -- ``boto3``
is imported lazily so ``analyze``/``export``/``report`` never need it.

Only ever calls read-only ``iam:List*``/``iam:Get*`` APIs (plus one
``sts:GetCallerIdentity`` to default the account id) -- nothing here can
modify the account it's pointed at.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import Group, Organization, Policy, Role, Statement, TrustStatement, User


# --------------------------------------------------------------------------
# Policy-document normalization (pure functions, no AWS calls -- IAM's JSON
# shapes are messier than the synthetic fixtures: Action/Resource/Principal
# can each be a single string or a list).
# --------------------------------------------------------------------------


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_principals(principal: Any) -> List[str]:
    """Flatten a trust-policy ``Principal`` block into a list of refs.

    ``"*"`` stays as-is; ``{"AWS": [...]}`` / ``{"Service": [...]}`` /
    ``{"Federated": [...]}`` are flattened to their string values (ARNs or
    service principals like ``ec2.amazonaws.com``) -- the same shapes
    ``synthetic.py`` already uses. ``CanonicalUser`` principals are kept as
    opaque refs too; nothing downstream resolves them further.
    """
    if principal == "*":
        return ["*"]
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        refs: List[str] = []
        for key in ("AWS", "Service", "Federated", "CanonicalUser"):
            refs.extend(_as_list(principal.get(key)))
        return refs
    return []


def normalize_statement(stmt: Dict[str, Any]) -> Statement:
    not_action = "NotAction" in stmt
    actions = _as_list(stmt.get("NotAction") if not_action else stmt.get("Action"))
    # NotResource isn't supported (see models.Statement docstring) -- fall
    # back to the conservative "*" rather than silently mis-evaluating it.
    resources = _as_list(stmt.get("Resource")) if "Resource" in stmt else ["*"]
    return Statement(
        effect=stmt["Effect"],
        actions=actions,
        resources=resources or ["*"],
        not_action=not_action,
        condition=stmt.get("Condition") or None,
    )


def normalize_policy_document(document: Dict[str, Any]) -> List[Statement]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [normalize_statement(s) for s in statements]


def normalize_trust_statement(stmt: Dict[str, Any]) -> TrustStatement:
    return TrustStatement(
        effect=stmt["Effect"],
        principals=normalize_principals(stmt.get("Principal", {})),
        actions=_as_list(stmt.get("Action")) or ["sts:AssumeRole"],
        condition=stmt.get("Condition") or None,
    )


def normalize_trust_document(document: Dict[str, Any]) -> List[TrustStatement]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [normalize_trust_statement(s) for s in statements]


# --------------------------------------------------------------------------
# Live collection
# --------------------------------------------------------------------------


class _PolicyCache:
    """Fetches (and memoizes) customer-managed / AWS-managed policy documents.

    Deliberately never calls ``list_policies`` -- that would enumerate
    every AWS-managed policy in existence. Only policies actually attached
    somewhere in this account are fetched, one ``get_policy`` +
    ``get_policy_version`` call each, no matter how many principals share it.
    """

    def __init__(self, iam, org: Organization):
        self._iam = iam
        self._org = org
        self._seen: Dict[str, Policy] = {}

    def get(self, arn: str) -> Policy:
        if arn in self._seen:
            return self._seen[arn]
        meta = self._iam.get_policy(PolicyArn=arn)["Policy"]
        version = self._iam.get_policy_version(PolicyArn=arn, VersionId=meta["DefaultVersionId"])
        policy = Policy(
            name=meta["PolicyName"],
            arn=arn,
            statements=normalize_policy_document(version["PolicyVersion"]["Document"]),
            aws_managed=arn.startswith("arn:aws:iam::aws:policy/"),
        )
        self._seen[arn] = policy
        self._org.add_policy(policy)
        return policy


def _inline_policies(iam, list_paginator: str, get_call, name_kwarg: str, principal_name: str) -> List[Policy]:
    policies = []
    for page in iam.get_paginator(list_paginator).paginate(**{name_kwarg: principal_name}):
        for policy_name in page["PolicyNames"]:
            doc = get_call(**{name_kwarg: principal_name, "PolicyName": policy_name})["PolicyDocument"]
            policies.append(Policy(
                name=policy_name,
                arn=f"inline:{principal_name}:{policy_name}",
                statements=normalize_policy_document(doc),
            ))
    return policies


def _attached_policy_names(iam, cache: _PolicyCache, list_paginator: str, name_kwarg: str, principal_name: str) -> List[str]:
    names = []
    for page in iam.get_paginator(list_paginator).paginate(**{name_kwarg: principal_name}):
        for entry in page["AttachedPolicies"]:
            cache.get(entry["PolicyArn"])
            names.append(entry["PolicyName"])
    return names


def _permissions_boundary_name(cache: _PolicyCache, entity: Dict[str, Any]) -> Optional[str]:
    boundary = entity.get("PermissionsBoundary")
    if not boundary:
        return None
    return cache.get(boundary["PermissionsBoundaryArn"]).name


def _collect_users(iam, org: Organization, cache: _PolicyCache) -> None:
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name = u["UserName"]

            has_console_password = True
            try:
                iam.get_login_profile(UserName=name)
            except iam.exceptions.NoSuchEntityException:
                has_console_password = False

            groups = [
                g["GroupName"]
                for page2 in iam.get_paginator("list_groups_for_user").paginate(UserName=name)
                for g in page2["Groups"]
            ]

            org.add_user(User(
                name=name,
                arn=u["Arn"],
                attached_policies=_attached_policy_names(iam, cache, "list_attached_user_policies", "UserName", name),
                inline_policies=_inline_policies(iam, "list_user_policies", iam.get_user_policy, "UserName", name),
                groups=groups,
                permissions_boundary=_permissions_boundary_name(cache, u),
                has_console_password=has_console_password,
                access_keys=len(iam.list_access_keys(UserName=name)["AccessKeyMetadata"]),
            ))


def _collect_roles(iam, org: Organization, cache: _PolicyCache) -> None:
    for page in iam.get_paginator("list_roles").paginate():
        for r in page["Roles"]:
            name = r["RoleName"]
            org.add_role(Role(
                name=name,
                arn=r["Arn"],
                trust_statements=normalize_trust_document(r["AssumeRolePolicyDocument"]),
                attached_policies=_attached_policy_names(iam, cache, "list_attached_role_policies", "RoleName", name),
                inline_policies=_inline_policies(iam, "list_role_policies", iam.get_role_policy, "RoleName", name),
                permissions_boundary=_permissions_boundary_name(cache, r),
            ))


def _collect_groups(iam, org: Organization, cache: _PolicyCache) -> None:
    for page in iam.get_paginator("list_groups").paginate():
        for g in page["Groups"]:
            name = g["GroupName"]
            members = [m["UserName"] for m in iam.get_group(GroupName=name)["Users"]]
            org.add_group(Group(
                name=name,
                arn=g["Arn"],
                attached_policies=_attached_policy_names(iam, cache, "list_attached_group_policies", "GroupName", name),
                inline_policies=_inline_policies(iam, "list_group_policies", iam.get_group_policy, "GroupName", name),
                members=members,
            ))


def collect_organization(session, account_id: Optional[str] = None) -> Organization:
    """Pull the given ``boto3.Session``'s IAM state into an :class:`Organization`.

    ``account_id`` defaults to the caller's own account (via
    ``sts:GetCallerIdentity``) -- pass it explicitly if the session's
    credentials belong to a different account than the one being audited.
    """
    iam = session.client("iam")
    if account_id is None:
        account_id = session.client("sts").get_caller_identity()["Account"]

    org = Organization(account_id=account_id)
    cache = _PolicyCache(iam, org)

    _collect_users(iam, org, cache)
    _collect_roles(iam, org, cache)
    _collect_groups(iam, org, cache)

    return org
