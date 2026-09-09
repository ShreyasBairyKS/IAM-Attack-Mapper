"""Data model for a (synthetic or real) AWS IAM account snapshot.

This intentionally mirrors the shape of real AWS IAM data (as you'd get
back from ``iam:Get*`` / ``iam:List*`` API calls via boto3) closely
enough that a future "pull live data from AWS" backend can populate the
same dataclasses without changing anything downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union


# --------------------------------------------------------------------------
# Policies
# --------------------------------------------------------------------------


@dataclass
class Statement:
    """A single IAM policy statement.

    Simplifications made for v1 (documented in README "Limitations"):
      * ``condition`` is stored but not evaluated -- a statement with a
        condition is treated as "would allow, but flagged conditional"
        rather than fully resolving IAM condition operators.
      * Only ``Action``/``NotAction`` and ``Resource`` are matched;
        ``NotResource`` is not supported.
    """

    effect: str  # "Allow" | "Deny"
    actions: List[str]
    resources: List[str] = field(default_factory=lambda: ["*"])
    not_action: bool = False
    condition: Optional[dict] = None

    def __post_init__(self) -> None:
        if self.effect not in ("Allow", "Deny"):
            raise ValueError(f"Statement.effect must be Allow/Deny, got {self.effect!r}")


@dataclass
class Policy:
    """A customer-managed or AWS-managed IAM policy (a named bundle of statements)."""

    name: str
    arn: str
    statements: List[Statement] = field(default_factory=list)
    aws_managed: bool = False


@dataclass
class TrustStatement:
    """A statement inside a role's assume-role (trust) policy."""

    effect: str
    principals: List[str]  # e.g. "arn:aws:iam::123456789012:user/alice", "ec2.amazonaws.com", "*"
    actions: List[str] = field(default_factory=lambda: ["sts:AssumeRole"])
    condition: Optional[dict] = None


@dataclass
class ResourcePolicyStatement:
    """A statement inside a resource-based policy (S3 bucket policy, KMS key
    policy, ...). Structurally an identity-policy statement with a
    ``Principal`` added, since that's what a resource policy actually is.
    """

    effect: str
    principals: List[str]
    actions: List[str]
    resources: List[str] = field(default_factory=lambda: ["*"])
    condition: Optional[dict] = None


@dataclass
class ResourcePolicy:
    """A resource-based policy attached to a non-IAM resource.

    v1 scope is deliberately narrow -- this only models the policy
    *document* well enough to flag external-account/wildcard trust (the
    same hygiene check ``trust.py`` already does for role trust
    policies), not full evaluation of what access a resource policy
    actually grants (see README "Limitations").
    """

    resource_arn: str
    resource_type: str  # "s3_bucket" | "kms_key" (extensible)
    statements: List[ResourcePolicyStatement] = field(default_factory=list)


# --------------------------------------------------------------------------
# Principals
# --------------------------------------------------------------------------


@dataclass
class User:
    name: str
    arn: str
    attached_policies: List[str] = field(default_factory=list)  # Policy.name refs
    inline_policies: List[Policy] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)  # Group.name refs
    permissions_boundary: Optional[str] = None  # Policy.name ref
    has_console_password: bool = False
    access_keys: int = 0

    kind: str = field(default="user", init=False)


@dataclass
class Role:
    name: str
    arn: str
    trust_statements: List[TrustStatement] = field(default_factory=list)
    attached_policies: List[str] = field(default_factory=list)
    inline_policies: List[Policy] = field(default_factory=list)
    permissions_boundary: Optional[str] = None

    kind: str = field(default="role", init=False)


@dataclass
class Group:
    name: str
    arn: str
    attached_policies: List[str] = field(default_factory=list)
    inline_policies: List[Policy] = field(default_factory=list)
    members: List[str] = field(default_factory=list)  # User.name refs

    kind: str = field(default="group", init=False)


Principal = Union[User, Role]


@dataclass
class Organization:
    """A full account snapshot: every principal, group, and managed policy.

    ``scps`` is the *effective* set of Service Control Policies that apply
    to this account -- i.e. already flattened from wherever they're
    attached in the real AWS Organization (root, each OU, and the account
    itself). This model doesn't represent the OU hierarchy; a live
    collector is expected to walk it and hand back the flattened result
    (see ``aws_collector.collect_organization(..., include_scps=True)``).
    An SCP never *grants* anything -- like a permissions boundary, it can
    only narrow what the account's identity policies already allow.
    """

    account_id: str
    users: Dict[str, User] = field(default_factory=dict)
    roles: Dict[str, Role] = field(default_factory=dict)
    groups: Dict[str, Group] = field(default_factory=dict)
    policies: Dict[str, Policy] = field(default_factory=dict)  # keyed by Policy.name
    scps: List[Policy] = field(default_factory=list)
    resource_policies: List[ResourcePolicy] = field(default_factory=list)

    def add_policy(self, policy: Policy) -> None:
        self.policies[policy.name] = policy

    def add_user(self, user: User) -> None:
        self.users[user.name] = user

    def add_role(self, role: Role) -> None:
        self.roles[role.name] = role

    def add_group(self, group: Group) -> None:
        self.groups[group.name] = group

    def get_principal(self, name: str) -> Optional[Principal]:
        return self.users.get(name) or self.roles.get(name)

    def all_principals(self) -> List[Principal]:
        return [*self.users.values(), *self.roles.values()]

    def policy_by_arn(self, arn: str) -> Optional[Policy]:
        for p in self.policies.values():
            if p.arn == arn:
                return p
        return None

    def principal_by_arn(self, arn: str) -> Optional[Principal]:
        for p in self.all_principals():
            if p.arn == arn:
                return p
        return None
