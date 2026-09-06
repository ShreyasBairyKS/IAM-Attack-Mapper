"""AWS-style IAM policy evaluation.

Implements just enough of the real IAM evaluation logic
(https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
to answer "can principal X do action Y on resource Z":

  1. Default deny.
  2. Any explicit Deny (identity-based) wins, full stop.
  3. If a permissions boundary is set, it must *also* allow the action
     (a boundary can only take away permissions, never grant them).
  4. Otherwise, an explicit Allow in an identity-based policy (attached,
     inline, or -- for users -- via group membership) grants it.

Not modeled (see README "Limitations"): resource-based policies (except
role trust policies, handled separately in ``trust.py``), Service
Control Policies, session policies, and real evaluation of ``Condition``
blocks -- a matching statement with a condition is treated as "allows,
but flagged conditional" rather than resolved.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import List, Optional

from .models import Organization, Policy, Principal, Statement, User

# A principal that can do this is, for all practical purposes, an admin:
# they can grant themselves anything IAM can express.
FULL_ADMIN_ACTION = "*"
FULL_ADMIN_RESOURCE = "*"
# Full IAM control is treated as admin-equivalent: from there you can
# always create/attach a policy that grants yourself "*"/"*".
IAM_FULL_CONTROL_ACTION = "iam:*"


def _aws_pattern_to_regex(pattern: str) -> re.Pattern:
    # AWS action/resource patterns use '*' (any run of chars) and '?'
    # (single char), case-insensitively for actions.
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE)


def action_matches(statement: Statement, action: str) -> bool:
    matched = any(_aws_pattern_to_regex(p).match(action) for p in statement.actions)
    return (not matched) if statement.not_action else matched


def resource_matches(statement: Statement, resource: str) -> bool:
    if resource == "*":
        # Asking "can you do this on *anything*" matches only a statement
        # that itself is unrestricted -- avoids false positives where a
        # narrowly-scoped statement would otherwise look admin-equivalent.
        return any(r == "*" for r in statement.resources)
    return any(_aws_pattern_to_regex(r).match(resource) for r in statement.resources)


@dataclass
class EvalResult:
    allowed: bool
    conditional: bool = False
    reason: str = ""


class PolicyEngine:
    def __init__(self, org: Organization):
        self.org = org

    # -- gathering statements -------------------------------------------------

    def _resolve_policy_statements(self, policy_name: str) -> List[Statement]:
        policy = self.org.policies.get(policy_name)
        return list(policy.statements) if policy else []

    def _identity_statements(self, principal: Principal) -> List[Statement]:
        stmts: List[Statement] = []
        for name in principal.attached_policies:
            stmts.extend(self._resolve_policy_statements(name))
        for inline in principal.inline_policies:
            stmts.extend(inline.statements)
        if isinstance(principal, User):
            for group_name in principal.groups:
                group = self.org.groups.get(group_name)
                if not group:
                    continue
                for name in group.attached_policies:
                    stmts.extend(self._resolve_policy_statements(name))
                for inline in group.inline_policies:
                    stmts.extend(inline.statements)
        return stmts

    def _boundary_statements(self, principal: Principal) -> Optional[List[Statement]]:
        if not principal.permissions_boundary:
            return None
        return self._resolve_policy_statements(principal.permissions_boundary)

    # -- evaluation -------------------------------------------------------

    def is_allowed(self, principal_name: str, action: str, resource: str = "*") -> EvalResult:
        principal = self.org.get_principal(principal_name)
        if principal is None:
            return EvalResult(False, reason=f"unknown principal {principal_name!r}")

        statements = self._identity_statements(principal)

        for s in statements:
            if s.effect == "Deny" and action_matches(s, action) and resource_matches(s, resource):
                return EvalResult(False, reason="explicit identity Deny")

        boundary = self._boundary_statements(principal)
        if boundary is not None:
            boundary_allows = any(
                s.effect == "Allow" and action_matches(s, action) and resource_matches(s, resource)
                for s in boundary
            )
            boundary_denies = any(
                s.effect == "Deny" and action_matches(s, action) and resource_matches(s, resource)
                for s in boundary
            )
            if boundary_denies or not boundary_allows:
                return EvalResult(False, reason="permissions boundary does not allow this")

        matching_allow = [
            s for s in statements
            if s.effect == "Allow" and action_matches(s, action) and resource_matches(s, resource)
        ]
        if not matching_allow:
            return EvalResult(False, reason="no matching Allow (default deny)")

        conditional = all(s.condition for s in matching_allow)
        return EvalResult(True, conditional=conditional, reason="identity Allow")

    def is_admin(self, principal_name: str) -> bool:
        """True if the principal is already admin-equivalent.

        Either literal ``*``/``*`` (e.g. AdministratorAccess), or full
        IAM control (``iam:*``), from which admin is always one step away.
        """
        if self.is_allowed(principal_name, FULL_ADMIN_ACTION, FULL_ADMIN_RESOURCE).allowed:
            return True
        if self.is_allowed(principal_name, IAM_FULL_CONTROL_ACTION, "*").allowed:
            return True
        return False

    def principals_with_policy_attached(self, policy_name: str) -> List[Principal]:
        """Every user/role that has ``policy_name`` attached, directly or via a group."""
        result = []
        for principal in self.org.all_principals():
            if policy_name in principal.attached_policies:
                result.append(principal)
                continue
            if isinstance(principal, User):
                for group_name in principal.groups:
                    group = self.org.groups.get(group_name)
                    if group and policy_name in group.attached_policies:
                        result.append(principal)
                        break
        return result
