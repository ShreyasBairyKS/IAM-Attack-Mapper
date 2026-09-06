"""Direct ``sts:AssumeRole`` reachability (not itself an escalation technique).

If a principal is (a) named in a role's trust policy as a trusted
principal, and (b) has ``sts:AssumeRole`` allowed on that role's ARN in
their own identity policy, they can assume it and simply *use* its
permissions. This isn't a misconfiguration on its own, but it's an edge
in the same reachability graph -- a human able to assume an
over-privileged role is exactly the kind of thing this tool exists to
surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from .models import Organization
from .policy_engine import PolicyEngine


@dataclass
class AssumeEdge:
    source: str
    target: str
    conditional: bool = False


def find_assume_role_edges(org: Organization, engine: PolicyEngine) -> Iterable[AssumeEdge]:
    for role in org.roles.values():
        for ts in role.trust_statements:
            if ts.effect != "Allow" or "sts:AssumeRole" not in ts.actions:
                continue
            for principal_ref in ts.principals:
                source = org.principal_by_arn(principal_ref)
                if source is None:
                    continue  # service principal, external account, or "*"
                res = engine.is_allowed(source.name, "sts:AssumeRole", role.arn)
                if res.allowed:
                    yield AssumeEdge(source=source.name, target=role.name, conditional=res.conditional)


@dataclass
class ExternalTrust:
    role: str
    principal_ref: str
    note: str


def find_external_trusts(org: Organization, own_account_id: str) -> List[ExternalTrust]:
    """Roles that trust a principal outside this account, or trust '*'."""
    findings: List[ExternalTrust] = []
    for role in org.roles.values():
        for ts in role.trust_statements:
            if ts.effect != "Allow":
                continue
            for principal_ref in ts.principals:
                if principal_ref == "*":
                    findings.append(ExternalTrust(role.name, principal_ref, "trusts ANY AWS principal (wildcard)"))
                elif principal_ref.startswith("arn:aws:iam::") and f"::{own_account_id}:" not in principal_ref:
                    findings.append(
                        ExternalTrust(role.name, principal_ref, "trusts a principal in a different AWS account")
                    )
    return findings
