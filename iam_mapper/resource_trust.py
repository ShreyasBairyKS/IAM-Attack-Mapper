"""Resource-based policy hygiene: flags resources (S3 buckets, ...) whose
policy trusts a principal outside this account, or trusts "*".

This is deliberately the same check ``trust.py`` already does for role
trust policies, applied to resource policies instead. It is a hygiene
check, not a reachability model -- a flagged bucket isn't wired into the
escalation graph, because what an external principal could actually *do*
with bucket access depends on data the model doesn't have (is the bucket
public data, CI artifacts, Terraform state?). See README "Limitations".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .models import Organization


@dataclass
class ExternalResourceTrust:
    resource_arn: str
    resource_type: str
    principal_ref: str
    note: str


def find_external_resource_trusts(org: Organization, own_account_id: str) -> List[ExternalResourceTrust]:
    """Resources whose policy trusts a principal outside this account, or trusts '*'."""
    findings: List[ExternalResourceTrust] = []
    for rp in org.resource_policies:
        for stmt in rp.statements:
            if stmt.effect != "Allow":
                continue
            for principal_ref in stmt.principals:
                if principal_ref == "*":
                    findings.append(ExternalResourceTrust(
                        rp.resource_arn, rp.resource_type, principal_ref,
                        "trusts ANY AWS principal (wildcard)",
                    ))
                elif principal_ref.startswith("arn:aws:iam::") and f"::{own_account_id}:" not in principal_ref:
                    findings.append(ExternalResourceTrust(
                        rp.resource_arn, rp.resource_type, principal_ref,
                        "trusts a principal in a different AWS account",
                    ))
    return findings
