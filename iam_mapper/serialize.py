"""JSON (de)serialization for :mod:`iam_mapper.models`.

Keeping this separate from ``models.py`` means the dataclasses stay
plain and boto3-shaped, while all "how do we persist this" logic lives
in one place.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Dict

from .models import Group, Organization, Policy, Role, Statement, TrustStatement, User


def _statement_from_dict(d: Dict[str, Any]) -> Statement:
    return Statement(
        effect=d["effect"],
        actions=list(d["actions"]),
        resources=list(d.get("resources", ["*"])),
        not_action=bool(d.get("not_action", False)),
        condition=d.get("condition"),
    )


def _policy_from_dict(d: Dict[str, Any]) -> Policy:
    return Policy(
        name=d["name"],
        arn=d["arn"],
        statements=[_statement_from_dict(s) for s in d.get("statements", [])],
        aws_managed=bool(d.get("aws_managed", False)),
    )


def _trust_statement_from_dict(d: Dict[str, Any]) -> TrustStatement:
    return TrustStatement(
        effect=d["effect"],
        principals=list(d["principals"]),
        actions=list(d.get("actions", ["sts:AssumeRole"])),
        condition=d.get("condition"),
    )


def _user_from_dict(d: Dict[str, Any]) -> User:
    return User(
        name=d["name"],
        arn=d["arn"],
        attached_policies=list(d.get("attached_policies", [])),
        inline_policies=[_policy_from_dict(p) for p in d.get("inline_policies", [])],
        groups=list(d.get("groups", [])),
        permissions_boundary=d.get("permissions_boundary"),
        has_console_password=bool(d.get("has_console_password", False)),
        access_keys=int(d.get("access_keys", 0)),
    )


def _role_from_dict(d: Dict[str, Any]) -> Role:
    return Role(
        name=d["name"],
        arn=d["arn"],
        trust_statements=[_trust_statement_from_dict(t) for t in d.get("trust_statements", [])],
        attached_policies=list(d.get("attached_policies", [])),
        inline_policies=[_policy_from_dict(p) for p in d.get("inline_policies", [])],
        permissions_boundary=d.get("permissions_boundary"),
    )


def _group_from_dict(d: Dict[str, Any]) -> Group:
    return Group(
        name=d["name"],
        arn=d["arn"],
        attached_policies=list(d.get("attached_policies", [])),
        inline_policies=[_policy_from_dict(p) for p in d.get("inline_policies", [])],
        members=list(d.get("members", [])),
    )


def organization_to_dict(org: Organization) -> Dict[str, Any]:
    return {
        "account_id": org.account_id,
        "users": [asdict(u) for u in org.users.values()],
        "roles": [asdict(r) for r in org.roles.values()],
        "groups": [asdict(g) for g in org.groups.values()],
        "policies": [asdict(p) for p in org.policies.values()],
    }


def organization_from_dict(d: Dict[str, Any]) -> Organization:
    org = Organization(account_id=d["account_id"])
    for p in d.get("policies", []):
        org.add_policy(_policy_from_dict(p))
    for u in d.get("users", []):
        org.add_user(_user_from_dict(u))
    for r in d.get("roles", []):
        org.add_role(_role_from_dict(r))
    for g in d.get("groups", []):
        org.add_group(_group_from_dict(g))
    return org


def save_organization(org: Organization, path: str) -> None:
    with open(path, "w") as f:
        json.dump(organization_to_dict(org), f, indent=2)
        f.write("\n")


def load_organization(path: str) -> Organization:
    with open(path) as f:
        return organization_from_dict(json.load(f))
