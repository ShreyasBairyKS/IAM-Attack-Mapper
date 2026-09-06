"""Build the reachability graph: nodes are principals, edges are ways
one principal can gain another's effective privileges.
"""

from __future__ import annotations

import networkx as nx

from .escalation_rules import all_escalation_edges
from .models import Organization
from .policy_engine import PolicyEngine
from .trust import find_assume_role_edges


def build_graph(org: Organization, engine: PolicyEngine = None) -> nx.MultiDiGraph:
    engine = engine or PolicyEngine(org)
    graph = nx.MultiDiGraph()

    for principal in org.all_principals():
        graph.add_node(
            principal.name,
            kind=principal.kind,
            arn=principal.arn,
            is_admin=engine.is_admin(principal.name),
        )

    for edge in find_assume_role_edges(org, engine):
        graph.add_edge(
            edge.source,
            edge.target,
            technique="AssumeRole",
            detail=f"can assume role '{edge.target}' (trusted + sts:AssumeRole allowed)",
            conditional=edge.conditional,
            edge_kind="assume",
        )

    for edge in all_escalation_edges(org, engine):
        if edge.source == edge.target:
            continue  # self-loops are reported separately as direct self-escalation
        if engine.is_admin(edge.source):
            continue  # trivially true (an admin can do anything) and not a discovery
        graph.add_edge(
            edge.source,
            edge.target,
            technique=edge.technique,
            detail=edge.detail,
            conditional=edge.conditional,
            edge_kind="escalate",
        )

    return graph


def self_escalation_techniques(org: Organization, engine: PolicyEngine = None):
    """Principals who can directly grant *themselves* admin (source == target)."""
    engine = engine or PolicyEngine(org)
    for edge in all_escalation_edges(org, engine):
        if edge.source == edge.target and not engine.is_admin(edge.source):
            yield edge
