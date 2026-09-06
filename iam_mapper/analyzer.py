"""Turn the reachability graph into a ranked list of findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import networkx as nx

from .graph_builder import build_graph, self_escalation_techniques
from .models import Organization
from .policy_engine import PolicyEngine
from .trust import find_external_trusts

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_DOWNGRADE = {"Critical": "High", "High": "Medium", "Medium": "Low", "Low": "Low", "Info": "Info"}
_BASE_SEVERITY_BY_HOPS = {1: "Critical", 2: "High", 3: "Medium"}


def _severity_for_path(n_hops: int, conditional: bool) -> str:
    base = _BASE_SEVERITY_BY_HOPS.get(n_hops, "Low")
    return _DOWNGRADE[base] if conditional else base


@dataclass
class Hop:
    source: str
    target: str
    technique: str
    detail: str
    conditional: bool = False


@dataclass
class Finding:
    kind: str  # "self_escalation" | "path" | "already_admin" | "external_trust"
    severity: str
    source: Optional[str] = None
    target: Optional[str] = None
    hops: List[Hop] = field(default_factory=list)
    conditional: bool = False
    summary: str = ""

    def render_path(self) -> str:
        if not self.hops:
            return self.summary
        return " -> ".join(
            [self.hops[0].source] + [f"--[{h.technique}]--> {h.target}" for h in self.hops]
        )


@dataclass
class AnalysisResult:
    findings: List[Finding]
    total_principals: int
    admin_count: int

    def by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]


def _rank_key(finding: Finding):
    return (SEVERITY_ORDER.index(finding.severity), len(finding.hops))


def analyze(org: Organization) -> AnalysisResult:
    engine = PolicyEngine(org)
    graph = build_graph(org, engine)
    findings: List[Finding] = []

    # 1. Principals who are already admin-equivalent.
    admin_names = {n for n, d in graph.nodes(data=True) if d.get("is_admin")}
    for name in sorted(admin_names):
        findings.append(
            Finding(
                kind="already_admin",
                severity="Info",
                source=name,
                summary=f"'{name}' is already admin-equivalent (has '*'/'*' or 'iam:*' access)",
            )
        )

    # 2. Direct self-escalation (source == target, source not already admin).
    #    A principal here is just as dangerous as an admin to anyone who can
    #    reach *them* -- so it also gets wired into the sink graph below.
    self_escalations = list(self_escalation_techniques(org, engine))
    for edge in self_escalations:
        findings.append(
            Finding(
                kind="self_escalation",
                severity=_severity_for_path(1, edge.conditional),
                source=edge.source,
                target=edge.source,
                hops=[Hop(edge.source, edge.target, edge.technique, edge.detail, edge.conditional)],
                conditional=edge.conditional,
                summary=f"'{edge.source}' can directly self-escalate to admin via {edge.technique}: {edge.detail}",
            )
        )

    # 3. Shortest path from every other principal to *any* admin-equivalent
    #    node (already-admin, or one hop from self-escalating to admin), via
    #    a virtual sink so we don't have to search per-target.
    sink = "__ADMIN_SINK__"
    g = graph.copy()
    g.add_node(sink)
    for name in admin_names:
        g.add_edge(name, sink, technique="IS_ADMIN", detail="", conditional=False, edge_kind="sink")
    for edge in self_escalations:
        g.add_edge(
            edge.source, sink,
            technique=edge.technique, detail=edge.detail, conditional=edge.conditional, edge_kind="sink",
        )

    escalatable = admin_names | {e.source for e in self_escalations}

    for name, data in graph.nodes(data=True):
        if name in escalatable or not nx.has_path(g, name, sink):
            continue
        full_path = nx.shortest_path(g, name, sink)  # [name, ..., <node before sink>, sink]
        hops: List[Hop] = []
        conditional_any = False
        for a, b in zip(full_path, full_path[1:]):
            edge_data = g.get_edge_data(a, b)
            first = next(iter(edge_data.values()))
            if first["technique"] == "IS_ADMIN":
                continue  # bookkeeping edge only -- arriving at an admin node already says it all
            target_label = "ADMIN-EQUIVALENT ACCESS" if b == sink else b
            hops.append(Hop(a, target_label, first["technique"], first["detail"], first.get("conditional", False)))
            conditional_any = conditional_any or first.get("conditional", False)
        if not hops:
            continue
        findings.append(
            Finding(
                kind="path",
                severity=_severity_for_path(len(hops), conditional_any),
                source=name,
                target=full_path[-2],
                hops=hops,
                conditional=conditional_any,
                summary=f"'{name}' can reach admin-equivalent access in {len(hops)} step(s)",
            )
        )

    # 4. Trust-policy hygiene: external accounts / wildcard trust.
    for ext in find_external_trusts(org, org.account_id):
        severity = "High" if ext.principal_ref == "*" else "Medium"
        findings.append(
            Finding(
                kind="external_trust",
                severity=severity,
                target=ext.role,
                summary=f"role '{ext.role}' {ext.note} ('{ext.principal_ref}')",
            )
        )

    findings.sort(key=_rank_key)
    return AnalysisResult(findings=findings, total_principals=len(org.all_principals()), admin_count=len(admin_names))
