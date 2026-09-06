"""Export the reachability graph for external tools (Gephi, yEd, a future web UI)."""

from __future__ import annotations

import json

import networkx as nx
from networkx.readwrite import json_graph


def export_graphml(graph: nx.MultiDiGraph, path: str) -> None:
    nx.write_graphml(graph, path)


def export_json(graph: nx.MultiDiGraph, path: str) -> None:
    data = json_graph.node_link_data(graph, edges="edges")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
