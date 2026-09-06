"""Tests for iam_mapper.export: writing the reachability graph for external tools."""

import json

import networkx as nx

from iam_mapper.export import export_graphml, export_json


def _sample_graph():
    graph = nx.MultiDiGraph()
    graph.add_node("alice", kind="user", arn="arn:aws:iam::123:user/alice", is_admin=False)
    graph.add_node("admin-role", kind="role", arn="arn:aws:iam::123:role/admin-role", is_admin=True)
    graph.add_edge(
        "alice", "admin-role",
        technique="AssumeRole", detail="can assume role", conditional=False, edge_kind="assume",
    )
    return graph


def test_export_json_writes_node_link_data(tmp_path):
    graph = _sample_graph()
    out = tmp_path / "graph.json"

    export_json(graph, str(out))

    assert out.exists()
    data = json.loads(out.read_text())
    node_ids = {n["id"] for n in data["nodes"]}
    assert node_ids == {"alice", "admin-role"}
    assert len(data["edges"]) == 1
    edge = data["edges"][0]
    assert edge["source"] == "alice"
    assert edge["target"] == "admin-role"
    assert edge["technique"] == "AssumeRole"


def test_export_json_ends_with_trailing_newline(tmp_path):
    out = tmp_path / "graph.json"
    export_json(_sample_graph(), str(out))
    assert out.read_text().endswith("\n")


def test_export_graphml_writes_readable_graph(tmp_path):
    graph = _sample_graph()
    out = tmp_path / "graph.graphml"

    export_graphml(graph, str(out))

    assert out.exists()
    loaded = nx.read_graphml(str(out))
    assert set(loaded.nodes) == {"alice", "admin-role"}
    assert loaded.has_edge("alice", "admin-role")


def test_export_json_empty_graph(tmp_path):
    out = tmp_path / "empty.json"
    export_json(nx.MultiDiGraph(), str(out))
    data = json.loads(out.read_text())
    assert data["nodes"] == []
    assert data["edges"] == []
