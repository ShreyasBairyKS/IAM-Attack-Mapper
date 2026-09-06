"""Tests for the ``iam-mapper`` command-line interface."""

import builtins
import json

import boto3
import networkx as nx
import pytest
from click.testing import CliRunner
from moto import mock_aws

from iam_mapper.cli import main
from iam_mapper.models import Organization, User
from iam_mapper.serialize import save_organization
from iam_mapper.synthetic import build_sample_organization


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def sample_org_path(tmp_path):
    path = tmp_path / "org.json"
    save_organization(build_sample_organization(), str(path))
    return str(path)


@pytest.fixture
def clean_org_path(tmp_path):
    """An account with a single harmless user -- no findings at all."""
    org = Organization(account_id="000000000000")
    org.add_user(User(name="grace", arn="arn:aws:iam::000000000000:user/grace"))
    path = tmp_path / "clean_org.json"
    save_organization(org, str(path))
    return str(path)


def test_generate_sample_writes_file(runner, tmp_path):
    out_path = tmp_path / "generated.json"
    result = runner.invoke(main, ["generate-sample", "-o", str(out_path)])

    assert result.exit_code == 0
    assert out_path.exists()
    assert "Wrote synthetic account" in result.output
    assert str(out_path) in result.output

    data = json.loads(out_path.read_text())
    assert data["users"]
    assert data["roles"]


def test_analyze_text_output(runner, sample_org_path):
    result = runner.invoke(main, ["analyze", "-i", sample_org_path])

    assert result.exit_code == 0
    assert "IAM Attack-Path Mapper" in result.output
    assert "alice" in result.output


def test_analyze_no_color_strips_ansi(runner, sample_org_path):
    result = runner.invoke(main, ["analyze", "-i", sample_org_path, "--no-color"])

    assert result.exit_code == 0
    assert "\033[" not in result.output


def test_analyze_json_output(runner, sample_org_path):
    result = runner.invoke(main, ["analyze", "-i", sample_org_path, "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "findings" in payload
    assert payload["total_principals"] > 0
    assert any(f["source"] == "alice" for f in payload["findings"])


def test_analyze_output_report_writes_file(runner, sample_org_path, tmp_path):
    report_path = tmp_path / "report.txt"
    result = runner.invoke(main, ["analyze", "-i", sample_org_path, "--output-report", str(report_path)])

    assert result.exit_code == 0
    assert f"Report written to {report_path}" in result.output
    assert report_path.exists()
    content = report_path.read_text()
    assert "IAM Attack-Path Mapper" in content
    # Written report replaces stdout output of the rendered report itself.
    assert "alice" in content


def test_analyze_output_graph_json(runner, sample_org_path, tmp_path):
    graph_path = tmp_path / "graph.json"
    result = runner.invoke(main, ["analyze", "-i", sample_org_path, "--output-graph", str(graph_path)])

    assert result.exit_code == 0
    assert f"Graph exported to {graph_path}" in result.output
    assert graph_path.exists()
    data = json.loads(graph_path.read_text())
    assert data["nodes"]


def test_analyze_output_graph_graphml(runner, sample_org_path, tmp_path):
    graph_path = tmp_path / "graph.graphml"
    result = runner.invoke(main, ["analyze", "-i", sample_org_path, "--output-graph", str(graph_path)])

    assert result.exit_code == 0
    assert graph_path.exists()
    loaded = nx.read_graphml(str(graph_path))
    assert "alice" in loaded.nodes


def test_analyze_fail_on_triggers_nonzero_exit(runner, sample_org_path):
    result = runner.invoke(main, ["analyze", "-i", sample_org_path, "--fail-on", "Critical"])
    assert result.exit_code == 1


def test_analyze_fail_on_none_is_default_and_always_zero(runner, sample_org_path):
    result = runner.invoke(main, ["analyze", "-i", sample_org_path])
    assert result.exit_code == 0


def test_analyze_fail_on_does_not_trigger_when_no_findings_at_or_above(runner, clean_org_path):
    result = runner.invoke(main, ["analyze", "-i", clean_org_path, "--fail-on", "Critical"])
    assert result.exit_code == 0


def test_analyze_missing_input_file_errors(runner, tmp_path):
    missing = tmp_path / "does_not_exist.json"
    result = runner.invoke(main, ["analyze", "-i", str(missing)])
    assert result.exit_code != 0


@mock_aws
def test_collect_command_writes_org_json(runner, tmp_path):
    session = boto3.Session(region_name="us-east-1")
    session.client("iam").create_user(UserName="alice")

    out_path = tmp_path / "live_org.json"
    result = runner.invoke(main, ["collect", "--region", "us-east-1", "-o", str(out_path)])

    assert result.exit_code == 0
    assert "Collected live account" in result.output
    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert any(u["name"] == "alice" for u in data["users"])


def test_collect_command_errors_without_boto3(runner, monkeypatch, tmp_path):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "boto3":
            raise ImportError("simulated: boto3 not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = runner.invoke(main, ["collect", "-o", str(tmp_path / "x.json")])
    assert result.exit_code != 0
    assert "boto3 is required" in result.output
