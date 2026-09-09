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


def test_analyze_sarif_output(runner, sample_org_path):
    result = runner.invoke(main, ["analyze", "-i", sample_org_path, "--format", "sarif"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]
    assert payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == sample_org_path


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


@mock_aws
def test_collect_command_include_s3_buckets_flag(runner, tmp_path):
    session = boto3.Session(region_name="us-east-1")
    session.client("iam").create_user(UserName="alice")
    session.client("s3").create_bucket(Bucket="open-bucket")
    session.client("s3").put_bucket_policy(Bucket="open-bucket", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}],
    }))

    out_path = tmp_path / "live_org.json"
    result = runner.invoke(main, ["collect", "--region", "us-east-1", "--include-s3-buckets", "-o", str(out_path)])

    assert result.exit_code == 0
    data = json.loads(out_path.read_text())
    assert data["resource_policies"]
    assert data["resource_policies"][0]["resource_arn"] == "arn:aws:s3:::open-bucket"


@mock_aws
def test_collect_command_include_scps_flag(runner, tmp_path):
    session = boto3.Session(region_name="us-east-1")
    session.client("iam").create_user(UserName="alice")
    orgs = session.client("organizations")
    orgs.create_organization(FeatureSet="ALL")
    root_id = orgs.list_roots()["Roots"][0]["Id"]
    account_id = orgs.list_accounts()["Accounts"][0]["Id"]
    orgs.enable_policy_type(RootId=root_id, PolicyType="SERVICE_CONTROL_POLICY")
    policy_id = orgs.create_policy(
        Name="deny-iam", Description="x", Type="SERVICE_CONTROL_POLICY",
        Content=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]}),
    )["Policy"]["PolicySummary"]["Id"]
    orgs.attach_policy(PolicyId=policy_id, TargetId=account_id)

    out_path = tmp_path / "live_org.json"
    result = runner.invoke(main, [
        "collect", "--region", "us-east-1", "--account-id", account_id, "--include-scps", "-o", str(out_path),
    ])

    assert result.exit_code == 0
    data = json.loads(out_path.read_text())
    assert any(p["name"] == "deny-iam" for p in data["scps"])


def test_collect_command_scp_access_denied_gives_friendly_error(runner, monkeypatch, tmp_path):
    from botocore.exceptions import ClientError

    def fake_collect_organization(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "not authorized"}}, "ListPoliciesForTarget",
        )

    monkeypatch.setattr("iam_mapper.aws_collector.collect_organization", fake_collect_organization)

    result = runner.invoke(main, ["collect", "--include-scps", "-o", str(tmp_path / "x.json")])
    assert result.exit_code != 0
    assert "management account or a delegated admin" in result.output


def test_collect_command_scp_no_organization_gives_friendly_error(runner, monkeypatch, tmp_path):
    from botocore.exceptions import ClientError

    def fake_collect_organization(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "not in use"}}, "ListPoliciesForTarget",
        )

    monkeypatch.setattr("iam_mapper.aws_collector.collect_organization", fake_collect_organization)

    result = runner.invoke(main, ["collect", "--include-scps", "-o", str(tmp_path / "x.json")])
    assert result.exit_code != 0
    assert "isn't part of an AWS Organization" in result.output


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


def test_diff_command_reports_new_findings(runner, clean_org_path, sample_org_path):
    result = runner.invoke(main, ["diff", clean_org_path, sample_org_path])

    assert result.exit_code == 0  # no --fail-on-regression: reporting only
    assert "Diff Report" in result.output
    assert "alice" in result.output


def test_diff_command_json_output(runner, clean_org_path, sample_org_path):
    result = runner.invoke(main, ["diff", clean_org_path, sample_org_path, "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["added"]
    assert not payload["removed"]


def test_diff_command_sarif_output(runner, clean_org_path, sample_org_path):
    result = runner.invoke(main, ["diff", clean_org_path, sample_org_path, "--format", "sarif"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]


def test_diff_command_fail_on_regression_triggers_nonzero_exit(runner, clean_org_path, sample_org_path):
    result = runner.invoke(main, ["diff", clean_org_path, sample_org_path, "--fail-on-regression"])
    assert result.exit_code == 1


def test_diff_command_no_regression_against_itself(runner, sample_org_path):
    result = runner.invoke(main, ["diff", sample_org_path, sample_org_path, "--fail-on-regression"])
    assert result.exit_code == 0
    assert "No changes between the two snapshots." in result.output


def test_diff_command_missing_file_errors(runner, sample_org_path, tmp_path):
    missing = tmp_path / "does_not_exist.json"
    result = runner.invoke(main, ["diff", sample_org_path, str(missing)])
    assert result.exit_code != 0
