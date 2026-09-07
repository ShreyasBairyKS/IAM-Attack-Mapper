"""Command-line entry point: ``iam-mapper``."""

from __future__ import annotations

import sys

import click

from .analyzer import analyze
from .diff import diff_results
from .export import export_graphml, export_json
from .report import (
    render_diff_json,
    render_diff_sarif,
    render_diff_text,
    render_json,
    render_sarif,
    render_text,
)
from .serialize import load_organization, organization_to_dict, save_organization
from .synthetic import build_sample_organization


@click.group()
@click.version_option(package_name="iam-attack-mapper")
def main():
    """AWS IAM privilege-escalation path mapper."""


@main.command()
@click.option("-o", "--output", default="data/sample_org.json", show_default=True, help="Where to write the sample account JSON.")
def generate_sample(output: str):
    """Regenerate the synthetic demo account (data/sample_org.json)."""
    org = build_sample_organization()
    save_organization(org, output)
    click.echo(f"Wrote synthetic account ({len(org.all_principals())} principals) to {output}")


@main.command()
@click.option("--profile", default=None, help="AWS named profile to use (see `aws configure list-profiles`).")
@click.option("--region", default=None, help="AWS region for the STS/IAM clients (IAM itself is a global service).")
@click.option("--account-id", default=None, help="Override the account id (default: the caller's own, via STS).")
@click.option("-o", "--output", default="org.json", show_default=True, help="Where to write the collected account JSON.")
def collect(profile: str, region: str, account_id: str, output: str):
    """Pull live IAM state from a real AWS account (read-only; requires the `aws` extra)."""
    try:
        import boto3
    except ImportError as e:
        raise click.ClickException(
            "boto3 is required for this command: pip install iam-attack-mapper[aws]"
        ) from e

    from .aws_collector import collect_organization

    session = boto3.Session(profile_name=profile, region_name=region)
    org = collect_organization(session, account_id=account_id)
    save_organization(org, output)
    click.echo(f"Collected live account ({len(org.all_principals())} principals) to {output}")


@main.command(name="analyze")
@click.option("-i", "--input", "input_path", required=True, help="Path to an account JSON file (see data/sample_org.json for the schema).")
@click.option("--format", "fmt", type=click.Choice(["text", "json", "sarif"]), default="text", show_default=True,
              help="`sarif` produces SARIF 2.1.0, for GitHub code scanning or any SARIF-consuming tool.")
@click.option("--no-color", is_flag=True, help="Disable ANSI colors in text output.")
@click.option("--output-report", default=None, help="Write the report to a file instead of stdout.")
@click.option("--output-graph", default=None, help="Export the reachability graph (path ending in .graphml or .json).")
@click.option("--fail-on", type=click.Choice(["Critical", "High", "Medium", "Low", "none"]), default="none",
              help="Exit non-zero if any finding at or above this severity is present (for CI use).")
def analyze_cmd(input_path: str, fmt: str, no_color: bool, output_report: str, output_graph: str, fail_on: str):
    """Analyze an account JSON file and report escalation paths."""
    org = load_organization(input_path)
    result = analyze(org)

    if fmt == "json":
        rendered = render_json(result)
    elif fmt == "sarif":
        rendered = render_sarif(result, source_path=input_path)
    else:
        rendered = render_text(result, use_color=not no_color)

    if output_report:
        with open(output_report, "w") as f:
            f.write(rendered + "\n")
        click.echo(f"Report written to {output_report}")
    else:
        click.echo(rendered)

    if output_graph:
        from .graph_builder import build_graph
        from .policy_engine import PolicyEngine

        graph = build_graph(org, PolicyEngine(org))
        if output_graph.endswith(".graphml"):
            export_graphml(graph, output_graph)
        else:
            export_json(graph, output_graph)
        click.echo(f"Graph exported to {output_graph}")

    if fail_on != "none":
        from .analyzer import SEVERITY_ORDER

        threshold = SEVERITY_ORDER.index(fail_on)
        if any(SEVERITY_ORDER.index(f.severity) <= threshold for f in result.findings if f.kind != "already_admin"):
            sys.exit(1)


@main.command(name="diff")
@click.argument("baseline", type=click.Path(exists=True))
@click.argument("current", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["text", "json", "sarif"]), default="text", show_default=True,
              help="`sarif` includes only new/worsened findings (not resolved ones) -- suited to a per-run code scanning upload.")
@click.option("--no-color", is_flag=True, help="Disable ANSI colors in text output.")
@click.option("--fail-on-regression", is_flag=True,
              help="Exit non-zero if anything new appeared or got more severe since the baseline (for CI use).")
def diff_cmd(baseline: str, current: str, fmt: str, no_color: bool, fail_on_regression: bool):
    """Compare two account JSON snapshots and report newly introduced or resolved escalation paths.

    Typical continuous-scanning use: keep a BASELINE snapshot (e.g. last
    week's `iam-mapper collect` output) and diff it against a fresh
    CURRENT one to answer "did this deploy open a new escalation path?"
    without re-flagging findings that were already there.
    """
    old_result = analyze(load_organization(baseline))
    new_result = analyze(load_organization(current))
    result = diff_results(old_result, new_result)

    if fmt == "json":
        click.echo(render_diff_json(result))
    elif fmt == "sarif":
        click.echo(render_diff_sarif(result, source_path=current))
    else:
        click.echo(render_diff_text(result, use_color=not no_color))

    if fail_on_regression and result.has_regression():
        sys.exit(1)


if __name__ == "__main__":
    main()
