"""Command-line entry point: ``iam-mapper``."""

from __future__ import annotations

import sys

import click

from .analyzer import analyze
from .export import export_graphml, export_json
from .report import render_json, render_text
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


@main.command(name="analyze")
@click.option("-i", "--input", "input_path", required=True, help="Path to an account JSON file (see data/sample_org.json for the schema).")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text", show_default=True)
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


if __name__ == "__main__":
    main()
