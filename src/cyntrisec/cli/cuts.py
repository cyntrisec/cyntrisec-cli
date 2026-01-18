"""
cuts command - Find minimal remediations that block attack paths.

Usage:
    cyntrisec cuts [OPTIONS]

Examples:
    cyntrisec cuts                    # Show top 5 remediations
    cyntrisec cuts --max-cuts 10      # Show top 10
    cyntrisec cuts --format json      # Machine-readable output
"""

from __future__ import annotations

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cyntrisec.cli.errors import EXIT_CODE_MAP, CyntriError, ErrorCode, handle_errors
from cyntrisec.cli.output import (
    build_artifact_paths,
    emit_agent_or_json,
    resolve_format,
    suggested_actions,
)
from cyntrisec.cli.schemas import CutsResponse
from cyntrisec.core.cost_estimator import CostEstimator
from cyntrisec.core.cuts import MinCutFinder
from cyntrisec.core.graph import GraphBuilder
from cyntrisec.storage import FileSystemStorage

console = Console()


@handle_errors
def cuts_cmd(
    max_cuts: int = typer.Option(
        5,
        "--max-cuts",
        "-n",
        help="Maximum number of remediations to return",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: table, json, agent (defaults to json when piped)",
    ),
    snapshot_id: str | None = typer.Option(
        None,
        "--snapshot",
        "-s",
        help="Specific snapshot ID (default: latest)",
    ),
    cost_source: str = typer.Option(
        "estimate",
        "--cost-source",
        help="Cost data source: estimate (static), pricing-api, cost-explorer",
    ),
):
    """
    Find minimal remediations that block the most attack paths.

    Uses a greedy set-cover algorithm to identify the smallest set of
    changes that would disconnect entry points from sensitive targets.

    Exit codes:
        0 - No attack paths (nothing to cut)
        0 - Remediations found
        2 - Error
    """
    output_format = resolve_format(
        format,
        default_tty="table",
        allowed=["table", "json", "agent"],
    )

    storage = FileSystemStorage()

    # Load data from storage
    assets = storage.get_assets(snapshot_id)
    relationships = storage.get_relationships(snapshot_id)
    paths = storage.get_attack_paths(snapshot_id)
    snapshot = storage.get_snapshot(snapshot_id)

    if not assets or not snapshot:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="No scan data found. Run 'cyntrisec scan' first.",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    if not paths:
        console.print("[green]No attack paths found - nothing to remediate.[/green]")
        raise typer.Exit(0)

    # Build graph and find cuts
    graph = GraphBuilder().build(assets=assets, relationships=relationships)
    finder = MinCutFinder()
    result = finder.find_cuts(graph, paths, max_cuts=max_cuts)

    if output_format in {"json", "agent"}:
        cost_estimator = CostEstimator(source=cost_source)
        payload = _build_payload(result, snapshot, graph, cost_estimator)
        top_rem = result.remediations[0] if result.remediations else None
        followups = suggested_actions(
            [
                (
                    f"cyntrisec can {top_rem.source_name} access {top_rem.target_name}"
                    if top_rem
                    else "",
                    "Verify the highest-priority remediation closes access" if top_rem else "",
                ),
                (
                    f"cyntrisec report --scan {snapshot.id}" if snapshot else "",
                    "Export a full report for stakeholders" if snapshot else "",
                ),
            ]
        )
        artifact_paths = build_artifact_paths(storage, snapshot_id)
        emit_agent_or_json(
            output_format,
            payload,
            suggested=followups,
            artifact_paths=artifact_paths,
            schema=CutsResponse,
        )
    else:
        _output_table(result, snapshot)


def _output_table(result, snapshot):
    """Display results as a rich table."""
    # Header panel
    console.print()
    console.print(
        Panel(
            f"[bold]Minimal Cut Analysis[/bold]\n"
            f"Account: {snapshot.aws_account_id if snapshot else 'unknown'}\n"
            f"Attack Paths: {result.total_paths} -> "
            f"[green]{result.paths_blocked} blocked[/green] "
            f"({result.coverage:.0%} coverage)",
            title="cyntrisec cuts",
            border_style="cyan",
        )
    )
    console.print()

    if not result.remediations:
        console.print("[yellow]No remediations found that would block attack paths.[/yellow]")
        return

    # Main table
    table = Table(
        title=f"Top {len(result.remediations)} Remediations",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Blocks", justify="right", style="green", width=8)
    table.add_column("Action", style="yellow", width=15)
    table.add_column("Remediation", style="white", min_width=40)

    for i, rem in enumerate(result.remediations, 1):
        table.add_row(
            str(i),
            f"{len(rem.paths_blocked)} paths",
            rem.action,
            rem.description,
        )

    console.print(table)
    console.print()

    # Summary
    if result.coverage < 1.0:
        remaining = result.total_paths - result.paths_blocked
        console.print(
            f"[yellow]{remaining} paths remain unblocked. "
            f"Increase --max-cuts to find more.[/yellow]"
        )
    else:
        console.print(
            f"[green]All {result.total_paths} attack paths can be blocked "
            f"with {len(result.remediations)} changes.[/green]"
        )


def _build_payload(result, snapshot, graph=None, cost_estimator=None):
    """Build structured output for JSON/agent modes."""
    remediations = []

    for i, rem in enumerate(result.remediations):
        rem_dict = {
            "priority": i + 1,
            "action": rem.action,
            "description": rem.description,
            "relationship_type": rem.relationship_type,
            "source": rem.source_name,
            "target": rem.target_name,
            "paths_blocked": len(rem.paths_blocked),
            "path_ids": [str(p) for p in rem.paths_blocked],
        }

        # Add cost estimate for target asset if available
        if cost_estimator and graph:
            target_asset = graph.asset(rem.relationship.target_asset_id)
            if target_asset:
                estimate = cost_estimator.estimate(target_asset)
                if estimate:
                    rem_dict["estimated_monthly_savings"] = float(
                        estimate.monthly_cost_usd_estimate
                    )
                    rem_dict["cost_source"] = estimate.cost_source
                    rem_dict["cost_confidence"] = estimate.confidence
                    rem_dict["cost_assumptions"] = estimate.assumptions

        remediations.append(rem_dict)

    return {
        "snapshot_id": str(snapshot.id) if snapshot else None,
        "account_id": snapshot.aws_account_id if snapshot else None,
        "total_paths": result.total_paths,
        "paths_blocked": result.paths_blocked,
        "coverage": result.coverage,
        "remediations": remediations,
    }
