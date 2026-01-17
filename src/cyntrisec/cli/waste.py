"""
waste command - Find unused IAM capabilities for blast radius reduction.

Usage:
    cyntrisec waste [OPTIONS]
    
Examples:
    cyntrisec waste                   # Analyze using scan data (no AWS calls)
    cyntrisec waste --live            # Fetch live usage data from AWS
    cyntrisec waste --days 90         # Consider unused if not accessed in 90 days
    cyntrisec waste --format json     # Machine-readable output
"""
from __future__ import annotations

import logging
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from cyntrisec.storage import FileSystemStorage
from cyntrisec.core.waste import WasteAnalyzer
from cyntrisec.core.cost_estimator import CostEstimator
from cyntrisec.cli.output import emit_agent_or_json, resolve_format, suggested_actions, build_artifact_paths
from cyntrisec.cli.errors import handle_errors, CyntriError, ErrorCode, EXIT_CODE_MAP
from cyntrisec.cli.schemas import WasteResponse

console = Console()
log = logging.getLogger(__name__)


@handle_errors
def waste_cmd(
    days: int = typer.Option(
        90,
        "--days", "-d",
        help="Days threshold for considering a permission unused",
    ),
    live: bool = typer.Option(
        False,
        "--live", "-l",
        help="Fetch live usage data from AWS (requires IAM permissions)",
    ),
    role_arn: Optional[str] = typer.Option(
        None,
        "--role-arn", "-r", 
        help="AWS role to assume for live analysis",
    ),
    external_id: Optional[str] = typer.Option(
        None,
        "--external-id", "-e",
        help="External ID for role assumption",
    ),
    format: Optional[str] = typer.Option(
        None,
        "--format", "-f",
        help="Output format: table, json, agent (defaults to json when piped)",
    ),
    cost_source: str = typer.Option(
        "estimate",
        "--cost-source",
        help="Cost data source: estimate (static), pricing-api, cost-explorer",
    ),
    max_roles: int = typer.Option(
        20,
        "--max-roles",
        help="Maximum number of roles to analyze (API throttling)",
    ),
    snapshot_id: Optional[str] = typer.Option(
        None,
        "--snapshot", "-s",
        help="Specific snapshot ID (default: latest)",
    ),
):
    """
    Analyze IAM roles for unused permissions (blast radius reduction).
    
    Compares granted permissions against actual usage to identify
    opportunities to reduce attack surface.
    
    Without --live, uses heuristic analysis of scan data.
    With --live, fetches actual usage data from AWS IAM Access Advisor.
    """
    output_format = resolve_format(
        format,
        default_tty="table",
        allowed=["table", "json", "agent"],
    )

    storage = FileSystemStorage()
    assets = storage.get_assets(snapshot_id)
    snapshot = storage.get_snapshot(snapshot_id)

    if not assets or not snapshot:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="No scan data found. Run 'cyntrisec scan' first.",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    analyzer = WasteAnalyzer(days_threshold=days)
    usage_reports = None

    if live:
        # Fetch real usage data from AWS
        usage_reports = _collect_live_usage(
            assets, role_arn, external_id, max_roles
        )
    
    # Run analysis
    report = analyzer.analyze_from_assets(assets, usage_reports)

    if output_format in {"json", "agent"}:
        cost_estimator = CostEstimator(source=cost_source)
        payload = _build_payload(report, snapshot, days, cost_estimator, assets)
        actions = suggested_actions([
            (
                f"cyntrisec comply --snapshot {snapshot_id or 'latest'} --format agent",
                "Connect unused permissions to compliance gaps",
            ),
            (
                f"cyntrisec cuts --snapshot {snapshot_id or 'latest'}",
                "Prioritize fixes that remove risky unused permissions",
            ),
        ])
        emit_agent_or_json(
            output_format,
            payload,
            suggested=actions,
            artifact_paths=build_artifact_paths(storage, snapshot_id),
            schema=WasteResponse,
        )
    else:
        _output_table(report, snapshot, days)


def _collect_live_usage(assets, role_arn, external_id, max_roles):
    """Collect live usage data from AWS."""
    from cyntrisec.aws import CredentialProvider
    from cyntrisec.aws.collectors.usage import UsageCollector
    
    console.print("[cyan]Fetching live usage data from AWS...[/cyan]")
    
    provider = CredentialProvider()
    if role_arn:
        session = provider.assume_role(role_arn, external_id=external_id)
    else:
        session = provider.default_session()
    
    collector = UsageCollector(session)
    
    # Get IAM role ARNs from assets
    role_arns = [
        a.arn for a in assets 
        if a.asset_type == "iam:role" and a.arn
    ]
    
    if not role_arns:
        console.print("[yellow]No IAM roles found in scan data.[/yellow]")
        return []
    
    console.print(f"[dim]Analyzing {min(len(role_arns), max_roles)} roles...[/dim]")
    return collector.collect_all_roles(role_arns, max_roles=max_roles)


def _output_table(report, snapshot, days):
    """Display results as a rich table."""
    console.print()
    
    # Summary panel
    reduction_pct = report.blast_radius_reduction * 100
    console.print(Panel(
        f"[bold]Unused Permissions Analysis[/bold]\n"
        f"Account: {snapshot.aws_account_id if snapshot else 'unknown'}\n"
        f"Threshold: {days} days\n"
        f"Unused: {report.total_unused} / {report.total_permissions} permissions\n"
        f"Blast Radius Reduction: [green]{reduction_pct:.0f}%[/green]",
        title="cyntrisec waste",
        border_style="yellow",
    ))
    console.print()

    if not report.role_reports:
        console.print("[green]No obvious waste found.[/green]")
        console.print("[dim]Run with --live for detailed IAM Access Advisor analysis.[/dim]")
        return

    # Table per role with findings
    for role_report in report.role_reports:
        if not role_report.unused_capabilities:
            continue
            
        table = Table(
            title=f"Role: {role_report.role_name}",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold yellow",
        )
        table.add_column("Risk", style="bold", width=8)
        table.add_column("Service", width=25)
        table.add_column("Status", width=20)
        table.add_column("Recommendation", min_width=30)

        for cap in role_report.unused_capabilities:
            risk_style = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            }.get(cap.risk_level, "white")
            
            if cap.days_unused is None:
                status = "[red]Never used[/red]"
            else:
                status = f"[yellow]{cap.days_unused} days[/yellow]"
            
            table.add_row(
                f"[{risk_style}]{cap.risk_level.upper()}[/]",
                cap.service_name,
                status,
                cap.recommendation,
            )

        console.print(table)
        console.print()
    
    # Summary
    console.print(
        f"[yellow]Remove {report.total_unused} unused permissions to reduce "
        f"blast radius by {reduction_pct:.0f}%[/yellow]"
    )


def _build_payload(report, snapshot, days, cost_estimator=None, assets=None):
    """Build structured output with optional cost estimates."""
    # Build asset lookup for cost estimation
    asset_lookup = {a.id: a for a in assets} if assets else {}
    
    return {
        "snapshot_id": str(snapshot.id) if snapshot else None,
        "account_id": snapshot.aws_account_id if snapshot else None,
        "days_threshold": days,
        "total_permissions": report.total_permissions,
        "total_unused": report.total_unused,
        "blast_radius_reduction": report.blast_radius_reduction,
        "roles": [
            {
                "role_arn": r.role_arn,
                "role_name": r.role_name,
                "total_services": r.total_services,
                "unused_services": r.unused_services,
                "reduction": r.blast_radius_reduction,
                "unused_capabilities": [
                    _build_capability_dict(c, r, cost_estimator, asset_lookup)
                    for c in r.unused_capabilities
                ],
            }
            for r in report.role_reports
        ],
    }


def _build_capability_dict(c, role_report, cost_estimator, asset_lookup):
    """Build capability dict with optional cost estimate."""
    result = {
        "service": c.service,
        "service_name": c.service_name,
        "days_unused": c.days_unused,
        "risk_level": c.risk_level,
        "recommendation": c.recommendation,
    }
    
    # Note: Cost estimation for IAM roles is heuristic-based.
    # For actual resource costs (NAT, EIP, EBS), use analyze business command.
    
    return result

