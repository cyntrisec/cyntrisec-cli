"""
can command - Test if a principal can access a resource.

Usage:
    cyntrisec can PRINCIPAL access RESOURCE [OPTIONS]

Examples:
    cyntrisec can ECforS access s3://secret-bucket
    cyntrisec can arn:aws:iam::123:role/MyRole access s3://data-bucket
    cyntrisec can MyRole access MyAdminRole --action sts:AssumeRole
"""

from __future__ import annotations

import logging

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cyntrisec.cli.errors import EXIT_CODE_MAP, CyntriError, ErrorCode, handle_errors
from cyntrisec.cli.output import emit_agent_or_json, resolve_format, suggested_actions
from cyntrisec.cli.schemas import CanResponse
from cyntrisec.storage import FileSystemStorage

console = Console()
log = logging.getLogger(__name__)


@handle_errors
def can_cmd(
    principal: str = typer.Argument(
        ...,
        help="IAM principal (role/user name or ARN)",
    ),
    access: str = typer.Argument(
        ...,
        help="Literal 'access' keyword",
    ),
    resource: str = typer.Argument(
        ...,
        help="Target resource (ARN, bucket name, or s3://path)",
    ),
    action: str | None = typer.Option(
        None,
        "--action",
        "-a",
        help="Specific action to test (auto-detected if not provided)",
    ),
    live: bool = typer.Option(
        False,
        "--live",
        "-l",
        help="Use AWS Policy Simulator API (requires IAM permissions)",
    ),
    role_arn: str | None = typer.Option(
        None,
        "--role-arn",
        "-r",
        help="AWS role to assume for live simulation",
    ),
    external_id: str | None = typer.Option(
        None,
        "--external-id",
        "-e",
        help="External ID for role assumption",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: text, json, agent (defaults to json when piped)",
    ),
    snapshot_id: str | None = typer.Option(
        None,
        "--snapshot",
        "-s",
        help="Specific snapshot ID (default: latest)",
    ),
):
    """
    Test if a principal can access a resource.

    Uses natural language syntax: "can PRINCIPAL access RESOURCE"

    Without --live, uses scan data and graph relationships.
    With --live, queries AWS IAM Policy Simulator for ground truth.

    Examples:
        cyntrisec can ECforS access s3://bucket
        cyntrisec can MyRole access arn:aws:secretsmanager:...:secret
        cyntrisec can AdminRole access ProdDB --action rds:CreateDBSnapshot
    """
    if access.lower() != "access":
        raise CyntriError(
            error_code=ErrorCode.INVALID_QUERY,
            message="Expected 'access' keyword. Usage: cyntrisec can PRINCIPAL access RESOURCE",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    output_format = resolve_format(
        format,
        default_tty="text",
        allowed=["text", "json", "agent"],
    )

    storage = FileSystemStorage()
    assets = storage.get_assets(snapshot_id)
    relationships = storage.get_relationships(snapshot_id)
    snapshot = storage.get_snapshot(snapshot_id)

    if not assets or not snapshot:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="No scan data found. Run 'cyntrisec scan' first.",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    # Resolve principal to ARN
    principal_arn = _resolve_principal(principal, assets)

    if live:
        try:
            result = _simulate_live(principal_arn, resource, action, role_arn, external_id)
        except PermissionError as e:
            raise CyntriError(
                error_code=ErrorCode.AWS_ACCESS_DENIED,
                message=str(e),
                exit_code=EXIT_CODE_MAP["usage"],
            )
    else:
        result = _simulate_offline(principal_arn, resource, action, assets, relationships)

    if output_format in {"json", "agent"}:
        payload = _build_payload(result, snapshot)
        followups = suggested_actions(
            [
                (
                    f"cyntrisec cuts --snapshot {snapshot.id}"
                    if snapshot and result.can_access
                    else "",
                    "Identify changes that would block this access"
                    if snapshot and result.can_access
                    else "",
                ),
                (
                    f"cyntrisec analyze paths --scan {snapshot.id}"
                    if snapshot and not result.can_access
                    else "",
                    "Review other risky paths from the latest scan"
                    if snapshot and not result.can_access
                    else "",
                ),
                (
                    f"cyntrisec can {principal_arn} access {resource} --live" if not live else "",
                    "Validate against live IAM policy simulation" if not live else "",
                ),
            ]
        )
        emit_agent_or_json(output_format, payload, suggested=followups, schema=CanResponse)
    else:
        _output_text(result, snapshot)

    # Exit with code based on result
    raise typer.Exit(0 if result.can_access else 1)


def _resolve_principal(principal: str, assets) -> str:
    """Resolve principal name to ARN."""
    if principal.startswith("arn:"):
        return principal

    # Find by name in assets
    for asset in assets:
        if asset.asset_type == "iam:role" and asset.name == principal:
            return asset.arn or asset.aws_resource_id
        if asset.asset_type == "iam:user" and asset.name == principal:
            return asset.arn or asset.aws_resource_id

    # Return as-is and let the simulator handle it
    return principal


def _simulate_live(principal_arn, resource, action, role_arn, external_id):
    """Run live simulation using AWS API."""
    from cyntrisec.aws import CredentialProvider
    from cyntrisec.core.simulator import PolicySimulator

    console.print("[cyan]Running live policy simulation...[/cyan]")

    provider = CredentialProvider()
    if role_arn:
        session = provider.assume_role(role_arn, external_id=external_id)
    else:
        session = provider.default_session()

    simulator = PolicySimulator(session)
    return simulator.can_access(principal_arn, resource, action=action)


def _simulate_offline(principal_arn, resource, action, assets, relationships):
    """Run offline simulation using scan data."""
    from cyntrisec.core.simulator import OfflineSimulator

    simulator = OfflineSimulator(assets, relationships)
    return simulator.can_access(principal_arn, resource, action=action)


def _output_text(result, snapshot):
    """Display result as formatted text."""
    console.print()

    if result.can_access:
        icon = "ALLOW"
        color = "green"
        status = "YES"
    else:
        icon = "DENY"
        color = "red"
        status = "NO"

    console.print(
        Panel(
            f"[bold {color}]{icon} {status}[/bold {color}]: "
            f"[white]{result.principal_arn.split('/')[-1]}[/white] can "
            f"{'access' if result.can_access else '[dim]NOT[/dim] access'} "
            f"[cyan]{result.target_resource}[/cyan]",
            title="cyntrisec can",
            border_style=color,
        )
    )

    # Show proof
    if result.simulations:
        console.print()
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
        table.add_column("Action", style="cyan")
        table.add_column("Decision", width=15)
        table.add_column("Matched", justify="right")

        for sim in result.simulations:
            if sim.decision.value == "allowed":
                decision = "[green]ALLOWED[/green]"
            elif sim.decision.value == "explicitDeny":
                decision = "[red]EXPLICIT DENY[/red]"
            else:
                decision = "[yellow]IMPLICIT DENY[/yellow]"

            table.add_row(
                sim.action,
                decision,
                str(len(sim.matched_statements)),
            )

        console.print(table)
    elif result.proof:
        console.print()
        console.print(f"[dim]Via: {result.proof.get('relationship_type', 'graph analysis')}[/dim]")

    console.print()


def _build_payload(result, snapshot):
    """Build structured output for JSON/agent formats."""
    return {
        "snapshot_id": str(snapshot.id) if snapshot else None,
        "principal": result.principal_arn,
        "resource": result.target_resource,
        "action": result.action,
        "can_access": result.can_access,
        "simulations": [
            {
                "action": s.action,
                "resource": s.resource,
                "decision": s.decision.value,
                "matched_statements": len(s.matched_statements),
            }
            for s in result.simulations
        ]
        if result.simulations
        else [],
        "proof": result.proof,
    }
