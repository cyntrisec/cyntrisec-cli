"""
comply command - Check compliance against security frameworks.
"""

from __future__ import annotations

import logging

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table

from cyntrisec.cli.errors import EXIT_CODE_MAP, CyntriError, ErrorCode, handle_errors
from cyntrisec.cli.output import (
    build_artifact_paths,
    emit_agent_or_json,
    resolve_format,
    suggested_actions,
)
from cyntrisec.cli.schemas import ComplyResponse
from cyntrisec.core.compliance import ComplianceChecker, Framework
from cyntrisec.storage import FileSystemStorage

console = Console()
log = logging.getLogger(__name__)


@handle_errors
def comply_cmd(
    framework: str = typer.Option(
        "cis-aws",
        "--framework",
        "-fw",
        help="Compliance framework: cis-aws, soc2",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: table, json, agent (defaults to json when piped)",
    ),
    show_passing: bool = typer.Option(
        False,
        "--show-passing",
        "-p",
        help="Show passing controls (default: only failing)",
    ),
    snapshot_id: str | None = typer.Option(
        None,
        "--snapshot",
        "-s",
        help="Specific snapshot ID (default: latest)",
    ),
):
    """
    Check compliance against security frameworks.
    """
    output_format = resolve_format(
        format,
        default_tty="table",
        allowed=["table", "json", "agent"],
    )

    storage = FileSystemStorage()
    findings = storage.get_findings(snapshot_id)
    assets = storage.get_assets(snapshot_id)
    snapshot = storage.get_snapshot(snapshot_id)

    if not snapshot:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="No scan data found. Run 'cyntrisec scan' first.",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    # Map CLI string to Framework enum
    framework_map = {
        "cis-aws": Framework.CIS_AWS,
        "cis_aws": Framework.CIS_AWS,
        "CIS-AWS": Framework.CIS_AWS,
        "soc2": Framework.SOC2,
        "SOC2": Framework.SOC2,
    }
    fw = framework_map.get(framework)
    if not fw:
        raise CyntriError(
            error_code=ErrorCode.INVALID_QUERY,
            message=f"Invalid framework: {framework}. Use 'cis-aws' or 'soc2'.",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    checker = ComplianceChecker()
    results = checker.check(findings, assets, framework=fw)

    # Get scan_id for suggested actions
    scan_id = storage.resolve_scan_id(snapshot_id)

    if output_format in {"json", "agent"}:
        payload = _build_payload(results, fw, snapshot, show_passing)
        # Generate appropriate suggested actions based on compliance status
        if results.failing > 0:
            actions = suggested_actions(
                [
                    (
                        f"cyntrisec explain control {results.results[0].control.id}"
                        if results.results
                        else "",
                        "Explain top failing control" if results.results else "",
                    ),
                    (
                        f"cyntrisec cuts --snapshot {scan_id}" if scan_id else "",
                        "Map compliance fixes to attack path cuts" if scan_id else "",
                    ),
                ]
            )
        else:
            # Clean scan - no failing controls
            actions = suggested_actions(
                [
                    (
                        f"cyntrisec diff --old {scan_id}" if scan_id else "",
                        "Monitor for compliance drift" if scan_id else "",
                    ),
                    (
                        "cyntrisec scan",
                        "Run periodic scans to maintain compliance",
                    ),
                ]
            )
        emit_agent_or_json(
            output_format,
            payload,
            suggested=actions,
            artifact_paths=build_artifact_paths(storage, snapshot_id),
            schema=ComplyResponse,
        )
    else:
        _output_table(results, fw, show_passing)

    if results.failing == 0:
        raise typer.Exit(0)
    raise typer.Exit(1)


def _output_table(results, framework: Framework, show_passing: bool):
    """Render compliance results."""
    passing = results.passing
    failing = results.failing
    total = passing + failing
    score = results.compliance_score * 100

    console.print()
    console.print(
        Panel(
            f"[bold]Compliance Report[/bold]\n"
            f"Framework: {framework.value}\n"
            f"Score: {score:.0f}% ({passing}/{total})",
            title="cyntrisec comply",
            border_style="green" if failing == 0 else "red",
        )
    )
    console.print()
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
    ) as progress:
        task = progress.add_task("Controls", total=total)
        progress.update(task, completed=passing)

    table = Table(
        title="Controls",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Status", width=10)
    table.add_column("Control")
    table.add_column("Severity", width=12)
    table.add_column("Description", min_width=40)

    for r in results.results:
        if r.status == "pass" and not show_passing:
            continue
        status = "[green]PASS[/green]" if r.status == "pass" else "[red]FAIL[/red]"
        table.add_row(status, r.control.id, r.control.severity, r.control.title[:60])

    console.print(table)


def _build_payload(results, framework: Framework, snapshot, show_passing: bool):
    """Build structured payload for JSON/agent outputs."""
    return {
        "framework": framework.value,
        "compliance_score": results.compliance_score,
        "passing": results.passing,
        "failing": results.failing,
        "controls": [
            {
                "id": r.control.id,
                "title": r.control.title,
                "status": r.status,
                "severity": r.control.severity,
                "description": r.control.title,
            }
            for r in results.results
            if show_passing or r.status != "pass"
        ],
    }
