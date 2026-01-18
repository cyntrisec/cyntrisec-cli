"""
diff command - Compare two scan snapshots to detect changes.
"""

from __future__ import annotations

import logging

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
from cyntrisec.cli.schemas import DiffResponse
from cyntrisec.core.diff import ChangeType, SnapshotDiff
from cyntrisec.storage import FileSystemStorage

console = Console()
log = logging.getLogger(__name__)


def _find_scan_id(scan_ids: list[str], partial: str) -> str:
    """Find a scan ID by partial match."""
    if partial in scan_ids:
        return partial
    for scan_id in scan_ids:
        if partial in scan_id:
            return scan_id
    return partial


@handle_errors
def diff_cmd(
    old_snapshot: str | None = typer.Option(
        None,
        "--old",
        "-o",
        help="Old snapshot ID (default: second most recent)",
    ),
    new_snapshot: str | None = typer.Option(
        None,
        "--new",
        "-n",
        help="New snapshot ID (default: most recent)",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: table, json, agent (defaults to json when piped)",
    ),
    show_all: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="Show all changes including assets and relationships",
    ),
):
    """
    Compare two scan snapshots to detect changes.
    """
    output_format = resolve_format(
        format,
        default_tty="table",
        allowed=["table", "json", "agent"],
    )

    storage = FileSystemStorage()
    scan_ids = storage.list_scans()
    if len(scan_ids) < 2:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="Need at least 2 scans to compare. Run 'cyntrisec scan' again.",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    new_scan_id = _find_scan_id(scan_ids, new_snapshot) if new_snapshot else scan_ids[0]
    old_scan_id = _find_scan_id(scan_ids, old_snapshot) if old_snapshot else scan_ids[1]

    old_snap = storage.get_snapshot(old_scan_id)
    new_snap = storage.get_snapshot(new_scan_id)
    if not old_snap or not new_snap:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="Could not load snapshots for diff.",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    old_assets = storage.get_assets(old_scan_id)
    old_rels = storage.get_relationships(old_scan_id)
    old_paths = storage.get_attack_paths(old_scan_id)
    old_findings = storage.get_findings(old_scan_id)

    new_assets = storage.get_assets(new_scan_id)
    new_rels = storage.get_relationships(new_scan_id)
    new_paths = storage.get_attack_paths(new_scan_id)
    new_findings = storage.get_findings(new_scan_id)

    differ = SnapshotDiff()
    result = differ.diff(
        old_assets=old_assets,
        old_relationships=old_rels,
        old_paths=old_paths,
        old_findings=old_findings,
        new_assets=new_assets,
        new_relationships=new_rels,
        new_paths=new_paths,
        new_findings=new_findings,
        old_snapshot_id=old_snap.id,
        new_snapshot_id=new_snap.id,
    )

    if output_format in {"json", "agent"}:
        payload = _build_payload(result, old_snap, new_snap)
        actions = suggested_actions(
            [
                (
                    f"cyntrisec analyze paths --scan {new_snapshot or 'latest'}",
                    "Review new attack paths",
                ),
                (
                    f"cyntrisec cuts --snapshot {new_snapshot or 'latest'}",
                    "Find fixes for new regressions",
                ),
            ]
        )
        emit_agent_or_json(
            output_format,
            payload,
            suggested=actions,
            status="regressions" if result.has_regressions else "success",
            artifact_paths=build_artifact_paths(storage, new_scan_id),
            schema=DiffResponse,
        )
    else:
        _output_table(result, old_snap, new_snap, show_all)

    if result.has_regressions:
        raise typer.Exit(1)
    raise typer.Exit(0)


def _output_table(result, old_snap, new_snap, show_all: bool):
    """Display diff as formatted tables."""
    console.print()

    summary = result.summary

    if result.has_regressions:
        status_icon = "REGRESSION"
        status_color = "red"
        status_text = "REGRESSIONS DETECTED"
    elif result.has_improvements:
        status_icon = "IMPROVED"
        status_color = "green"
        status_text = "IMPROVEMENTS FOUND"
    else:
        status_icon = "="
        status_color = "cyan"
        status_text = "NO SECURITY CHANGES"

    console.print(
        Panel(
            f"[bold {status_color}]{status_icon} {status_text}[/bold {status_color}]\n\n"
            f"Comparing:\n"
            f"  Old: {old_snap.aws_account_id} @ {old_snap.started_at:%Y-%m-%d %H:%M}\n"
            f"  New: {new_snap.aws_account_id} @ {new_snap.started_at:%Y-%m-%d %H:%M}",
            title="cyntrisec diff",
            border_style=status_color,
        )
    )
    console.print()

    summary_table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    summary_table.add_column("Category", style="cyan")
    summary_table.add_column("Added", justify="right", style="green")
    summary_table.add_column("Removed", justify="right", style="red")

    summary_table.add_row("Assets", f"+{summary['assets_added']}", f"-{summary['assets_removed']}")
    summary_table.add_row(
        "Relationships",
        f"+{summary['relationships_added']}",
        f"-{summary['relationships_removed']}",
    )
    summary_table.add_row(
        "Attack Paths", f"+{summary['paths_added']}", f"-{summary['paths_removed']}"
    )
    summary_table.add_row(
        "Findings", f"+{summary['findings_new']}", f"-{summary['findings_resolved']}"
    )

    console.print(summary_table)
    console.print()

    if result.path_changes:
        path_table = Table(
            title="Attack Path Changes",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold yellow",
        )
        path_table.add_column("Status", width=12)
        path_table.add_column("Vector", width=20)
        path_table.add_column("Risk", justify="right", width=8)

        for change in result.path_changes:
            status = (
                "[red]+ NEW (regression)[/red]"
                if change.change_type == ChangeType.added
                else "[green]- FIXED[/green]"
            )
            path_table.add_row(
                status, change.path.attack_vector, f"{float(change.path.risk_score):.2f}"
            )

        console.print(path_table)
        console.print()

    if result.finding_changes:
        finding_table = Table(title="Finding Changes", box=box.ROUNDED, show_header=True)
        finding_table.add_column("Status", width=12)
        finding_table.add_column("Severity", width=10)
        finding_table.add_column("Finding", min_width=30)

        for change in result.finding_changes:
            status = (
                "[red]+ NEW[/red]"
                if change.change_type == ChangeType.added
                else "[green]- FIXED[/green]"
            )
            sev_style = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            }.get(change.finding.severity, "white")
            finding_table.add_row(
                status,
                f"[{sev_style}]{change.finding.severity.upper()}[/]",
                change.finding.title[:50],
            )

        console.print(finding_table)
        console.print()

    if show_all and result.asset_changes:
        asset_table = Table(title="Asset Changes", box=box.SIMPLE)
        asset_table.add_column("Status", width=8)
        asset_table.add_column("Type", width=15)
        asset_table.add_column("Name", min_width=30)

        for change in result.asset_changes[:20]:
            status = (
                "[green]+[/green]" if change.change_type == ChangeType.added else "[red]-[/red]"
            )
            asset_table.add_row(status, change.asset.asset_type, change.asset.name[:40])

        if len(result.asset_changes) > 20:
            asset_table.add_row("...", f"+{len(result.asset_changes) - 20} more", "")

        console.print(asset_table)
        console.print()


def _build_payload(result, old_snap, new_snap):
    """Build structured output for JSON/agent formats."""
    return {
        "old_snapshot": {
            "id": str(old_snap.id),
            "account_id": old_snap.aws_account_id,
            "timestamp": old_snap.started_at.isoformat(),
        },
        "new_snapshot": {
            "id": str(new_snap.id),
            "account_id": new_snap.aws_account_id,
            "timestamp": new_snap.started_at.isoformat(),
        },
        "summary": result.summary,
        "has_regressions": result.has_regressions,
        "has_improvements": result.has_improvements,
        "path_changes": [
            {
                "change_type": c.change_type.value,
                "attack_vector": c.path.attack_vector,
                "risk_score": float(c.path.risk_score),
                "is_regression": c.is_regression,
                "is_improvement": c.is_improvement,
            }
            for c in result.path_changes
        ],
        "finding_changes": [
            {
                "change_type": c.change_type.value,
                "severity": c.finding.severity,
                "title": c.finding.title,
                "is_regression": c.is_regression,
            }
            for c in result.finding_changes
        ],
    }
