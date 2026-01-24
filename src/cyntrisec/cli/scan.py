"""
Scan Command - Run AWS scans.
"""

from __future__ import annotations

import logging

import typer

from cyntrisec.cli.errors import EXIT_CODE_MAP, CyntriError, ErrorCode, handle_errors
from cyntrisec.cli.output import (
    build_artifact_paths,
    emit_agent_or_json,
    resolve_format,
    suggested_actions,
)
from cyntrisec.cli.schemas import ScanResponse

log = logging.getLogger(__name__)


@handle_errors
def scan_cmd(
    role_arn: str | None = typer.Option(
        None,
        "--role-arn",
        "-r",
        help="AWS IAM role ARN to assume (read-only access)",
    ),
    regions: str = typer.Option(
        "us-east-1",
        "--regions",
        help="Comma-separated list of AWS regions to scan",
    ),
    external_id: str | None = typer.Option(
        None,
        "--external-id",
        "-e",
        help="External ID for role assumption",
    ),
    role_session_name: str | None = typer.Option(
        None,
        "--role-session-name",
        help="Session name for role assumption (default: cyntrisec-scan)",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help="AWS CLI profile for base credentials",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: text, json, agent (defaults to json when piped)",
    ),
    business_config: str | None = typer.Option(
        None,
        "--business-config",
        "-b",
        help="Path to business configuration file (yaml/json)",
    ),
):
    """
    Run AWS security scan.

    Scans an AWS account using read-only API calls to discover:

    - Infrastructure resources (EC2, IAM, S3, Lambda, RDS, etc.)

    - Network connectivity and security groups

    - Attack paths through the infrastructure

    - Security misconfigurations

    Examples:

        cyntrisec scan --role-arn arn:aws:iam::123456789012:role/ReadOnly

        cyntrisec scan -r arn:aws:iam::123456789012:role/ReadOnly --regions us-east-1,eu-west-1
    """
    from cyntrisec.aws import AwsScanner
    from cyntrisec.storage import FileSystemStorage

    # Parse regions
    region_list = [r.strip() for r in regions.split(",")]
    output_format = resolve_format(
        format,
        default_tty="text",
        allowed=["text", "json", "agent"],
    )

    typer.echo("Starting AWS scan...", err=True)
    typer.echo(f"  Role: {role_arn or 'default credentials'}", err=True)
    typer.echo(f"  Regions: {', '.join(region_list)}", err=True)

    # Create storage and scanner
    storage = FileSystemStorage()
    scanner = AwsScanner(storage)

    try:
        snapshot = scanner.scan(
            regions=region_list,
            role_arn=role_arn,
            external_id=external_id,
            role_session_name=role_session_name,
            profile=profile,
            business_config=business_config,
        )
    except PermissionError as e:
        raise CyntriError(
            error_code=ErrorCode.AWS_ACCESS_DENIED,
            message=str(e),
            exit_code=EXIT_CODE_MAP["usage"],
        )
    except Exception as e:
        log.exception("Scan failed")
        raise CyntriError(
            error_code=ErrorCode.INTERNAL_ERROR,
            message=str(e),
            exit_code=EXIT_CODE_MAP["internal"],
        )

    # Print summary
    typer.echo("", err=True)
    typer.echo("Scan complete!", err=True)
    typer.echo(f"  Assets: {snapshot.asset_count}", err=True)
    typer.echo(f"  Relationships: {snapshot.relationship_count}", err=True)
    typer.echo(f"  Findings: {snapshot.finding_count}", err=True)
    typer.echo(f"  Attack paths: {snapshot.path_count}", err=True)

    # Print warnings if there were partial failures
    if snapshot.errors:
        typer.echo("", err=True)
        typer.echo("Warnings:", err=True)
        for err in snapshot.errors:
            service = err.get("service", "unknown")
            region = err.get("region", "")
            error_msg = err.get("error", "unknown error")
            if region:
                typer.echo(f"  - Failed to collect {service} in {region}: {error_msg}", err=True)
            else:
                typer.echo(f"  - Failed to collect {service}: {error_msg}", err=True)

    typer.echo("", err=True)
    typer.echo("Run 'cyntrisec analyze paths' to view attack paths", err=True)
    typer.echo("Run 'cyntrisec report' to generate HTML report", err=True)

    # Get the scan_id (directory name) for use in suggested actions
    scan_id = storage.resolve_scan_id(None)  # Get latest scan_id
    artifact_paths = build_artifact_paths(storage, scan_id)

    # Build warnings from snapshot errors
    warnings = None
    if snapshot.errors:
        warnings = [
            f"Failed to collect {err.get('service', 'unknown')}"
            + (f" in {err['region']}" if "region" in err else "")
            + f": {err.get('error', 'unknown error')}"
            for err in snapshot.errors
        ]

    # Determine status based on errors
    status = "completed_with_errors" if snapshot.errors else "success"

    summary = {
        "scan_id": scan_id,
        "snapshot_id": str(snapshot.id),
        "status": status,
        "account_id": snapshot.aws_account_id,
        "regions": snapshot.regions,
        "asset_count": snapshot.asset_count,
        "relationship_count": snapshot.relationship_count,
        "finding_count": snapshot.finding_count,
        "attack_path_count": snapshot.path_count,
        "warnings": warnings,
    }
    followups = suggested_actions(
        [
            (f"cyntrisec analyze paths --scan {scan_id}", "Review discovered attack paths"),
            (
                f"cyntrisec cuts --snapshot {snapshot.id}",
                "Prioritize fixes that block paths",
            ),
            (
                f"cyntrisec report --scan {scan_id} --output cyntrisec-report.html",
                "Generate a full report",
            ),
        ]
    )

    if output_format in {"json", "agent"}:
        emit_agent_or_json(
            output_format,
            summary,
            suggested=followups,
            artifact_paths=artifact_paths,
            schema=ScanResponse,
        )

    # Exit code based on paths found
    if snapshot.path_count > 0:
        raise typer.Exit(1)  # Paths found
    raise typer.Exit(0)
