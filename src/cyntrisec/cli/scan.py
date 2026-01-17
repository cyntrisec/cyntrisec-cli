"""
Scan Command - Run AWS scans.
"""
from __future__ import annotations

import logging
from typing import Optional

import typer

from cyntrisec.cli.output import emit_agent_or_json, resolve_format, suggested_actions, build_artifact_paths
from cyntrisec.cli.errors import handle_errors, CyntriError, ErrorCode, EXIT_CODE_MAP
from cyntrisec.cli.schemas import ScanResponse

log = logging.getLogger(__name__)


@handle_errors
def scan_cmd(
    role_arn: Optional[str] = typer.Option(
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
    external_id: Optional[str] = typer.Option(
        None,
        "--external-id",
        "-e",
        help="External ID for role assumption",
    ),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        "-p",
        help="AWS CLI profile for base credentials",
    ),
    format: Optional[str] = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: text, json, agent (defaults to json when piped)",
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
    from cyntrisec.storage import FileSystemStorage
    from cyntrisec.aws import AwsScanner

    # Parse regions
    region_list = [r.strip() for r in regions.split(",")]
    output_format = resolve_format(
        format,
        default_tty="text",
        allowed=["text", "json", "agent"],
    )
    
    typer.echo(f"Starting AWS scan...", err=True)
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
            profile=profile,
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
    typer.echo("", err=True)
    typer.echo("Run 'cyntrisec analyze paths' to view attack paths", err=True)
    typer.echo("Run 'cyntrisec report' to generate HTML report", err=True)

    artifact_paths = build_artifact_paths(storage, snapshot.id)
    summary = {
        "snapshot_id": str(snapshot.id),
        "account_id": snapshot.aws_account_id,
        "regions": snapshot.regions,
        "asset_count": snapshot.asset_count,
        "relationship_count": snapshot.relationship_count,
        "finding_count": snapshot.finding_count,
        "attack_path_count": snapshot.path_count,
    }
    followups = suggested_actions([
        (f"cyntrisec analyze paths --scan {snapshot.id}", "Review discovered attack paths"),
        (f"cyntrisec cuts --snapshot {snapshot.id}", "Prioritize fixes that block paths"),
        (f"cyntrisec report --scan {snapshot.id} --output cyntrisec-report.html", "Generate a full report"),
    ])

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
