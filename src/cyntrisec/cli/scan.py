"""
Scan Command - Run AWS scans.
"""
from __future__ import annotations

import logging
from typing import List, Optional

import typer

log = logging.getLogger(__name__)


def scan_cmd(
    role_arn: str = typer.Option(
        ...,
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
    
    typer.echo(f"Starting AWS scan...", err=True)
    typer.echo(f"  Role: {role_arn}", err=True)
    typer.echo(f"  Regions: {', '.join(region_list)}", err=True)
    
    # Create storage and scanner
    storage = FileSystemStorage()
    scanner = AwsScanner(storage)
    
    try:
        snapshot = scanner.scan(
            role_arn=role_arn,
            regions=region_list,
            external_id=external_id,
            profile=profile,
        )
    except PermissionError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(2)
    except Exception as e:
        log.exception("Scan failed")
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(2)
    
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
    
    # Exit code based on paths found
    if snapshot.path_count > 0:
        raise typer.Exit(1)  # Paths found
    raise typer.Exit(0)
