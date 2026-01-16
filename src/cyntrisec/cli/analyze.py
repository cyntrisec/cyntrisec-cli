"""
Analyze Commands - Analyze scan results.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

analyze_app = typer.Typer(help="Analyze scan results")


@analyze_app.command("paths")
def analyze_paths(
    scan_id: Optional[str] = typer.Option(
        None,
        "--scan",
        "-s",
        help="Scan ID (default: latest)",
    ),
    min_risk: float = typer.Option(
        0.0,
        "--min-risk",
        help="Minimum risk score (0-1)",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        help="Maximum number of paths to show",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json",
    ),
):
    """
    Show attack paths from scan results.
    
    Attack paths are routes from internet-facing entry points
    to sensitive targets through the infrastructure.
    
    Examples:
    
        cyntrisec analyze paths --min-risk 0.5
        
        cyntrisec analyze paths --format json | jq '.paths[:5]'
    """
    from cyntrisec.storage import FileSystemStorage
    
    storage = FileSystemStorage()
    paths = storage.get_attack_paths(scan_id)
    
    # Filter by risk
    if min_risk > 0:
        paths = [p for p in paths if float(p.risk_score) >= min_risk]
    
    # Sort by risk
    paths.sort(key=lambda p: float(p.risk_score), reverse=True)
    
    # Limit
    paths = paths[:limit]
    
    if format == "json":
        data = {"paths": [p.model_dump(mode="json") for p in paths]}
        typer.echo(json.dumps(data, indent=2, default=str))
    else:
        # Table format
        if not paths:
            typer.echo("No attack paths found.")
            return
        
        typer.echo(f"{'Risk':<8} {'Vector':<25} {'Length':<8} {'Entry':<8} {'Impact':<8}")
        typer.echo("-" * 65)
        
        for p in paths:
            risk = float(p.risk_score)
            vector = p.attack_vector[:24]
            length = p.path_length
            entry = float(p.entry_confidence)
            impact = float(p.impact_score)
            typer.echo(f"{risk:<8.3f} {vector:<25} {length:<8} {entry:<8.3f} {impact:<8.3f}")
        
        typer.echo("")
        typer.echo(f"Total: {len(paths)} paths")


@analyze_app.command("findings")
def analyze_findings(
    scan_id: Optional[str] = typer.Option(
        None,
        "--scan",
        "-s",
        help="Scan ID (default: latest)",
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        help="Filter by severity: critical, high, medium, low, info",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json",
    ),
):
    """
    Show security findings from scan results.
    """
    from cyntrisec.storage import FileSystemStorage
    
    storage = FileSystemStorage()
    findings = storage.get_findings(scan_id)
    
    # Filter by severity
    if severity:
        findings = [f for f in findings if f.severity == severity]
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 5))
    
    if format == "json":
        data = {"findings": [f.model_dump(mode="json") for f in findings]}
        typer.echo(json.dumps(data, indent=2, default=str))
    else:
        if not findings:
            typer.echo("No findings found.")
            return
        
        typer.echo(f"{'Severity':<10} {'Type':<35} {'Title':<50}")
        typer.echo("-" * 95)
        
        for f in findings:
            sev = f.severity.upper()[:9]
            ftype = f.finding_type[:34]
            title = f.title[:49]
            typer.echo(f"{sev:<10} {ftype:<35} {title:<50}")
        
        typer.echo("")
        typer.echo(f"Total: {len(findings)} findings")


@analyze_app.command("stats")
def analyze_stats(
    scan_id: Optional[str] = typer.Option(
        None,
        "--scan",
        "-s",
        help="Scan ID (default: latest)",
    ),
):
    """
    Show summary statistics for a scan.
    """
    from cyntrisec.storage import FileSystemStorage
    
    storage = FileSystemStorage()
    
    snapshot = storage.get_snapshot(scan_id)
    if not snapshot:
        typer.echo("No scan found.", err=True)
        raise typer.Exit(2)
    
    assets = storage.get_assets(scan_id)
    findings = storage.get_findings(scan_id)
    paths = storage.get_attack_paths(scan_id)
    
    typer.echo("=== Scan Statistics ===")
    typer.echo("")
    typer.echo(f"Account: {snapshot.aws_account_id}")
    typer.echo(f"Regions: {', '.join(snapshot.regions)}")
    typer.echo(f"Status: {snapshot.status}")
    typer.echo(f"Started: {snapshot.started_at}")
    typer.echo(f"Completed: {snapshot.completed_at}")
    typer.echo("")
    
    typer.echo("--- Counts ---")
    typer.echo(f"Assets: {len(assets)}")
    typer.echo(f"Findings: {len(findings)}")
    typer.echo(f"Attack paths: {len(paths)}")
    typer.echo("")
    
    # Asset types
    asset_types = {}
    for a in assets:
        asset_types[a.asset_type] = asset_types.get(a.asset_type, 0) + 1
    
    typer.echo("--- Assets by Type ---")
    for t, count in sorted(asset_types.items(), key=lambda x: -x[1])[:10]:
        typer.echo(f"  {t}: {count}")
    
    # Finding severities
    severities = {}
    for f in findings:
        severities[f.severity] = severities.get(f.severity, 0) + 1
    
    if severities:
        typer.echo("")
        typer.echo("--- Findings by Severity ---")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severities:
                typer.echo(f"  {sev}: {severities[sev]}")
    
    # Attack path stats
    if paths:
        risks = [float(p.risk_score) for p in paths]
        typer.echo("")
        typer.echo("--- Attack Paths ---")
        typer.echo(f"  Highest risk: {max(risks):.3f}")
        typer.echo(f"  Average risk: {sum(risks)/len(risks):.3f}")
