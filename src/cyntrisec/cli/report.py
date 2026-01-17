"""
Report Command - Generate reports from scan results.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

from cyntrisec.cli.output import emit_agent_or_json, resolve_format, suggested_actions, build_artifact_paths
from cyntrisec.cli.errors import handle_errors, CyntriError, ErrorCode, EXIT_CODE_MAP
from cyntrisec.cli.schemas import ReportResponse


@handle_errors
def report_cmd(
    scan_id: Optional[str] = typer.Option(
        None,
        "--scan",
        "-s",
        help="Scan ID (default: latest)",
    ),
    output: Path = typer.Option(
        Path("cyntrisec-report.html"),
        "--output",
        "-o",
        help="Output file path",
    ),
    title: Optional[str] = typer.Option(
        None,
        "--title",
        "-t",
        help="Report title",
    ),
    format: Optional[str] = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: html, json, agent (defaults to json when piped)",
    ),
):
    """
    Generate report from scan results.
    
    Examples:
    
        cyntrisec report --output report.html
        
        cyntrisec report --format json --output report.json
    """
    from cyntrisec.storage import FileSystemStorage
    
    storage = FileSystemStorage()
    snapshot = storage.get_snapshot(scan_id)
    output_format = resolve_format(
        format,
        default_tty="html",
        allowed=["html", "json", "agent"],
    )
    
    if not snapshot:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="No scan found.",
            exit_code=EXIT_CODE_MAP["usage"],
        )
    
    if not title:
        title = f"Cyntrisec Security Report - {snapshot.aws_account_id}"

    # If caller didn't override output and we emit JSON/agent, use .json for clarity
    if output_format in {"json", "agent"} and output.suffix.lower() == ".html":
        output = output.with_suffix(".json")
    
    data = storage.export_all(scan_id)
    
    artifact_paths = build_artifact_paths(storage, scan_id)

    if output_format in {"json", "agent"}:
        output.write_text(json.dumps(data, indent=2, default=str))
        actions = suggested_actions([
            ("cyntrisec analyze paths --format agent", "Inspect top attack paths"),
            ("cyntrisec cuts --format agent", "Prioritize fixes to block paths"),
        ])
        emit_agent_or_json(
            output_format,
            {
                "snapshot_id": str(snapshot.id),
                "account_id": snapshot.aws_account_id,
                "output_path": str(output),
                "format": "json",
                "findings": len(data.get("findings", [])),
                "paths": len(data.get("attack_paths", [])),
            },
            suggested=actions,
            artifact_paths=artifact_paths,
            schema=ReportResponse,
        )
    else:
        html = _generate_html(data, title)
        output.write_text(html)
        typer.echo(f"HTML report written to {output}")


def _generate_html(data: dict, title: str) -> str:
    """Generate standalone HTML report."""
    snapshot = data.get("snapshot", {})
    assets = data.get("assets", [])
    findings = data.get("findings", [])
    paths = data.get("attack_paths", [])
    
    # Count findings by severity
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    
    # Sort paths by risk
    paths.sort(key=lambda p: float(p.get("risk_score", 0)), reverse=True)
    
    # Sort findings by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))
    
    # Build paths table rows
    path_rows = []
    for p in paths[:25]:
        risk = float(p.get('risk_score', 0))
        vector = p.get('attack_vector', 'unknown')
        length = p.get('path_length', 0)
        entry = float(p.get('entry_confidence', 0))
        impact = float(p.get('impact_score', 0))
        path_rows.append(
            f'<tr><td><strong>{risk:.3f}</strong></td>'
            f'<td>{vector}</td><td>{length}</td>'
            f'<td>{entry:.2f}</td><td>{impact:.2f}</td></tr>'
        )
    
    # Build attack paths section
    if not paths:
        paths_section = '<p style="color:#8b949e;">No attack paths discovered.</p>'
    else:
        paths_section = '''<table>
            <thead><tr><th>Risk</th><th>Vector</th><th>Length</th><th>Entry</th><th>Impact</th></tr></thead>
            <tbody>''' + ''.join(path_rows) + '''</tbody>
        </table>'''
    
    # Build findings table rows
    finding_rows = []
    for f in findings[:50]:
        sev = f.get('severity', 'info')
        ftype = f.get('finding_type', '')
        ftitle = f.get('title', '')
        finding_rows.append(
            f'<tr><td><span class="pill pill-{sev}">{sev.upper()}</span></td>'
            f'<td>{ftype}</td><td>{ftitle}</td></tr>'
        )
    
    # Build findings section
    if not findings:
        findings_section = '<p style="color:#8b949e;">No findings discovered.</p>'
    else:
        findings_section = '''<table>
            <thead><tr><th>Severity</th><th>Type</th><th>Title</th></tr></thead>
            <tbody>''' + ''.join(finding_rows) + '''</tbody>
        </table>'''
    
    regions = ', '.join(snapshot.get('regions', []))
    account_id = snapshot.get('aws_account_id', 'N/A')
    generated_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --fg: #c9d1d9;
            --accent: #58a6ff;
            --critical: #f85149;
            --high: #db6d28;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
            --border: #30363d;
            --card-bg: #161b22;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--fg);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3 {{ color: #fff; margin-bottom: 1rem; }}
        h1 {{ font-size: 1.75rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
        h2 {{ font-size: 1.25rem; margin-top: 2rem; color: var(--accent); }}
        .meta {{ color: #8b949e; margin-bottom: 2rem; font-size: 0.875rem; }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 1rem;
        }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat {{ text-align: center; padding: 1rem; }}
        .stat-value {{ font-size: 2rem; font-weight: bold; color: var(--accent); }}
        .stat-label {{ color: #8b949e; font-size: 0.75rem; text-transform: uppercase; }}
        .stat-critical .stat-value {{ color: var(--critical); }}
        .stat-high .stat-value {{ color: var(--high); }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
        th, td {{ text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); }}
        th {{ color: #8b949e; font-weight: 500; text-transform: uppercase; font-size: 0.75rem; }}
        tr:hover {{ background: rgba(88, 166, 255, 0.05); }}
        .pill {{ display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.625rem; font-weight: 600; text-transform: uppercase; }}
        .pill-critical {{ background: rgba(248,81,73,0.2); color: var(--critical); }}
        .pill-high {{ background: rgba(219,109,40,0.2); color: var(--high); }}
        .pill-medium {{ background: rgba(210,153,34,0.2); color: var(--medium); }}
        .pill-low {{ background: rgba(63,185,80,0.2); color: var(--low); }}
        .pill-info {{ background: rgba(88,166,255,0.2); color: var(--info); }}
        .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: #8b949e; font-size: 0.75rem; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p class="meta">Account: {account_id} &bull; Regions: {regions} &bull; Generated: {generated_at}</p>
        
        <div class="stats">
            <div class="card stat"><div class="stat-value">{len(assets)}</div><div class="stat-label">Assets</div></div>
            <div class="card stat"><div class="stat-value">{len(findings)}</div><div class="stat-label">Findings</div></div>
            <div class="card stat"><div class="stat-value">{len(paths)}</div><div class="stat-label">Attack Paths</div></div>
            <div class="card stat stat-critical"><div class="stat-value">{sev_counts['critical']}</div><div class="stat-label">Critical</div></div>
            <div class="card stat stat-high"><div class="stat-value">{sev_counts['high']}</div><div class="stat-label">High</div></div>
        </div>
        
        <h2>Attack Paths ({len(paths)})</h2>
        <div class="card">{paths_section}</div>
        
        <h2>Security Findings ({len(findings)})</h2>
        <div class="card">{findings_section}</div>
        
        <div class="footer">
            Generated by Cyntrisec CLI &bull; Read-Only AWS Security Analysis &bull;
            <a href="https://github.com/cyntrisec/cyntrisec-cli" style="color:var(--accent);">GitHub</a>
        </div>
    </div>
</body>
</html>'''
