"""
Report Command - Generate reports from scan results.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import typer

from cyntrisec.cli.errors import EXIT_CODE_MAP, CyntriError, ErrorCode, handle_errors
from cyntrisec.cli.output import (
    build_artifact_paths,
    emit_agent_or_json,
    resolve_format,
    suggested_actions,
)
from cyntrisec.cli.schemas import ReportResponse


def _infer_format_from_extension(output_path: Path) -> str | None:
    """Infer output format from file extension."""
    name = output_path.name.lower()
    if name.endswith(".html"):
        return "html"
    if name.endswith(".json"):
        return "json"
    return None


@handle_errors
def report_cmd(
    scan_id: str | None = typer.Option(
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
    title: str | None = typer.Option(
        None,
        "--title",
        "-t",
        help="Report title",
    ),
    format: str | None = typer.Option(
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

    # Infer format from output file extension if not explicitly specified
    inferred_format = format
    if inferred_format is None:
        inferred_format = _infer_format_from_extension(output)

    output_format = resolve_format(
        inferred_format,
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
        actions = suggested_actions(
            [
                ("cyntrisec analyze paths --format agent", "Inspect top attack paths"),
                ("cyntrisec cuts --format agent", "Prioritize fixes to block paths"),
            ]
        )
        emit_agent_or_json(
            output_format,
            {
                "snapshot_id": str(snapshot.id),
                "account_id": snapshot.aws_account_id,
                "output_path": str(output),
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
    """Generate standalone HTML report with CLI/Terminal aesthetic."""
    import html

    snapshot = data.get("snapshot", {})
    assets = data.get("assets", [])
    findings = data.get("findings", [])
    paths = data.get("attack_paths", [])

    allowed_severities = {"critical", "high", "medium", "low", "info"}

    def to_float(value: object, default: float = 0.0) -> float:
        try:
            return float(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return default

    def normalize_severity(value: object) -> str:
        sev = str(value or "info").strip().lower()
        return sev if sev in allowed_severities else "info"

    class SafeHtml(str):
        pass

    # Count findings by severity
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = normalize_severity(f.get("severity"))
        sev_counts[sev] += 1

    # Sort paths by risk (descending)
    paths.sort(key=lambda p: to_float(p.get("risk_score", 0)), reverse=True)

    # Sort findings by severity (critical first)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: sev_order.get(normalize_severity(f.get("severity")), 5))

    # --- CLI Report Helper Functions ---
    def render_row(cells, header=False):
        tag = "th" if header else "td"
        row_html = "<tr>"
        for cell in cells:
            if isinstance(cell, SafeHtml):
                cell_html = str(cell)
            else:
                cell_html = html.escape(str(cell), quote=True)
            row_html += f"<{tag}>{cell_html}</{tag}>"
        row_html += "</tr>"
        return row_html

    # Build Attack Paths Table
    if not paths:
        paths_section = '<div class="empty-state">> No attack paths discovered. System secure.</div>'
    else:
        rows = []
        for p in paths[:25]:
            risk = to_float(p.get("risk_score", 0))
            vector = p.get("attack_vector", "unknown")
            length = p.get("path_length", 0)
            entry = to_float(p.get("entry_confidence", 0))
            impact = to_float(p.get("impact_score", 0))

            # Colorize Risk
            risk_class = "risk-low"
            if risk >= 0.7: risk_class = "risk-critical"
            elif risk >= 0.4: risk_class = "risk-high"

            rows.append(render_row([
                SafeHtml(f'<span class="{risk_class}">{risk:.3f}</span>'),
                vector,
                length,
                f"{entry:.2f}",
                f"{impact:.2f}"
            ]))

        paths_section = f"""
        <table class="cli-table">
            <thead>{render_row(["RISK", "VECTOR", "LEN", "ENTRY", "IMPACT"], header=True)}</thead>
            <tbody>{"".join(rows)}</tbody>
        </table>
        """

    # Build Findings Table
    if not findings:
        findings_section = '<div class="empty-state">> No findings detected. Clean scan.</div>'
    else:
        rows = []
        for f in findings[:50]:
            sev = normalize_severity(f.get("severity"))
            ftype = f.get("finding_type", "")
            ftitle = f.get("title", "")
            rows.append(render_row([
                SafeHtml(f'<span class="badge badge-{sev}">{sev.upper()}</span>'),
                ftype,
                ftitle
            ]))

        findings_section = f"""
        <table class="cli-table">
            <thead>{render_row(["SEVERITY", "TYPE", "TITLE"], header=True)}</thead>
            <tbody>{"".join(rows)}</tbody>
        </table>
        """

    regions_val = ", ".join(str(r) for r in (snapshot.get("regions") or []))
    regions = html.escape(regions_val, quote=True)
    account_id = html.escape(str(snapshot.get("aws_account_id", "N/A")), quote=True)
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    safe_title = html.escape(title, quote=True)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{safe_title}</title>
    <style>
        :root {{
            --bg: #0c0c0c;
            --fg: #cccccc;
            --dim: #666666;
            --accent: #33ff00; /* Terminal Green */
            --accent-dim: #1a8000;
            --border: #333333;
            --panel: #111111;
            
            /* Severities */
            --sev-critical: #ff0055;
            --sev-high: #ff9900;
            --sev-medium: #ffcc00;
            --sev-low: #33ff00;
            --sev-info: #00ccff;
        }}
        
        @font-face {{
            font-family: 'Terminess';
            src: local('Consolas'), local('Monaco'), local('Andale Mono'), local('Ubuntu Mono'), monospace;
        }}

        * {{ box-sizing: border-box; }}
        
        body {{
            background-color: var(--bg);
            color: var(--fg);
            font-family: 'Terminess', monospace;
            font-size: 14px;
            margin: 0;
            padding: 20px;
            line-height: 1.5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            border: 1px solid var(--border);
            padding: 20px;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
        }}

        /* Header */
        header {{
            border-bottom: 2px dashed var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        
        h1 {{
            color: var(--accent);
            text-transform: uppercase;
            font-size: 24px;
            margin: 0 0 10px 0;
            letter-spacing: 1px;
            text-shadow: 0 0 5px rgba(51, 255, 0, 0.3);
        }}
        
        .meta {{
            color: var(--dim);
            font-size: 12px;
        }}

        /* Sections */
        h2 {{
            color: #fff;
            background: var(--border);
            display: inline-block;
            padding: 2px 10px;
            margin: 40px 0 15px 0;
            font-size: 16px;
            text-transform: uppercase;
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            border: 1px solid var(--border);
            background: var(--panel);
            padding: 15px;
            text-align: center;
        }}
        
        .stat-val {{
            font-size: 32px;
            font-weight: bold;
            display: block;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: var(--dim);
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        /* Colors for Stats */
        .sc-critical {{ color: var(--sev-critical); border-color: var(--sev-critical); }}
        .sc-high {{ color: var(--sev-high); border-color: var(--sev-high); }}
        
        /* Tables */
        .cli-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        
        .cli-table th {{
            text-align: left;
            border-bottom: 1px solid var(--fg);
            color: var(--accent);
            padding: 8px;
            text-transform: uppercase;
        }}
        
        .cli-table td {{
            border-bottom: 1px solid var(--border);
            padding: 8px;
            color: #eeeeee;
        }}
        
        .cli-table tr:hover td {{
            background-color: #1a1a1a;
            color: #fff;
        }}

        /* Badges & Pills */
        .badge {{
            padding: 2px 6px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
            border: 1px solid;
        }}
        
        .badge-critical {{ color: var(--sev-critical); border-color: var(--sev-critical); }}
        .badge-high {{ color: var(--sev-high); border-color: var(--sev-high); }}
        .badge-medium {{ color: var(--sev-medium); border-color: var(--sev-medium); }}
        .badge-low {{ color: var(--sev-low); border-color: var(--sev-low); }}
        .badge-info {{ color: var(--sev-info); border-color: var(--sev-info); }}

        .risk-critical {{ color: var(--sev-critical); font-weight: bold; }}
        .risk-high {{ color: var(--sev-high); }}
        .risk-low {{ color: var(--sev-low); }}

        .footer {{
            margin-top: 50px;
            border-top: 1px dotted var(--border);
            padding-top: 15px;
            text-align: center;
            font-size: 11px;
            color: var(--dim);
        }}
        
        a {{ color: var(--fg); text-decoration: none; border-bottom: 1px solid var(--dim); }}
        a:hover {{ color: var(--accent); border-color: var(--accent); }}

        .empty-state {{
            padding: 20px;
            color: var(--dim);
            font-style: italic;
            border: 1px dashed var(--border);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>> {safe_title}_</h1>
            <div class="meta">
                TARGET_ACCOUNT: {account_id} <br>
                REGIONS.......: {regions} <br>
                TIMESTAMP.....: {generated_at} <br>
                STATUS........: {len(findings)} FINDINGS DETECTED
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-val" style="color:#fff">{len(assets)}</span>
                <span class="stat-label">Assets Scanned</span>
            </div>
            <div class="stat-card">
                <span class="stat-val" style="color:var(--sev-high)">{len(paths)}</span>
                <span class="stat-label">Attack Paths</span>
            </div>
            <div class="stat-card sc-critical">
                <span class="stat-val">{sev_counts["critical"]}</span>
                <span class="stat-label">Critical</span>
            </div>
            <div class="stat-card sc-high">
                <span class="stat-val">{sev_counts["high"]}</span>
                <span class="stat-label">High Risk</span>
            </div>
        </div>

        <h2>// DETECTED ATTACK PATHS</h2>
        {paths_section}

        <h2>// SECURITY FINDINGS</h2>
        {findings_section}

        <div class="footer">
            [ CYNTRISEC SECURITY CLI v0.1 ] <br>
            <a href="https://cyntrisec.com">DOCUMENTATION</a> | <a href="https://github.com/cyntrisec/cyntrisec-cli">SOURCE</a>
        </div>
    </div>
</body>
</html>"""
