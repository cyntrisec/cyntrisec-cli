"""
serve command - Run Cyntrisec as an MCP server for AI agents.

Usage:
    cyntrisec serve            # Start MCP server (stdio)
"""
from __future__ import annotations

import logging
import sys
from typing import Optional

import typer
from rich.console import Console

from cyntrisec.cli.errors import handle_errors, CyntriError, ErrorCode, EXIT_CODE_MAP
from cyntrisec.cli.output import emit_agent_or_json, resolve_format
from cyntrisec.cli.schemas import ServeToolsResponse

console = Console()
log = logging.getLogger(__name__)


@handle_errors
def serve_cmd(
    transport: str = typer.Option(
        "stdio",
        "--transport", "-t",
        help="Transport mode: stdio",
    ),
    list_tools: bool = typer.Option(
        False,
        "--list-tools", "-l",
        help="List available MCP tools and exit",
    ),
    format: Optional[str] = typer.Option(
        None,
        "--format", "-f",
        help="Output format when listing tools: text, json, agent",
    ),
):
    """
    Run Cyntrisec as an MCP (Model Context Protocol) server.
    
    This allows AI agents to invoke Cyntrisec tools directly
    for security analysis, attack path discovery, and remediation.
    
    Tools exposed:
    - get_scan_summary: Get latest scan stats
    - get_attack_paths: List discovered attack paths
    - get_remediations: Find optimal fixes
    - check_access: Test "can X access Y"
    - get_unused_permissions: Find waste
    - check_compliance: Check CIS/SOC2
    - compare_scans: Detect regressions
    """
    resolved_format = resolve_format(format, default_tty="text", allowed=["text", "json", "agent"])

    if list_tools:
        tools = _list_tools_data()
        if resolved_format in {"json", "agent"}:
            emit_agent_or_json(resolved_format, {"tools": tools}, schema=ServeToolsResponse)
        else:
            console.print_json(data={"tools": tools})
        return

    try:
        from cyntrisec.mcp.server import run_mcp_server, HAS_MCP
    except ImportError as e:
        raise CyntriError(
            error_code=ErrorCode.INTERNAL_ERROR,
            message=f"Import error: {e}",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    if not HAS_MCP:
        raise CyntriError(
            error_code=ErrorCode.INVALID_QUERY,
            message="MCP SDK not installed. Install with: pip install mcp",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    stderr_console = Console(file=sys.stderr)
    stderr_console.print("[cyan]Starting MCP server (stdio transport)...[/cyan]")
    stderr_console.print("[dim]AI agents can now invoke Cyntrisec tools[/dim]")
    try:
        run_mcp_server()
    except Exception as e:
        log.exception("Error in serve")
        raise CyntriError(
            error_code=ErrorCode.INTERNAL_ERROR,
            message=str(e),
            exit_code=EXIT_CODE_MAP["internal"],
        )


def _list_tools_data():
    """Return available MCP tools."""
    tools = [
        {
            "name": "get_scan_summary",
            "description": "Get summary of the latest AWS scan",
            "parameters": [],
        },
        {
            "name": "get_attack_paths",
            "description": "Get discovered attack paths with risk scores",
            "parameters": [
                {"name": "max_paths", "type": "integer", "default": 10}
            ],
        },
        {
            "name": "get_remediations",
            "description": "Find minimal set of fixes to block attack paths",
            "parameters": [
                {"name": "max_cuts", "type": "integer", "default": 5}
            ],
        },
        {
            "name": "check_access",
            "description": "Test if a principal can access a resource",
            "parameters": [
                {"name": "principal", "type": "string", "required": True},
                {"name": "resource", "type": "string", "required": True}
            ],
        },
        {
            "name": "get_unused_permissions",
            "description": "Find unused IAM permissions",
            "parameters": [
                {"name": "days_threshold", "type": "integer", "default": 90}
            ],
        },
        {
            "name": "check_compliance",
            "description": "Check CIS AWS or SOC 2 compliance",
            "parameters": [
                {"name": "framework", "type": "string", "enum": ["cis-aws", "soc2"], "default": "cis-aws"}
            ],
        },
        {
            "name": "compare_scans",
            "description": "Compare latest scan to previous for regressions",
            "parameters": [],
        },
    ]
    return tools
