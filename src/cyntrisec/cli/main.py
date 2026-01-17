"""
Cyntrisec CLI

Main entry point for the CLI application.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import typer

# Create main app
app = typer.Typer(
    name="cyntrisec",
    help="AWS capability graph analysis and attack path discovery",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main(
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress all output except errors",
    ),
):
    """
    Cyntrisec - AWS Capability Graph Analysis
    
    A read-only CLI tool for:
    
    - AWS attack path discovery
    
    - Security posture analysis
    
    - Cost optimization opportunities
    
    Run 'cyntrisec COMMAND --help' for command-specific help.
    """
    # Configure logging
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    logging.basicConfig(
        level=level,
        format="%(message)s" if not verbose else "%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


@app.command()
def version():
    """Show version information."""
    from cyntrisec import __version__
    typer.echo(f"cyntrisec {__version__}")


# Register subcommands at module load time
# Import inside try/except for graceful handling if deps missing
try:
    from cyntrisec.cli.scan import scan_cmd
    from cyntrisec.cli.analyze import analyze_app
    from cyntrisec.cli.report import report_cmd
    from cyntrisec.cli.setup import setup_app
    from cyntrisec.cli.validate import validate_role_cmd
    
    app.command("scan")(scan_cmd)
    app.add_typer(analyze_app, name="analyze", help="Analyze scan results")
    app.command("report")(report_cmd)
    app.add_typer(setup_app, name="setup", help="Setup commands")
    app.command("validate-role")(validate_role_cmd)
except ImportError as e:
    # Allow --version and --help to work even if deps missing
    pass


if __name__ == "__main__":
    app()

