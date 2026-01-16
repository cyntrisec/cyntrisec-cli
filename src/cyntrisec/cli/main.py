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


# Import and add subcommands
# We do this lazily to avoid import errors if boto3 isn't installed
def _register_commands():
    from cyntrisec.cli.scan import scan_cmd
    from cyntrisec.cli.analyze import analyze_app
    from cyntrisec.cli.report import report_cmd
    from cyntrisec.cli.setup import setup_app
    
    app.command("scan")(scan_cmd)
    app.add_typer(analyze_app, name="analyze", help="Analyze scan results")
    app.command("report")(report_cmd)
    app.add_typer(setup_app, name="setup", help="Setup commands")


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
    
    # Register commands after logging is configured
    _register_commands()


@app.command()
def version():
    """Show version information."""
    from cyntrisec import __version__
    typer.echo(f"cyntrisec {__version__}")


if __name__ == "__main__":
    app()
