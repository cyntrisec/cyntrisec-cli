"""
Cyntrisec CLI

Main entry point for the CLI application.
"""

from __future__ import annotations

import logging
import sys

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


# Register subcommands at module load time.
# Each command is imported individually so a single broken import
# does not prevent all other commands from registering.
_log = logging.getLogger(__name__)

_COMMANDS: list[tuple[str, str, str | None]] = [
    # (cli_name, import_path, typer_method)
    # typer_method is None for app.command(), "add_typer" for sub-apps
    ("scan", "cyntrisec.cli.scan:scan_cmd", None),
    ("analyze", "cyntrisec.cli.analyze:analyze_app", "add_typer"),
    ("report", "cyntrisec.cli.report:report_cmd", None),
    ("setup", "cyntrisec.cli.setup:setup_app", "add_typer"),
    ("validate-role", "cyntrisec.cli.validate:validate_role_cmd", None),
    ("cuts", "cyntrisec.cli.cuts:cuts_cmd", None),
    ("waste", "cyntrisec.cli.waste:waste_cmd", None),
    ("can", "cyntrisec.cli.can:can_cmd", None),
    ("diff", "cyntrisec.cli.diff:diff_cmd", None),
    ("comply", "cyntrisec.cli.comply:comply_cmd", None),
    ("manifest", "cyntrisec.cli.manifest:manifest_cmd", None),
    ("explain", "cyntrisec.cli.explain:explain_cmd", None),
    ("serve", "cyntrisec.cli.serve:serve_cmd", None),
    ("remediate", "cyntrisec.cli.remediate:remediate_cmd", None),
    ("ask", "cyntrisec.cli.ask:ask_cmd", None),
]

_TYPER_HELP = {
    "analyze": "Analyze scan results",
    "setup": "Setup commands",
}

for _name, _import_path, _method in _COMMANDS:
    try:
        _module_path, _attr = _import_path.rsplit(":", 1)
        import importlib as _importlib

        _mod = _importlib.import_module(_module_path)
        _obj = getattr(_mod, _attr)
        if _method == "add_typer":
            app.add_typer(_obj, name=_name, help=_TYPER_HELP.get(_name, ""))
        else:
            app.command(_name)(_obj)
    except (ImportError, AttributeError) as _err:
        _log.warning("Failed to register command '%s': %s", _name, _err)


if __name__ == "__main__":
    app()
