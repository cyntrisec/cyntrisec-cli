"""
remediate command - Generate remediation plans (plan/apply).

Current implementation generates a remediation plan using existing scan data
and minimal cut analysis. Apply is a stub that requires explicit enablement.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typer.models import OptionInfo

from cyntrisec.cli.errors import EXIT_CODE_MAP, CyntriError, ErrorCode, handle_errors
from cyntrisec.cli.output import (
    build_artifact_paths,
    emit_agent_or_json,
    resolve_format,
    suggested_actions,
)
from cyntrisec.cli.schemas import RemediateResponse
from cyntrisec.core.cuts import MinCutFinder
from cyntrisec.core.graph import GraphBuilder
from cyntrisec.storage import FileSystemStorage

console = Console()


@handle_errors
def remediate_cmd(
    max_cuts: int = typer.Option(
        5,
        "--max-cuts",
        help="Maximum remediations to include in the plan",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Simulate apply (mark actions as pending) and write plan to disk",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Apply the remediation plan (writes plan + marks actions pending)",
    ),
    terraform_output: str | None = typer.Option(
        None,
        "--terraform-output",
        help="Path to write Terraform hints (default: cyntrisec-remediation.tf when applying)",
    ),
    terraform_dir: str | None = typer.Option(
        None,
        "--terraform-dir",
        help="Directory to write Terraform module (default: cyntrisec-remediation-tf)",
    ),
    execute_terraform: bool = typer.Option(
        False,
        "--execute-terraform",
        help="UNSAFE: execute terraform apply locally. Requires --enable-unsafe-write-mode.",
    ),
    terraform_plan: bool = typer.Option(
        False,
        "--terraform-plan",
        help="Run terraform init + plan only against the generated module",
    ),
    terraform_cmd: str = typer.Option(
        "terraform",
        "--terraform-cmd",
        help="Terraform binary to invoke when using --execute-terraform",
    ),
    enable_unsafe_write_mode: bool = typer.Option(
        False,
        "--enable-unsafe-write-mode",
        help="Required to allow --apply/--execute-terraform (defaults to off for safety)",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Skip confirmation when using --apply",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write plan/apply payload to a file (json)",
    ),
    snapshot_id: str | None = typer.Option(
        None,
        "--snapshot",
        help="Snapshot UUID (default: latest; scan_id accepted)",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: table, json, agent (defaults to json when piped)",
    ),
):
    """
    Generate or apply remediation plans.

    Use existing scan data and minimal-cut analysis to propose fixes that
    block attack paths. Apply/terraform are gated and disabled by default.
    """
    output_format = resolve_format(
        format,
        default_tty="table",
        allowed=["table", "json", "agent"],
    )

    if isinstance(output, OptionInfo):
        output = None
    if isinstance(terraform_output, OptionInfo):
        terraform_output = None
    if isinstance(terraform_dir, OptionInfo):
        terraform_dir = None

    storage = FileSystemStorage()
    assets = storage.get_assets(snapshot_id)
    relationships = storage.get_relationships(snapshot_id)
    paths = storage.get_attack_paths(snapshot_id)
    snapshot = storage.get_snapshot(snapshot_id)

    if not assets or not snapshot:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="No scan data found. Run 'cyntrisec scan' first.",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    if not paths:
        status_console = console if output_format == "table" else Console(stderr=True)
        status_console.print("[green]No attack paths found. Nothing to remediate.[/green]")
        raise typer.Exit(0)

    graph = GraphBuilder().build(assets=assets, relationships=relationships)
    result = MinCutFinder().find_cuts(graph, paths, max_cuts=max_cuts)
    plan = _build_plan(result, graph)

    apply_output = None
    mode = "plan"

    if apply or dry_run or execute_terraform or terraform_plan:
        mode, apply_output = _handle_apply_mode(
            plan=plan,
            snapshot=snapshot,
            apply=apply,
            dry_run=dry_run,
            execute_terraform=execute_terraform,
            terraform_plan=terraform_plan,
            enable_unsafe_write_mode=enable_unsafe_write_mode,
            yes=yes,
            output=output,
            terraform_output=terraform_output,
            terraform_dir=terraform_dir,
            terraform_cmd=terraform_cmd,
        )

    if output_format in {"json", "agent"}:
        # Determine status and applied based on mode
        if dry_run:
            status = "dry_run"
            applied = False
        elif apply_output:
            results = apply_output.get("results") or []
            failed = any(
                item.get("status") in {"terraform_failed", "terraform_plan_failed"} for item in results
            )
            applied = any(item.get("status") == "terraform_invoked" for item in results)
            if failed:
                status = "terraform_failed"
                applied = False
            elif mode == "terraform-plan":
                status = "terraform_plan_ok"
                applied = False
            elif applied:
                status = "applied"
            else:
                status = "planned"
        else:
            status = "planned"
            applied = False

        payload = {
            "snapshot_id": str(snapshot.id) if snapshot else None,
            "account_id": snapshot.aws_account_id if snapshot else None,
            "total_paths": result.total_paths,
            "paths_blocked": result.paths_blocked,
            "coverage": result.coverage,
            "plan": plan,
            "applied": applied,
            "mode": mode,
            "output_path": apply_output["output_path"] if apply_output else None,
            "terraform_path": apply_output["terraform_path"] if apply_output else None,
            "terraform_dir": apply_output["terraform_dir"] if apply_output else None,
            "apply": apply_output,
        }
        actions = suggested_actions(
            [
                (
                    "cyntrisec can <principal> access <resource>",
                    "Verify access is closed after remediation",
                ),
                ("cyntrisec diff --format agent", "Detect regressions after applying fixes"),
            ]
        )
        emit_agent_or_json(
            output_format,
            payload,
            suggested=actions,
            status=status,
            artifact_paths=build_artifact_paths(storage, snapshot_id),
            schema=RemediateResponse,
        )
        raise typer.Exit(0)

    _output_table(
        plan,
        result,
        snapshot,
        applied=bool(apply_output),
        output_path=apply_output["output_path"] if apply_output else None,
        terraform_path=apply_output["terraform_path"] if apply_output else terraform_output,
        mode=mode,
    )
    raise typer.Exit(0)


def _build_plan(result, graph):
    """Construct a remediation plan with human + IaC hints."""
    plan = []
    for i, rem in enumerate(result.remediations, 1):
        source_asset = graph.asset(rem.relationship.source_asset_id) if graph else None
        target_asset = graph.asset(rem.relationship.target_asset_id) if graph else None
        terraform = _terraform_snippet(
            rem.action,
            rem.source_name,
            rem.target_name,
            rem.relationship_type,
            source_arn=source_asset.arn if source_asset else None,
            target_arn=target_asset.arn if target_asset else None,
        )
        plan.append(
            {
                "priority": i,
                "action": rem.action,
                "description": rem.description,
                "source": rem.source_name,
                "target": rem.target_name,
                "relationship_type": rem.relationship_type,
                "paths_blocked": len(rem.paths_blocked),
                "terraform": terraform,
            }
        )
    return plan


def _terraform_snippet(
    action: str,
    source: str,
    target: str,
    relationship_type: str,
    *,
    source_arn: str | None = None,
    target_arn: str | None = None,
) -> str:
    """Generate a minimal Terraform hint for the remediation."""
    if relationship_type == "ALLOWS_TRAFFIC_TO":
        return (
            "# Restrict security group ingress\n"
            'resource "aws_security_group_rule" "restrict_ingress" {\n'
            f'  description = "Restrict {source} -> {target}"\n'
            '  type        = "ingress"\n'
            "  from_port   = 0\n"
            "  to_port     = 0\n"
            '  protocol    = "tcp"\n'
            '  cidr_blocks = ["10.0.0.0/8"]\n'
            "}\n"
        )
    if relationship_type == "MAY_ACCESS":
        resources_line = (
            f'    resources = ["{target_arn}"]\n' if target_arn else "    resources = []\n"
        )
        return (
            "# Tighten IAM policy\n"
            f"# TODO: replace resources for {target} if empty\n"
            'data "aws_iam_policy_document" "restricted" {\n'
            "  statement {\n"
            f'    sid    = "Limit{source}Access"\n'
            '    effect = "Allow"\n'
            '    actions   = ["*"]\n'
            f"{resources_line}"
            "  }\n"
            "}\n"
        )
    if relationship_type == "CAN_ASSUME":
        identifiers_line = (
            f'      identifiers = ["{source_arn}"]\n'
            if source_arn
            else "      identifiers = []\n"
        )
        return (
            "# Restrict role trust policy\n"
            f"# TODO: replace trusted principal for {source} if empty\n"
            'data "aws_iam_policy_document" "assume_role" {\n'
            "  statement {\n"
            '    effect = "Allow"\n'
            "    principals {\n"
            '      type = "AWS"\n'
            f"{identifiers_line}"
            "    }\n"
            '    actions = ["sts:AssumeRole"]\n'
            "  }\n"
            "}\n"
        )
    return "# Review and update access between resources."


def _output_table(
    plan,
    result,
    snapshot,
    *,
    applied: bool,
    output_path: str | None,
    terraform_path: str | None,
    mode: str,
):
    """Render a remediation plan as a table."""
    console.print()
    console.print(
        Panel(
            f"[bold]Remediation Plan[/bold]\n"
            f"Account: {snapshot.aws_account_id if snapshot else 'unknown'}\n"
            f"Attack Paths: {result.total_paths} -> {result.paths_blocked} blocked "
            f"({result.coverage:.0%} coverage)",
            title="cyntrisec remediate",
            border_style="cyan",
        )
    )
    console.print()

    if not plan:
        console.print("[yellow]No remediations identified.[/yellow]")
        return

    table = Table(
        title=f"Top {len(plan)} Remediations",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#", width=3, style="dim")
    table.add_column("Action", width=15)
    table.add_column("Description", min_width=40)
    table.add_column("Blocks", justify="right", width=8)

    for item in plan:
        table.add_row(
            str(item["priority"]),
            item["action"],
            item["description"],
            f"{item['paths_blocked']} paths",
        )

    console.print(table)
    console.print("[dim]Use --format json|agent for IaC snippets and automation.[/dim]")
    if applied:
        console.print(
            f"[green]{mode.title()} written to {output_path or 'cyntrisec-remediation-plan.json'}[/green]"
        )
        console.print(
            f"[green]Terraform hints written to {terraform_path or 'cyntrisec-remediation.tf'}[/green]"
        )


def _handle_apply_mode(
    plan: list[dict],
    snapshot,
    apply: bool,
    dry_run: bool,
    execute_terraform: bool,
    terraform_plan: bool,
    enable_unsafe_write_mode: bool,
    yes: bool,
    output: str | None,
    terraform_output: str | None,
    terraform_dir: str | None,
    terraform_cmd: str,
):
    """Handle apply, dry-run, and terraform execution logic."""
    if (apply or execute_terraform or terraform_plan) and not enable_unsafe_write_mode:
        raise CyntriError(
            error_code=ErrorCode.INVALID_QUERY,
            message="Apply/terraform execution is disabled. Use --enable-unsafe-write-mode to proceed.",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    mode = "apply" if apply else ("terraform-plan" if terraform_plan else "dry_run")

    # Skip confirmation for dry-run and terraform-plan since they are read-only.
    if not dry_run and not terraform_plan and not yes:
        confirm = typer.confirm(
            "This will write the remediation plan to disk and mark actions as pending. Proceed?",
            default=False,
            err=True,
        )
        if not confirm:
            raise typer.Exit(1)

    if execute_terraform and not yes:
        confirm_tf = typer.confirm(
            "You requested to run terraform locally. Continue?",
            default=False,
            err=True,
        )
        if not confirm_tf:
            raise typer.Exit(1)

    plan_path = output or "cyntrisec-remediation-plan.json"
    tf_module_dir = terraform_dir or "cyntrisec-remediation-tf"
    tf_path = terraform_output or str(Path(tf_module_dir) / "main.tf")

    apply_results, plan_result = _apply_plan(
        plan,
        snapshot,
        plan_path,
        tf_module_dir,
        tf_path,
        dry_run=not apply,
        execute_terraform=execute_terraform and apply,
        terraform_plan=terraform_plan,
        terraform_cmd=terraform_cmd,
    )

    apply_output = {
        "mode": mode,
        "output_path": plan_path,
        "terraform_path": tf_path,
        "terraform_dir": tf_module_dir,
        "results": apply_results,
        "plan_exit_code": plan_result.get("exit_code") if plan_result else None,
        "plan_summary": plan_result.get("summary") if plan_result else None,
    }

    return mode, apply_output


def _write_plan_file(plan: list[dict], path: str, snapshot):
    """Write remediation plan to a JSON file."""
    import json

    payload = {
        "snapshot_id": str(getattr(snapshot, "id", None)) if snapshot else None,
        "account_id": getattr(snapshot, "aws_account_id", None) if snapshot else None,
        "plan": plan,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _apply_plan(
    plan: list[dict],
    snapshot,
    plan_path: str,
    tf_dir: str,
    tf_main_path: str,
    *,
    dry_run: bool,
    execute_terraform: bool,
    terraform_plan: bool,
    terraform_cmd: str,
) -> tuple[list[dict], dict | None]:
    """
    Apply or simulate apply of the remediation plan.

    Writes plan and Terraform hints to disk. Optionally runs terraform plan/apply.
    Returns (items, plan_result).
    """
    _write_plan_file(plan, plan_path, snapshot)
    tf_main = _write_terraform_files(plan, tf_dir, tf_main_path)
    status = "pending_dry_run" if dry_run else "pending_apply_via_terraform"
    tf_result = None
    plan_result = None

    if terraform_plan:
        plan_result = _run_terraform_plan(terraform_cmd, tf_dir)
        status = "terraform_plan_ok" if plan_result.get("ok") else "terraform_plan_failed"
    elif execute_terraform and not dry_run:
        tf_result = _run_terraform(terraform_cmd, tf_dir)
        status = "terraform_invoked" if tf_result.get("ok") else "terraform_failed"

    items = [
        {
            "priority": item["priority"],
            "action": item["action"],
            "description": item["description"],
            "status": status,
            "paths_blocked": item["paths_blocked"],
            "terraform_path": tf_main,
            "terraform_result": tf_result or plan_result,
        }
        for item in plan
    ]
    return items, plan_result


def _write_terraform_files(plan: list[dict], dir_path: str, main_path: str) -> str:
    """Write aggregated Terraform hints as a simple module."""
    dirp = Path(dir_path)
    dirp.mkdir(parents=True, exist_ok=True)
    main_file = Path(main_path) if main_path else dirp / "main.tf"
    body = "\n\n".join(item.get("terraform") or "# no terraform snippet" for item in plan)
    header = "# Cyntrisec remediation hints - review and adapt before apply\n"
    main_file.write_text(header + body, encoding="utf-8")

    readme = dirp / "README.md"
    if not readme.exists():
        readme.write_text(
            "# Cyntrisec remediation\n\n"
            "This module is generated as a starting point. Review and customize before applying.\n",
            encoding="utf-8",
        )
    return str(main_file)


def _run_terraform(terraform_cmd: str, tf_dir: str) -> dict:
    """
    Run terraform apply -auto-approve against the generated hints.

    Returns a dict with command and status. If terraform is missing, returns error.
    """
    if not shutil.which(terraform_cmd):
        return {"ok": False, "error": f"terraform command '{terraform_cmd}' not found"}

    init_cmd = [terraform_cmd, f"-chdir={tf_dir}", "init", "-input=false"]
    apply_cmd = [terraform_cmd, f"-chdir={tf_dir}", "apply", "-auto-approve"]
    try:
        init_result = subprocess.run(init_cmd, check=True, capture_output=True)
        apply_result = subprocess.run(apply_cmd, check=True, capture_output=True)
        return {
            "ok": True,
            "command": " ".join(apply_cmd),
            "stdout": apply_result.stdout.decode(),
            "stderr": apply_result.stderr.decode(),
            "exit_code": apply_result.returncode,
            "init_stdout": init_result.stdout.decode(),
        }
    except subprocess.CalledProcessError as e:
        return {
            "ok": False,
            "error": str(e),
            "command": " ".join(apply_cmd),
            "exit_code": e.returncode,
            "stdout": getattr(e, "stdout", b"").decode() if hasattr(e, "stdout") else "",
            "stderr": getattr(e, "stderr", b"").decode() if hasattr(e, "stderr") else "",
        }


def _run_terraform_plan(terraform_cmd: str, tf_dir: str) -> dict:
    """
    Run terraform plan (no apply) to validate generated module.
    """
    if not shutil.which(terraform_cmd):
        return {
            "ok": False,
            "error": f"terraform command '{terraform_cmd}' not found",
            "exit_code": None,
        }

    init_cmd = [terraform_cmd, f"-chdir={tf_dir}", "init", "-input=false"]
    plan_cmd = [terraform_cmd, f"-chdir={tf_dir}", "plan", "-input=false", "-no-color"]
    try:
        init_result = subprocess.run(init_cmd, check=True, capture_output=True)
        plan_result = subprocess.run(plan_cmd, check=True, capture_output=True)
        stdout_text = plan_result.stdout.decode()
        summary = None
        for line in reversed(stdout_text.splitlines()):
            if "Plan:" in line:
                summary = line.strip()
                break
        return {
            "ok": True,
            "exit_code": plan_result.returncode,
            "stdout": stdout_text,
            "stderr": plan_result.stderr.decode(),
            "summary": summary,
            "init_stdout": init_result.stdout.decode(),
        }
    except subprocess.CalledProcessError as e:
        return {
            "ok": False,
            "exit_code": e.returncode,
            "error": str(e),
            "stdout": getattr(e, "stdout", b"").decode() if hasattr(e, "stdout") else "",
            "stderr": getattr(e, "stderr", b"").decode() if hasattr(e, "stderr") else "",
        }
