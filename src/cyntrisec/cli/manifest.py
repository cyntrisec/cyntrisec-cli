"""
manifest command - Self-describing tool capabilities for AI agents.

This command enables AI agents to discover, understand, and invoke
Cyntrisec commands programmatically without parsing help text.

Usage:
    cyntrisec manifest
    cyntrisec manifest --command scan
"""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from typer.models import OptionInfo

from cyntrisec import __version__
from cyntrisec.cli.output import emit_agent_or_json, resolve_format
from cyntrisec.cli.output import SCHEMA_VERSION
from cyntrisec.cli.errors import handle_errors, CyntriError, ErrorCode, EXIT_CODE_MAP
from cyntrisec.cli.schemas import ManifestResponse, schema_json

console = Console()


# Command capability definitions
CAPABILITIES = [
    {
        "name": "scan",
        "description": "Scan an AWS account for security issues and attack paths",
        "parameters": [
            {"name": "role_arn", "type": "string", "required": True,
             "description": "AWS IAM role ARN to assume for scanning"},
            {"name": "external_id", "type": "string", "required": False,
             "description": "External ID for role assumption"},
            {"name": "regions", "type": "array", "required": False, "default": ["us-east-1"],
             "description": "AWS regions to scan"},
        ],
        "output": {
            "type": "object",
            "properties": {
                "snapshot_id": {"type": "string"},
                "assets": {"type": "integer"},
                "relationships": {"type": "integer"},
                "findings": {"type": "integer"},
                "attack_paths": {"type": "integer"},
            }
        },
        "exit_codes": {"0": "success", "1": "scan completed with findings", "2": "error"},
        "example": "cyntrisec scan --role-arn arn:aws:iam::123:role/Scanner",
    },
    {
        "name": "cuts",
        "description": "Find minimal set of remediations that block all attack paths",
        "parameters": [
            {"name": "max_cuts", "type": "integer", "required": False, "default": 5,
             "description": "Maximum number of remediations to return"},
            {"name": "format", "type": "string", "required": False, "default": "table",
             "enum": ["table", "json"], "description": "Output format"},
        ],
        "output": {
            "type": "object",
            "properties": {
                "total_paths": {"type": "integer"},
                "paths_blocked": {"type": "integer"},
                "coverage": {"type": "number"},
                "remediations": {"type": "array"},
            }
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec cuts --format json",
        "suggested_after": ["scan"],
    },
    {
        "name": "waste",
        "description": "Analyze IAM roles for unused permissions (blast radius reduction)",
        "parameters": [
            {"name": "days", "type": "integer", "required": False, "default": 90,
             "description": "Days threshold for considering a permission unused"},
            {"name": "live", "type": "boolean", "required": False, "default": False,
             "description": "Fetch live usage data from AWS IAM Access Advisor"},
            {"name": "format", "type": "string", "required": False, "default": "table",
             "enum": ["table", "json"], "description": "Output format"},
        ],
        "output": {
            "type": "object",
            "properties": {
                "total_permissions": {"type": "integer"},
                "total_unused": {"type": "integer"},
                "blast_radius_reduction": {"type": "number"},
                "roles": {"type": "array"},
            }
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec waste --live --format json",
        "suggested_after": ["scan"],
    },
    {
        "name": "can",
        "description": "Test if a principal can access a resource (IAM policy simulation)",
        "parameters": [
            {"name": "principal", "type": "string", "required": True,
             "description": "IAM principal (role/user name or ARN)"},
            {"name": "access", "type": "string", "required": True, "const": "access",
             "description": "Literal 'access' keyword"},
            {"name": "resource", "type": "string", "required": True,
             "description": "Target resource (ARN, bucket name, or s3://path)"},
            {"name": "action", "type": "string", "required": False,
             "description": "Specific action to test (auto-detected if not provided)"},
            {"name": "live", "type": "boolean", "required": False, "default": False,
             "description": "Use AWS Policy Simulator API"},
        ],
        "output": {
            "type": "object",
            "properties": {
                "principal": {"type": "string"},
                "resource": {"type": "string"},
                "can_access": {"type": "boolean"},
                "simulations": {"type": "array"},
            }
        },
        "exit_codes": {"0": "access allowed", "1": "access denied", "2": "error"},
        "example": "cyntrisec can ECforS access s3://prod-bucket --format json",
        "suggested_after": ["scan", "cuts"],
    },
    {
        "name": "diff",
        "description": "Compare two scan snapshots to detect changes and regressions",
        "parameters": [
            {"name": "old", "type": "string", "required": False,
             "description": "Old snapshot ID (default: second most recent)"},
            {"name": "new", "type": "string", "required": False,
             "description": "New snapshot ID (default: most recent)"},
            {"name": "format", "type": "string", "required": False, "default": "table",
             "enum": ["table", "json"], "description": "Output format"},
        ],
        "output": {
            "type": "object",
            "properties": {
                "has_regressions": {"type": "boolean"},
                "has_improvements": {"type": "boolean"},
                "summary": {"type": "object"},
                "path_changes": {"type": "array"},
            }
        },
        "exit_codes": {"0": "no regressions", "1": "regressions detected", "2": "error"},
        "example": "cyntrisec diff --format json",
        "suggested_after": ["scan"],
    },
    {
        "name": "comply",
        "description": "Check compliance against CIS AWS Foundations or SOC 2",
        "parameters": [
            {"name": "framework", "type": "string", "required": False, "default": "cis-aws",
             "enum": ["cis-aws", "soc2"], "description": "Compliance framework"},
            {"name": "format", "type": "string", "required": False, "default": "table",
             "enum": ["table", "json"], "description": "Output format"},
        ],
        "output": {
            "type": "object",
            "properties": {
                "framework": {"type": "string"},
                "compliance_score": {"type": "number"},
                "passing": {"type": "integer"},
                "failing": {"type": "integer"},
                "controls": {"type": "array"},
            }
        },
        "exit_codes": {"0": "fully compliant", "1": "compliance failures", "2": "error"},
        "example": "cyntrisec comply --framework soc2 --format json",
        "suggested_after": ["scan"],
    },
    {
        "name": "analyze paths",
        "description": "View discovered attack paths from the latest scan",
        "parameters": [
            {"name": "format", "type": "string", "required": False, "default": "table",
             "enum": ["table", "json"], "description": "Output format"},
        ],
        "output": {
            "type": "object",
            "properties": {
                "paths": {"type": "array"},
                "total": {"type": "integer"},
            }
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec analyze paths --format json",
        "suggested_after": ["scan"],
    },
    {
        "name": "analyze business",
        "description": "Map business entrypoints vs attackable assets (waste = attackable - business)",
        "parameters": [
            {"name": "entrypoints", "type": "array", "required": False,
             "description": "Business entrypoint names/ARNs (comma-separated)"},
            {"name": "business_entrypoint", "type": "array", "required": False,
             "description": "Repeatable business entrypoint flags (--business-entrypoint)"},
            {"name": "business_tags", "type": "object", "required": False,
             "description": "Tag filters marking business assets"},
            {"name": "business_config", "type": "string", "required": False,
             "description": "Path to business config (JSON/YAML)"},
            {"name": "report", "type": "boolean", "required": False, "default": False,
             "description": "Emit full coverage report"},
            {"name": "format", "type": "string", "required": False, "default": "table",
             "enum": ["table", "json", "agent"], "description": "Output format"},
        ],
        "output": {
            "type": "object",
            "properties": {
                "entrypoints_found": {"type": "array"},
                "attackable_count": {"type": "integer"},
                "waste_candidate_count": {"type": "integer"},
            }
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec analyze business --entrypoints web,api --format agent",
        "suggested_after": ["scan"],
    },
    {
        "name": "remediate",
        "description": "Generate remediation plan or optionally execute Terraform (gated)",
        "parameters": [
            {"name": "max_cuts", "type": "integer", "required": False, "default": 5,
             "description": "Maximum remediations to include"},
            {"name": "apply", "type": "boolean", "required": False, "default": False,
             "description": "Write remediation plan to disk (safety stub)"},
            {"name": "dry_run", "type": "boolean", "required": False, "default": False,
             "description": "Simulate apply and write plan/IaC artifacts"},
            {"name": "execute_terraform", "type": "boolean", "required": False, "default": False,
             "description": "UNSAFE: execute terraform apply locally. Requires --enable-unsafe-write-mode."},
            {"name": "terraform_plan", "type": "boolean", "required": False, "default": False,
             "description": "Run terraform init/plan against generated module"},
            {"name": "terraform_output", "type": "string", "required": False,
             "description": "Terraform hints output path"},
            {"name": "enable_unsafe_write_mode", "type": "boolean", "required": False,
             "description": "Required to allow --apply/--execute-terraform (defaults to off for safety)"},
            {"name": "terraform_dir", "type": "string", "required": False,
             "description": "Directory to write Terraform module"},
            {"name": "output", "type": "string", "required": False,
             "description": "Output path for remediation plan"},
            {"name": "format", "type": "string", "required": False, "default": "table",
             "enum": ["table", "json", "agent"], "description": "Output format"},
        ],
        "output": {
            "type": "object",
            "properties": {
                "plan": {"type": "array"},
                "coverage": {"type": "number"},
                "paths_blocked": {"type": "integer"},
            }
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec remediate --format agent",
        "suggested_after": ["cuts", "analyze paths"],
    },
    {
        "name": "ask",
        "description": "Natural language interface to query scan results",
        "parameters": [
            {"name": "query", "type": "string", "required": True, "description": "NL question"},
            {"name": "format", "type": "string", "required": False, "default": "text",
             "enum": ["text", "json", "agent"], "description": "Output format"},
        ],
        "output": {
            "type": "object",
            "properties": {
                "intent": {"type": "string"},
                "results": {"type": "object"},
            }
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec ask \"what can reach the production database?\" --format agent",
        "suggested_after": ["scan", "analyze paths"],
    },
]


@handle_errors
def manifest_cmd(
    command: Optional[str] = typer.Option(
        None,
        "--command", "-c",
        help="Get manifest for a specific command",
    ),
    format: Optional[str] = typer.Option(
        None,
        "--format", "-f",
        help="Output format: json, agent (defaults to json when piped)",
    ),
):
    """
    Output machine-readable manifest of tool capabilities.
    
    Use this command to discover what Cyntrisec can do and how to invoke it.
    This is designed for AI agents to understand the tool programmatically.
    """
    if isinstance(command, OptionInfo):
        command = None
    if isinstance(format, OptionInfo):
        format = None
    output_format = resolve_format(
        format,
        default_tty="json",
        allowed=["json", "agent"],
    )

    schemas = schema_json()

    if command:
        # Find specific command
        for cap in CAPABILITIES:
            if cap["name"] == command:
                emit_agent_or_json(output_format, cap)
                return
        raise CyntriError(
            error_code=ErrorCode.INVALID_QUERY,
            message=f"Command '{command}' not found",
            exit_code=EXIT_CODE_MAP["usage"],
        )
    
    # Full manifest
    manifest = {
        "name": "cyntrisec",
        "version": __version__,
        "description": "AWS capability graph analysis and attack path discovery",
        "agentic_features": {
            "json_output": True,
            "structured_errors": True,
            "exit_codes": True,
            "suggested_actions": True,
            "artifact_paths": True,
        },
        "schemas": {
            "version": SCHEMA_VERSION,
            "base_url": "https://cyntrisec.dev/schemas/cli",
            "responses": schemas,
        },
        "capabilities": CAPABILITIES,
        "usage_pattern": [
            "1. Run 'cyntrisec scan' to collect AWS data",
            "2. Run 'cyntrisec analyze paths' to see attack paths",
            "3. Run 'cyntrisec cuts' to get prioritized fixes",
            "4. Run 'cyntrisec can X access Y' to verify specific access",
        ],
        "error_codes": [
            ErrorCode.AWS_ACCESS_DENIED,
            ErrorCode.AWS_THROTTLED,
            ErrorCode.AWS_REGION_DISABLED,
            ErrorCode.SNAPSHOT_NOT_FOUND,
            ErrorCode.SCHEMA_MISMATCH,
            ErrorCode.INVALID_QUERY,
            ErrorCode.INTERNAL_ERROR,
        ],
    }
    
    emit_agent_or_json(output_format, manifest, schema=ManifestResponse)
