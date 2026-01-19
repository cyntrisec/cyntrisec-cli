"""
manifest command - Self-describing tool capabilities for AI agents.

This command enables AI agents to discover, understand, and invoke
Cyntrisec commands programmatically without parsing help text.

Usage:
    cyntrisec manifest
    cyntrisec manifest --command scan
"""

from __future__ import annotations

import typer
from rich.console import Console
from typer.models import OptionInfo

from cyntrisec import __version__
from cyntrisec.cli.errors import EXIT_CODE_MAP, CyntriError, ErrorCode, handle_errors
from cyntrisec.cli.output import SCHEMA_VERSION, emit_agent_or_json, resolve_format
from cyntrisec.cli.schemas import ManifestResponse, schema_json

console = Console()


# Command capability definitions
CAPABILITIES = [
    {
        "name": "scan",
        "description": "Scan an AWS account for security issues and attack paths",
        "parameters": [
            {
                "name": "role_arn",
                "type": "string",
                "required": False,
                "description": "AWS IAM role ARN to assume for scanning (uses default credentials if not provided)",
            },
            {
                "name": "external_id",
                "type": "string",
                "required": False,
                "description": "External ID for role assumption",
            },
            {
                "name": "regions",
                "type": "array",
                "required": False,
                "default": ["us-east-1"],
                "description": "AWS regions to scan",
            },
            {
                "name": "profile",
                "type": "string",
                "required": False,
                "description": "AWS CLI profile for base credentials",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "text",
                "enum": ["text", "json", "agent"],
                "description": "Output format",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string"},
                "snapshot_id": {"type": "string"},
                "account_id": {"type": "string"},
                "regions": {"type": "array"},
                "asset_count": {"type": "integer"},
                "relationship_count": {"type": "integer"},
                "finding_count": {"type": "integer"},
                "attack_path_count": {"type": "integer"},
                "warnings": {"type": "array"},
            },
        },
        "exit_codes": {"0": "success", "1": "scan completed with findings", "2": "error"},
        "example": "cyntrisec scan --role-arn arn:aws:iam::123:role/Scanner",
    },
    {
        "name": "cuts",
        "description": "Find minimal set of remediations that block all attack paths",
        "parameters": [
            {
                "name": "max_cuts",
                "type": "integer",
                "required": False,
                "default": 5,
                "description": "Maximum number of remediations to return",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "table",
                "enum": ["table", "json", "agent"],
                "description": "Output format",
            },
            {
                "name": "snapshot",
                "type": "string",
                "required": False,
                "description": "Specific snapshot ID (default: latest)",
            },
            {
                "name": "cost_source",
                "type": "string",
                "required": False,
                "default": "estimate",
                "description": "Cost data source: estimate (static), pricing-api, cost-explorer",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "total_paths": {"type": "integer"},
                "paths_blocked": {"type": "integer"},
                "coverage": {"type": "number"},
                "remediations": {"type": "array"},
            },
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec cuts --format json",
        "suggested_after": ["scan"],
    },
    {
        "name": "waste",
        "description": "Analyze IAM roles for unused permissions (blast radius reduction)",
        "parameters": [
            {
                "name": "days",
                "type": "integer",
                "required": False,
                "default": 90,
                "description": "Days threshold for considering a permission unused",
            },
            {
                "name": "live",
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "Fetch live usage data from AWS IAM Access Advisor",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "table",
                "enum": ["table", "json", "agent"],
                "description": "Output format",
            },
            {
                "name": "snapshot",
                "type": "string",
                "required": False,
                "description": "Specific snapshot ID (default: latest)",
            },
            {
                "name": "cost_source",
                "type": "string",
                "required": False,
                "default": "estimate",
                "description": "Cost data source: estimate (static), pricing-api, cost-explorer",
            },
            {
                "name": "max_roles",
                "type": "integer",
                "required": False,
                "default": 20,
                "description": "Maximum number of roles to analyze (API throttling)",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "total_permissions": {"type": "integer"},
                "total_unused": {"type": "integer"},
                "blast_radius_reduction": {"type": "number"},
                "roles": {"type": "array"},
            },
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec waste --live --format json",
        "suggested_after": ["scan"],
    },
    {
        "name": "can",
        "description": "Test if a principal can access a resource (IAM policy simulation)",
        "parameters": [
            {
                "name": "principal",
                "type": "string",
                "required": True,
                "description": "IAM principal (role/user name or ARN)",
            },
            {
                "name": "access",
                "type": "string",
                "required": True,
                "const": "access",
                "description": "Literal 'access' keyword",
            },
            {
                "name": "resource",
                "type": "string",
                "required": True,
                "description": "Target resource (ARN, bucket name, or s3://path)",
            },
            {
                "name": "action",
                "type": "string",
                "required": False,
                "description": "Specific action to test (auto-detected if not provided)",
            },
            {
                "name": "live",
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "Use AWS Policy Simulator API",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "text",
                "enum": ["text", "json", "agent"],
                "description": "Output format",
            },
            {
                "name": "snapshot",
                "type": "string",
                "required": False,
                "description": "Specific snapshot ID (default: latest)",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "principal": {"type": "string"},
                "resource": {"type": "string"},
                "can_access": {"type": "boolean"},
                "simulations": {"type": "array"},
            },
        },
        "exit_codes": {"0": "access allowed", "1": "access denied", "2": "error"},
        "example": "cyntrisec can ECforS access s3://prod-bucket --format json",
        "suggested_after": ["scan", "cuts"],
    },
    {
        "name": "diff",
        "description": "Compare two scan snapshots to detect changes and regressions",
        "parameters": [
            {
                "name": "old",
                "type": "string",
                "required": False,
                "description": "Old snapshot ID (default: second most recent)",
            },
            {
                "name": "new",
                "type": "string",
                "required": False,
                "description": "New snapshot ID (default: most recent)",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "table",
                "enum": ["table", "json", "agent"],
                "description": "Output format",
            },
            {
                "name": "all",
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "Show all changes including assets and relationships",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "has_regressions": {"type": "boolean"},
                "has_improvements": {"type": "boolean"},
                "summary": {"type": "object"},
                "path_changes": {"type": "array"},
            },
        },
        "exit_codes": {"0": "no regressions", "1": "regressions detected", "2": "error"},
        "example": "cyntrisec diff --format json",
        "suggested_after": ["scan"],
    },
    {
        "name": "comply",
        "description": "Check compliance against CIS AWS Foundations or SOC 2",
        "parameters": [
            {
                "name": "framework",
                "type": "string",
                "required": False,
                "default": "cis-aws",
                "enum": ["cis-aws", "soc2"],
                "description": "Compliance framework",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "table",
                "enum": ["table", "json", "agent"],
                "description": "Output format",
            },
            {
                "name": "snapshot",
                "type": "string",
                "required": False,
                "description": "Specific snapshot ID (default: latest)",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "framework": {"type": "string"},
                "compliance_score": {"type": "number"},
                "passing": {"type": "integer"},
                "failing": {"type": "integer"},
                "controls": {"type": "array"},
            },
        },
        "exit_codes": {"0": "fully compliant", "1": "compliance failures", "2": "error"},
        "example": "cyntrisec comply --framework soc2 --format json",
        "suggested_after": ["scan"],
    },
    {
        "name": "analyze paths",
        "description": "View discovered attack paths from the latest scan",
        "parameters": [
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "table",
                "enum": ["table", "json", "agent"],
                "description": "Output format",
            },
            {
                "name": "scan",
                "type": "string",
                "required": False,
                "description": "Scan ID (default: latest)",
            },
            {
                "name": "min_risk",
                "type": "number",
                "required": False,
                "default": 0.0,
                "description": "Minimum risk score (0-1)",
            },
            {
                "name": "limit",
                "type": "integer",
                "required": False,
                "default": 20,
                "description": "Maximum number of paths to show",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "paths": {"type": "array"},
                "total": {"type": "integer"},
            },
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec analyze paths --format json",
        "suggested_after": ["scan"],
    },
    {
        "name": "analyze business",
        "description": "Map business entrypoints vs attackable assets (waste = attackable - business)",
        "parameters": [
            {
                "name": "entrypoints",
                "type": "array",
                "required": False,
                "description": "Business entrypoint names/ARNs (comma-separated)",
            },
            {
                "name": "business_entrypoint",
                "type": "array",
                "required": False,
                "description": "Repeatable business entrypoint flags (--business-entrypoint)",
            },
            {
                "name": "business_tags",
                "type": "object",
                "required": False,
                "description": "Tag filters marking business assets",
            },
            {
                "name": "business_config",
                "type": "string",
                "required": False,
                "description": "Path to business config (JSON/YAML)",
            },
            {
                "name": "report",
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "Emit full coverage report",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "table",
                "enum": ["table", "json", "agent"],
                "description": "Output format",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "entrypoints_found": {"type": "array"},
                "attackable_count": {"type": "integer"},
                "waste_candidate_count": {"type": "integer"},
            },
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec analyze business --entrypoints web,api --format agent",
        "suggested_after": ["scan"],
    },
    {
        "name": "remediate",
        "description": "Generate remediation plan or optionally execute Terraform (gated)",
        "parameters": [
            {
                "name": "max_cuts",
                "type": "integer",
                "required": False,
                "default": 5,
                "description": "Maximum remediations to include",
            },
            {
                "name": "apply",
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "Write remediation plan to disk (safety stub)",
            },
            {
                "name": "dry_run",
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "Simulate apply and write plan/IaC artifacts",
            },
            {
                "name": "execute_terraform",
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "UNSAFE: execute terraform apply locally. Requires --enable-unsafe-write-mode.",
            },
            {
                "name": "terraform_plan",
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "Run terraform init/plan against generated module",
            },
            {
                "name": "terraform_output",
                "type": "string",
                "required": False,
                "description": "Terraform hints output path",
            },
            {
                "name": "enable_unsafe_write_mode",
                "type": "boolean",
                "required": False,
                "description": "Required to allow --apply/--execute-terraform (defaults to off for safety)",
            },
            {
                "name": "terraform_dir",
                "type": "string",
                "required": False,
                "description": "Directory to write Terraform module",
            },
            {
                "name": "output",
                "type": "string",
                "required": False,
                "description": "Output path for remediation plan",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "table",
                "enum": ["table", "json", "agent"],
                "description": "Output format",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "plan": {"type": "array"},
                "coverage": {"type": "number"},
                "paths_blocked": {"type": "integer"},
            },
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
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "text",
                "enum": ["text", "json", "agent"],
                "description": "Output format",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "intent": {"type": "string"},
                "results": {"type": "object"},
            },
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": 'cyntrisec ask "what can reach the production database?" --format agent',
        "suggested_after": ["scan", "analyze paths"],
    },
    {
        "name": "report",
        "description": "Generate HTML or JSON report from scan results",
        "parameters": [
            {
                "name": "scan",
                "type": "string",
                "required": False,
                "description": "Scan ID (default: latest)",
            },
            {
                "name": "output",
                "type": "string",
                "required": False,
                "default": "cyntrisec-report.html",
                "description": "Output file path",
            },
            {
                "name": "title",
                "type": "string",
                "required": False,
                "description": "Report title",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "html",
                "enum": ["html", "json", "agent"],
                "description": "Output format",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "snapshot_id": {"type": "string"},
                "account_id": {"type": "string"},
                "output_path": {"type": "string"},
                "findings": {"type": "integer"},
                "paths": {"type": "integer"},
            },
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec report --output report.html",
        "suggested_after": ["scan"],
    },
    {
        "name": "validate-role",
        "description": "Validate that an IAM role can be assumed",
        "parameters": [
            {
                "name": "role_arn",
                "type": "string",
                "required": True,
                "description": "IAM role ARN to validate",
            },
            {
                "name": "external_id",
                "type": "string",
                "required": False,
                "description": "External ID for role assumption",
            },
            {
                "name": "profile",
                "type": "string",
                "required": False,
                "description": "AWS CLI profile for base credentials",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "text",
                "enum": ["text", "json", "agent"],
                "description": "Output format",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "role_arn": {"type": "string"},
                "account": {"type": "string"},
                "arn": {"type": "string"},
                "user_id": {"type": "string"},
            },
        },
        "exit_codes": {"0": "role valid", "1": "role invalid", "2": "error"},
        "example": "cyntrisec validate-role --role-arn arn:aws:iam::123:role/Scanner",
    },
    {
        "name": "setup iam",
        "description": "Generate IAM role template for Cyntrisec scanning",
        "parameters": [
            {
                "name": "account_id",
                "type": "string",
                "required": True,
                "description": "AWS account ID (12 digits)",
            },
            {
                "name": "role_name",
                "type": "string",
                "required": False,
                "default": "CyntrisecReadOnly",
                "description": "Name for the IAM role",
            },
            {
                "name": "external_id",
                "type": "string",
                "required": False,
                "description": "External ID for extra security",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "terraform",
                "enum": ["terraform", "cloudformation", "policy"],
                "description": "Template format",
            },
            {
                "name": "output",
                "type": "string",
                "required": False,
                "description": "Output file path",
            },
            {
                "name": "output_format",
                "type": "string",
                "required": False,
                "default": "text",
                "enum": ["text", "json", "agent"],
                "description": "Render format for CLI output",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "role_name": {"type": "string"},
                "external_id": {"type": "string"},
                "template_format": {"type": "string"},
                "template": {"type": "string"},
                "output_path": {"type": "string"},
            },
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec setup iam 123456789012 --output role.tf",
    },
    {
        "name": "explain",
        "description": "Get natural language explanation of paths, controls, or findings",
        "parameters": [
            {
                "name": "category",
                "type": "string",
                "required": True,
                "enum": ["finding", "path", "control"],
                "description": "Category to explain: finding, path, control",
            },
            {
                "name": "identifier",
                "type": "string",
                "required": True,
                "description": "Identifier of the item to explain",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "text",
                "enum": ["text", "json", "markdown", "agent"],
                "description": "Output format",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "type": {"type": "string"},
                "id": {"type": "string"},
                "explanation": {"type": "object"},
            },
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec explain finding security_group_open_to_world --format agent",
    },
    {
        "name": "analyze findings",
        "description": "View security findings from the latest scan",
        "parameters": [
            {
                "name": "scan",
                "type": "string",
                "required": False,
                "description": "Scan ID (default: latest)",
            },
            {
                "name": "severity",
                "type": "string",
                "required": False,
                "enum": ["critical", "high", "medium", "low", "info"],
                "description": "Filter by severity",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "table",
                "enum": ["table", "json", "agent"],
                "description": "Output format",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "findings": {"type": "array"},
                "total": {"type": "integer"},
                "filter": {"type": "string"},
            },
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec analyze findings --severity high --format json",
        "suggested_after": ["scan"],
    },
    {
        "name": "analyze stats",
        "description": "View summary statistics from the latest scan",
        "parameters": [
            {
                "name": "scan",
                "type": "string",
                "required": False,
                "description": "Scan ID (default: latest)",
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "default": "text",
                "enum": ["text", "json", "agent"],
                "description": "Output format",
            },
        ],
        "output": {
            "type": "object",
            "properties": {
                "snapshot_id": {"type": "string"},
                "scan_id": {"type": "string"},
                "account_id": {"type": "string"},
                "asset_count": {"type": "integer"},
                "relationship_count": {"type": "integer"},
                "finding_count": {"type": "integer"},
                "path_count": {"type": "integer"},
                "regions": {"type": "array"},
                "status": {"type": "string"},
            },
        },
        "exit_codes": {"0": "success", "2": "error"},
        "example": "cyntrisec analyze stats --format json",
        "suggested_after": ["scan"],
    },
]


@handle_errors
def manifest_cmd(
    command: str | None = typer.Option(
        None,
        "--command",
        "-c",
        help="Get manifest for a specific command",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
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
