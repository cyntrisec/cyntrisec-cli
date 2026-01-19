"""
explain command - Natural language explanations of findings and attack paths.

Provides agent-friendly explanations for findings, attack vectors, and compliance controls.
"""

from __future__ import annotations

import logging

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from cyntrisec.cli.errors import EXIT_CODE_MAP, CyntriError, ErrorCode, handle_errors
from cyntrisec.cli.output import emit_agent_or_json, resolve_format, suggested_actions
from cyntrisec.cli.schemas import ExplainResponse
from cyntrisec.core.compliance import CIS_CONTROLS, SOC2_CONTROLS

console = Console()
log = logging.getLogger(__name__)

# Finding type explanations
FINDING_EXPLANATIONS = {
    "security_group_open_to_world": {
        "title": "Security Group Open to World",
        "severity": "HIGH",
        "what": "A security group has an inbound rule allowing traffic from 0.0.0.0/0 (all IPs).",
        "why": "This exposes the resource to the entire internet. Attackers can scan and probe the exposed ports, potentially leading to exploitation if vulnerabilities exist.",
        "fix": "Restrict the source IP to specific trusted ranges. Use VPN or bastion hosts for remote access instead of direct internet exposure.",
        "next_command": "cyntrisec cuts",
    },
    "security-group-open-to-world": {
        "title": "Security Group Open to World",
        "severity": "HIGH",
        "what": "A security group has an inbound rule allowing traffic from 0.0.0.0/0 (all IPs).",
        "why": "This exposes the resource to the entire internet. Attackers can scan and probe the exposed ports, potentially leading to exploitation if vulnerabilities exist.",
        "fix": "Restrict the source IP to specific trusted ranges. Use VPN or bastion hosts for remote access instead of direct internet exposure.",
        "next_command": "cyntrisec cuts",
    },
    "s3_public_bucket": {
        "title": "S3 Bucket Publicly Accessible",
        "severity": "CRITICAL",
        "what": "An S3 bucket has public access enabled through ACLs or bucket policies.",
        "why": "Public buckets can be discovered and accessed by anyone. This is a leading cause of data breaches, exposing sensitive customer data, credentials, or intellectual property.",
        "fix": "Enable S3 Block Public Access at both bucket and account level. Review and remove any 'Principal: *' statements from bucket policies.",
        "next_command": "cyntrisec comply --framework cis-aws",
    },
    "s3-bucket-partial-public-access-block": {
        "title": "S3 Bucket Missing Public Access Block",
        "severity": "HIGH",
        "what": "An S3 bucket does not have all public access block settings enabled.",
        "why": "Partial public access blocks leave gaps that could allow unintended public access to bucket contents through ACLs or bucket policies.",
        "fix": "Enable all four S3 Block Public Access settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.",
        "next_command": "cyntrisec comply --framework cis-aws",
    },
    "s3-bucket-public-access-block": {
        "title": "S3 Bucket Public Access Block Disabled",
        "severity": "HIGH",
        "what": "An S3 bucket has public access block settings disabled.",
        "why": "Without public access blocks, the bucket may be exposed to the internet through ACLs or bucket policies.",
        "fix": "Enable S3 Block Public Access at both bucket and account level.",
        "next_command": "cyntrisec comply --framework cis-aws",
    },
    "ec2-public-ip": {
        "title": "EC2 Instance with Public IP",
        "severity": "MEDIUM",
        "what": "An EC2 instance has a public IP address assigned.",
        "why": "Public IPs expose instances directly to the internet, increasing attack surface. Attackers can scan and probe exposed services.",
        "fix": "Use private subnets with NAT gateways for outbound access. Use load balancers or bastion hosts for inbound access.",
        "next_command": "cyntrisec analyze paths",
    },
    "iam_overly_permissive_trust": {
        "title": "Overly Permissive IAM Trust Policy",
        "severity": "HIGH",
        "what": "An IAM role has a trust policy that allows assumption from broad principals (e.g., all AWS accounts, or Principal: '*').",
        "why": "This could allow unauthorized cross-account access or privilege escalation if an attacker compromises any trusted entity.",
        "fix": "Restrict trust policies to specific, known AWS account IDs and principals. Add conditions like external ID or source IP restrictions.",
        "next_command": "cyntrisec can <role> access <target>",
    },
}

# Attack vector explanations
ATTACK_VECTOR_EXPLANATIONS = {
    "instance-compromise": {
        "title": "Instance Compromise Attack Path",
        "description": "An attacker who gains access to an EC2 instance can leverage its IAM role to access other resources.",
        "stages": [
            "1. **Initial Access**: Attacker exploits vulnerability or uses stolen credentials to access EC2 instance",
            "2. **Credential Theft**: Instance metadata service (IMDS) provides temporary IAM credentials",
            "3. **Lateral Movement**: Attacker uses IAM role permissions to access S3, RDS, or other services",
            "4. **Impact**: Data exfiltration, privilege escalation, or further infrastructure compromise",
        ],
        "mitigations": [
            "Use IMDSv2 instead of IMDSv1 to prevent SSRF-based credential theft",
            "Apply least-privilege to instance IAM roles",
            "Use VPC endpoints to restrict network paths",
            "Enable GuardDuty for anomaly detection",
        ],
    },
    "lateral-movement": {
        "title": "Lateral Movement Attack Path",
        "description": "An attacker moves from one compromised resource to another to expand their access.",
        "stages": [
            "1. **Initial Foothold**: Attacker compromises one resource (EC2, Lambda, etc.)",
            "2. **Discovery**: Attacker enumerates accessible resources using IAM permissions",
            "3. **Pivot**: Attacker uses shared credentials or trust relationships to reach new resources",
            "4. **Escalation**: Each hop potentially grants access to more sensitive data or controls",
        ],
        "mitigations": [
            "Segment networks using VPCs and security groups",
            "Implement strict IAM policies with least-privilege",
            "Use AWS PrivateLink for sensitive service access",
            "Monitor for unusual API calls with CloudTrail",
        ],
    },
}


@handle_errors
def explain_cmd(
    category: str = typer.Argument(
        ...,
        help="Category to explain: finding, path, control",
    ),
    identifier: str = typer.Argument(
        ...,
        help="Identifier of the item to explain",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: text, json, markdown, agent (defaults to json when piped)",
    ),
):
    """
    Get natural language explanations of security findings, attack paths, or compliance controls.

    Examples:
        cyntrisec explain finding security_group_open_to_world
        cyntrisec explain path instance-compromise
        cyntrisec explain control CIS-AWS:5.1
    """
    output_format = resolve_format(
        format,
        default_tty="text",
        allowed=["text", "json", "markdown", "agent"],
    )

    if category == "finding":
        _explain_finding(identifier, output_format)
    elif category == "path":
        _explain_path(identifier, output_format)
    elif category == "control":
        _explain_control(identifier, output_format)
    else:
        raise CyntriError(
            error_code=ErrorCode.INVALID_QUERY,
            message=f"Unknown category '{category}'. Use: finding, path, control",
            exit_code=EXIT_CODE_MAP["usage"],
        )


def _explain_finding(finding_type: str, format: str):
    """Explain a finding type."""
    explanation = FINDING_EXPLANATIONS.get(finding_type)

    if not explanation:
        # Try to find partial match
        for key, exp in FINDING_EXPLANATIONS.items():
            if finding_type in key:
                explanation = exp
                break

    if not explanation:
        raise CyntriError(
            error_code=ErrorCode.INVALID_QUERY,
            message=f"No explanation found for finding type '{finding_type}'",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    if format in {"json", "agent"}:
        next_cmd = explanation.get("next_command")
        actions = suggested_actions([(next_cmd, "Suggested next step")] if next_cmd else [])
        emit_agent_or_json(
            format,
            {"type": "finding", "id": finding_type, "explanation": explanation},
            suggested=actions,
            schema=ExplainResponse,
        )
        return

    if format == "markdown":
        md = (
            f"# {explanation['title']}\n\n"
            f"**Severity:** {explanation['severity']}\n\n"
            f"## What is it?\n{explanation['what']}\n\n"
            f"## Why does it matter?\n{explanation['why']}\n\n"
            f"## How to fix it?\n{explanation['fix']}\n"
        )
        # Output raw markdown text, not Rich-rendered
        typer.echo(md)
        return

    _render_finding_explanation(explanation)


def _explain_path(attack_vector: str, format: str):
    """Explain an attack path/vector."""
    explanation = ATTACK_VECTOR_EXPLANATIONS.get(attack_vector)

    if not explanation:
        for key, exp in ATTACK_VECTOR_EXPLANATIONS.items():
            if attack_vector in key:
                explanation = exp
                break

    if not explanation:
        raise CyntriError(
            error_code=ErrorCode.INVALID_QUERY,
            message=f"No explanation found for attack vector '{attack_vector}'",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    if format in {"json", "agent"}:
        emit_agent_or_json(
            format,
            {"type": "path", "id": attack_vector, "explanation": explanation},
            suggested=suggested_actions(
                [
                    ("cyntrisec analyze paths --format agent", "List concrete paths of this type"),
                ]
            ),
            schema=ExplainResponse,
        )
        return

    if format == "markdown":
        md = (
            f"# {explanation['title']}\n\n"
            f"{explanation['description']}\n\n"
            f"## Attack Stages\n" + "\n".join(explanation["stages"]) + "\n\n"
            "## Mitigations\n" + "\n".join(f"- {m}" for m in explanation["mitigations"])
        )
        # Output raw markdown text, not Rich-rendered
        typer.echo(md)
        return

    _render_path_explanation(explanation)


def _explain_control(control_id: str, format: str):
    """Explain a compliance control."""
    all_controls = CIS_CONTROLS + SOC2_CONTROLS

    control = None
    for c in all_controls:
        if c.id == control_id or c.full_id == control_id:
            control = c
            break

    if not control:
        raise CyntriError(
            error_code=ErrorCode.INVALID_QUERY,
            message=f"No control found for '{control_id}'",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    explanation = {
        "id": control.full_id,
        "title": control.title,
        "description": control.description,
        "severity": control.severity,
        "framework": control.framework.value,
    }

    if format in {"json", "agent"}:
        emit_agent_or_json(
            format,
            {"type": "control", "id": control.full_id, "explanation": explanation},
            suggested=suggested_actions(
                [
                    ("cyntrisec comply --format agent", "Run a full compliance check"),
                ]
            ),
            schema=ExplainResponse,
        )
    elif format == "markdown":
        md = (
            f"# {control.full_id}: {control.title}\n\n"
            f"{control.description}\n\n"
            f"**Severity:** {control.severity.upper()}\n"
        )
        # Output raw markdown text, not Rich-rendered
        typer.echo(md)
    else:
        console.print()
        console.print(
            Panel(
                f"{control.title}\n\n{control.description}\n\nSeverity: {control.severity.upper()}",
                title=f"Control {control.full_id}",
                border_style="cyan",
            )
        )


def _render_finding_explanation(exp: dict):
    """Render a finding explanation as rich text."""
    console.print()

    sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(
        exp["severity"], "white"
    )

    console.print(
        Panel(
            f"{exp['title']}\n\n"
            f"Severity: {exp['severity']}\n\n"
            f"What is it?\n{exp['what']}\n\n"
            f"Why does it matter?\n{exp['why']}\n\n"
            f"How to fix it?\n{exp['fix']}",
            title="Finding Explanation",
            border_style=sev_color,
        )
    )

    if exp.get("next_command"):
        console.print(f"\n[cyan]Suggested next command:[/cyan] `{exp['next_command']}`")


def _render_path_explanation(exp: dict):
    """Render an attack path explanation as rich text."""
    console.print()

    stages = "\n".join(exp["stages"])
    mitigations = "\n".join(f"- {m}" for m in exp["mitigations"])

    console.print(
        Panel(
            f"**{exp['title']}**\n\n"
            f"{exp['description']}\n\n"
            f"**Attack Stages:**\n{stages}\n\n"
            f"**Mitigations:**\n{mitigations}",
            title="Attack Path Explanation",
            border_style="red",
        )
    )
