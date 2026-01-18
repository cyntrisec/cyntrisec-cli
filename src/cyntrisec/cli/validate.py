"""
Validate Role Command - Check AWS role trust without running a full scan.
"""

from __future__ import annotations

import typer

from cyntrisec.cli.errors import EXIT_CODE_MAP, CyntriError, ErrorCode, handle_errors
from cyntrisec.cli.output import emit_agent_or_json, resolve_format, suggested_actions
from cyntrisec.cli.schemas import ValidateRoleResponse


@handle_errors
def validate_role_cmd(
    role_arn: str = typer.Option(
        ...,
        "--role-arn",
        "-r",
        help="AWS IAM role ARN to validate",
    ),
    external_id: str | None = typer.Option(
        None,
        "--external-id",
        "-e",
        help="External ID for role assumption",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help="AWS CLI profile for base credentials",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: text, json, agent (defaults to json when piped)",
    ),
):
    """
    Validate that an IAM role can be assumed.

    Performs STS AssumeRole + GetCallerIdentity to verify trust.
    Useful for testing role configuration before running a full scan.

    Examples:

        cyntrisec validate-role --role-arn arn:aws:iam::123456789012:role/ReadOnly

        cyntrisec validate-role -r arn:aws:iam::123456789012:role/ReadOnly --json
    """
    from cyntrisec.aws.credentials import CredentialProvider

    typer.echo(f"Validating role: {role_arn}", err=True)
    resolved_format = resolve_format(
        "json" if json_output and format is None else format,
        default_tty="text",
        allowed=["text", "json", "agent"],
    )

    creds = CredentialProvider(profile=profile)
    try:
        session = creds.assume_role(role_arn, external_id=external_id)
    except PermissionError as e:
        raise CyntriError(
            error_code=ErrorCode.AWS_ACCESS_DENIED,
            message=str(e),
            exit_code=EXIT_CODE_MAP["usage"],
        )
    identity = session.client("sts").get_caller_identity()

    result = {
        "success": True,
        "role_arn": role_arn,
        "account": identity.get("Account"),
        "arn": identity.get("Arn"),
        "user_id": identity.get("UserId"),
    }

    if resolved_format in {"json", "agent"}:
        actions = suggested_actions(
            [
                (f"cyntrisec scan --role-arn {role_arn}", "Start a scan with the validated role"),
                ("cyntrisec report --format json", "Export results for audit"),
            ]
        )
        emit_agent_or_json(resolved_format, result, suggested=actions, schema=ValidateRoleResponse)
    else:
        typer.echo("", err=True)
        typer.echo("Role validation successful!", err=True)
        typer.echo(f"  Account: {identity['Account']}", err=True)
        typer.echo(f"  ARN: {identity['Arn']}", err=True)
        typer.echo(f"  UserId: {identity['UserId']}", err=True)

    raise typer.Exit(0)
