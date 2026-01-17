"""
Validate Role Command - Check AWS role trust without running a full scan.
"""
from __future__ import annotations

import json
from typing import Optional

import typer


def validate_role_cmd(
    role_arn: str = typer.Option(
        ...,
        "--role-arn",
        "-r",
        help="AWS IAM role ARN to validate",
    ),
    external_id: Optional[str] = typer.Option(
        None,
        "--external-id",
        "-e",
        help="External ID for role assumption",
    ),
    profile: Optional[str] = typer.Option(
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
    
    try:
        creds = CredentialProvider(profile=profile)
        session = creds.assume_role(role_arn, external_id=external_id)
        identity = session.client("sts").get_caller_identity()
        
        result = {
            "success": True,
            "role_arn": role_arn,
            "account": identity["Account"],
            "arn": identity["Arn"],
            "user_id": identity["UserId"],
        }
        
        if json_output:
            typer.echo(json.dumps(result, indent=2))
        else:
            typer.echo("", err=True)
            typer.echo("✓ Role validation successful!", err=True)
            typer.echo(f"  Account: {identity['Account']}", err=True)
            typer.echo(f"  ARN: {identity['Arn']}", err=True)
            typer.echo(f"  UserId: {identity['UserId']}", err=True)
        
        raise typer.Exit(0)
        
    except PermissionError as e:
        result = {
            "success": False,
            "role_arn": role_arn,
            "error": str(e),
            "error_type": "AccessDenied",
        }
        
        if json_output:
            typer.echo(json.dumps(result, indent=2))
        else:
            typer.echo("", err=True)
            typer.echo("✗ Role validation failed: Access Denied", err=True)
            typer.echo(f"  {e}", err=True)
        
        raise typer.Exit(2)
        
    except Exception as e:
        result = {
            "success": False,
            "role_arn": role_arn,
            "error": str(e),
            "error_type": type(e).__name__,
        }
        
        if json_output:
            typer.echo(json.dumps(result, indent=2))
        else:
            typer.echo("", err=True)
            typer.echo(f"✗ Role validation failed: {e}", err=True)
        
        raise typer.Exit(2)
