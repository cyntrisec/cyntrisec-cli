"""
Setup Commands - Generate IAM roles and configuration.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

setup_app = typer.Typer(help="Setup commands")


@setup_app.command("iam")
def setup_iam(
    account_id: str = typer.Argument(
        ...,
        help="AWS account ID (12 digits)",
    ),
    role_name: str = typer.Option(
        "CyntrisecReadOnly",
        "--role-name",
        "-n",
        help="Name for the IAM role",
    ),
    external_id: Optional[str] = typer.Option(
        None,
        "--external-id",
        "-e",
        help="External ID for extra security",
    ),
    format: str = typer.Option(
        "terraform",
        "--format",
        "-f",
        help="Output format: terraform, cloudformation, policy",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file (default: stdout)",
    ),
):
    """
    Generate IAM role for AWS scanning.
    
    Creates a read-only IAM role that Cyntrisec can assume.
    
    Examples:
    
        cyntrisec setup iam 123456789012 --output role.tf
        
        cyntrisec setup iam 123456789012 --format policy
        
        cyntrisec setup iam 123456789012 --external-id my-id --format cloudformation
    """
    # Validate
    if not account_id.isdigit() or len(account_id) != 12:
        typer.echo("Error: Account ID must be exactly 12 digits", err=True)
        raise typer.Exit(2)
    
    # Read-only policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "CyntrisecReadOnly",
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "iam:Get*",
                "iam:List*",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketLocation",
                "s3:ListBucket",
                "s3:ListAllMyBuckets",
                "lambda:GetFunction",
                "lambda:GetFunctionConfiguration",
                "lambda:GetPolicy",
                "lambda:ListFunctions",
                "rds:Describe*",
                "elasticloadbalancing:Describe*",
                "route53:List*",
                "route53:Get*",
                "cloudfront:Get*",
                "cloudfront:List*",
                "apigateway:GET",
                "sts:GetCallerIdentity",
            ],
            "Resource": "*"
        }]
    }
    
    if format == "terraform":
        result = _gen_terraform(account_id, role_name, external_id, policy)
    elif format == "cloudformation":
        result = _gen_cloudformation(role_name, external_id, policy)
    elif format == "policy":
        result = json.dumps(policy, indent=2)
    else:
        typer.echo(f"Unknown format: {format}", err=True)
        raise typer.Exit(2)
    
    if output:
        output.write_text(result)
        typer.echo(f"Written to {output}", err=True)
    else:
        typer.echo(result)


def _gen_terraform(account_id: str, role_name: str, external_id: Optional[str], policy: dict) -> str:
    """Generate Terraform configuration."""
    safe_name = role_name.lower().replace("-", "_")
    
    ext_cond = ""
    if external_id:
        ext_cond = f'''
    condition {{
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["{external_id}"]
    }}'''
    
    policy_json = json.dumps(policy, indent=4)
    
    return f'''# Cyntrisec Read-Only IAM Role
# Usage: cyntrisec scan --role-arn <output.role_arn>{f' --external-id {external_id}' if external_id else ''}

data "aws_caller_identity" "current" {{}}

resource "aws_iam_role" "{safe_name}" {{
  name = "{role_name}"
  
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect    = "Allow"
      Principal = {{ AWS = "arn:aws:iam::${{data.aws_caller_identity.current.account_id}}:root" }}
      Action    = "sts:AssumeRole"{ext_cond}
    }}]
  }})
  
  tags = {{
    Purpose   = "Cyntrisec"
    ManagedBy = "terraform"
    ReadOnly  = "true"
  }}
}}

resource "aws_iam_role_policy" "{safe_name}_policy" {{
  name   = "{role_name}Policy"
  role   = aws_iam_role.{safe_name}.id
  policy = jsonencode({policy_json})
}}

output "role_arn" {{
  value = aws_iam_role.{safe_name}.arn
}}
'''


def _gen_cloudformation(role_name: str, external_id: Optional[str], policy: dict) -> str:
    """Generate CloudFormation template."""
    cond = ""
    if external_id:
        cond = f'''
            Condition:
              StringEquals:
                sts:ExternalId: "{external_id}"'''
    
    policy_yaml = json.dumps(policy, indent=8).replace("\n", "\n        ")
    
    return f'''AWSTemplateFormatVersion: "2010-09-09"
Description: Cyntrisec Read-Only IAM Role

Resources:
  CyntrisecRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: {role_name}
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub "arn:aws:iam::${{AWS::AccountId}}:root"
            Action: sts:AssumeRole{cond}
      Tags:
        - Key: Purpose
          Value: Cyntrisec
        - Key: ReadOnly
          Value: "true"

  CyntrisecPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: {role_name}Policy
      Roles: [!Ref CyntrisecRole]
      PolicyDocument: {policy_yaml}

Outputs:
  RoleArn:
    Value: !GetAtt CyntrisecRole.Arn
    Export:
      Name: CyntrisecRoleArn
'''
