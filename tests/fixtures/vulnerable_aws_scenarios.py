"""
Vulnerable AWS Test Fixtures for cyntrisec-cli.

This module provides realistic test data representing various AWS security
misconfigurations and attack paths, modeled after:
- CloudGoat scenarios (RhinoSecurityLabs)
- IAM Vulnerable paths (BishopFox)
- Real-world AWS security incidents

Each fixture function returns (assets, relationships, expected_paths) where
expected_paths describes the attack paths that should be discovered.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from cyntrisec.core.schema import (
    INTERNET_ASSET_ID,
    Asset,
    EdgeEvidence,
    EdgeKind,
    Relationship,
)


# Fixed UUIDs for consistent testing
SNAPSHOT_ID = uuid.UUID("00000000-0000-0000-0000-000000000000")

# Well-known asset IDs
LAMBDA_SERVICE_ID = uuid.UUID("00000000-0000-0000-0000-00000000000a")


@dataclass
class ExpectedPath:
    """Describes an expected attack path for test validation."""
    description: str
    entry_point_name: str
    target_name: str
    min_hops: int
    max_hops: int
    key_edges: list[str]  # e.g., ["CAN_ASSUME", "CAN_PASS_TO", "MAY_CREATE_LAMBDA"]
    confidence: str = "HIGH"  # HIGH, MED, LOW


def make_asset(
    asset_id: uuid.UUID,
    asset_type: str,
    name: str,
    *,
    arn: str | None = None,
    aws_resource_id: str | None = None,
    properties: dict | None = None,
    is_internet_facing: bool = False,
    is_sensitive_target: bool = False,
    region: str = "us-east-1",
) -> Asset:
    """Helper to create an Asset with common defaults."""
    return Asset(
        id=asset_id,
        snapshot_id=SNAPSHOT_ID,
        asset_type=asset_type,
        name=name,
        arn=arn or f"arn:aws:{asset_type.split(':')[0]}::{region}:{name}",
        aws_resource_id=aws_resource_id or name,
        aws_region=region,
        properties=properties or {},
        is_internet_facing=is_internet_facing,
        is_sensitive_target=is_sensitive_target,
    )


def make_relationship(
    source_id: uuid.UUID,
    target_id: uuid.UUID,
    rel_type: str,
    edge_kind: EdgeKind = EdgeKind.CAPABILITY,
    properties: dict | None = None,
    evidence: EdgeEvidence | None = None,
) -> Relationship:
    """Helper to create a Relationship with common defaults."""
    return Relationship(
        snapshot_id=SNAPSHOT_ID,
        source_asset_id=source_id,
        target_asset_id=target_id,
        relationship_type=rel_type,
        edge_kind=edge_kind,
        properties=properties or {},
        evidence=evidence,
    )


def make_iam_role(
    role_id: uuid.UUID,
    name: str,
    account_id: str = "123456789012",
    policy_statements: list[dict] | None = None,
    trust_policy_principals: list[str] | None = None,
    is_admin: bool = False,
) -> Asset:
    """Create an IAM role asset with policies."""
    arn = f"arn:aws:iam::{account_id}:role/{name}"

    policy_docs = []
    if policy_statements:
        policy_docs.append({
            "Version": "2012-10-17",
            "Statement": policy_statements,
        })

    trust_policy = None
    if trust_policy_principals:
        trust_statements = []
        for principal in trust_policy_principals:
            if principal.startswith("arn:aws:iam::") and ":role/" in principal:
                # Role principal
                trust_statements.append({
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "sts:AssumeRole",
                })
            elif principal.endswith(".amazonaws.com"):
                # Service principal
                trust_statements.append({
                    "Effect": "Allow",
                    "Principal": {"Service": principal},
                    "Action": "sts:AssumeRole",
                })
            elif principal == "*":
                # Wildcard
                trust_statements.append({
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole",
                })
            else:
                # Account root or specific principal
                trust_statements.append({
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "sts:AssumeRole",
                })

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": trust_statements,
        }

    return make_asset(
        asset_id=role_id,
        asset_type="iam:role",
        name=name,
        arn=arn,
        properties={
            "role_id": str(role_id)[:20],
            "policy_documents": policy_docs,
            "trust_policy": trust_policy,
        },
        is_sensitive_target=is_admin or "admin" in name.lower(),
    )


def make_ec2_instance(
    instance_id: uuid.UUID,
    name: str,
    security_group_ids: list[str],
    has_public_ip: bool = False,
    instance_profile_arn: str | None = None,
) -> Asset:
    """Create an EC2 instance asset."""
    return make_asset(
        asset_id=instance_id,
        asset_type="ec2:instance",
        name=name,
        aws_resource_id=f"i-{str(instance_id)[:17].replace('-', '')}",
        properties={
            "security_groups": security_group_ids,
            "instance_profile_arn": instance_profile_arn,
            "public_ip": "1.2.3.4" if has_public_ip else None,
        },
        is_internet_facing=has_public_ip,
    )


def make_security_group(
    sg_id: uuid.UUID,
    name: str,
    vpc_id: str,
    ingress_rules: list[dict] | None = None,
) -> Asset:
    """Create a Security Group asset."""
    return make_asset(
        asset_id=sg_id,
        asset_type="ec2:security-group",
        name=name,
        aws_resource_id=f"sg-{str(sg_id)[:17].replace('-', '')}",
        properties={
            "vpc_id": vpc_id,
            "ingress_rules": ingress_rules or [],
        },
    )


def make_lambda_function(
    func_id: uuid.UUID,
    name: str,
    execution_role_arn: str,
) -> Asset:
    """Create a Lambda function asset."""
    return make_asset(
        asset_id=func_id,
        asset_type="lambda:function",
        name=name,
        arn=f"arn:aws:lambda:us-east-1:123456789012:function:{name}",
        properties={
            "execution_role_arn": execution_role_arn,
            "runtime": "python3.9",
        },
    )


def make_internet_asset() -> Asset:
    """Create the Internet pseudo-asset."""
    return Asset(
        id=INTERNET_ASSET_ID,
        snapshot_id=SNAPSHOT_ID,
        asset_type="pseudo:internet",
        name="Internet",
        aws_resource_id="internet",
        properties={"description": "The Internet (0.0.0.0/0)"},
        is_internet_facing=True,
    )


# =============================================================================
# SCENARIO 1: Lambda Privilege Escalation (CloudGoat lambda_privesc)
# =============================================================================
def scenario_lambda_privesc() -> tuple[list[Asset], list[Relationship], list[ExpectedPath]]:
    """
    Lambda Privilege Escalation scenario.

    Attack path:
    1. Attacker compromises EC2 instance with public IP
    2. EC2 has role with Lambda:* and PassRole permissions
    3. Attacker creates Lambda with admin role
    4. Lambda executes with admin privileges

    Based on CloudGoat lambda_privesc scenario.
    """
    account_id = "123456789012"
    vpc_id = "vpc-12345678"

    # Asset IDs
    ec2_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    sg_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    attacker_role_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    admin_role_id = uuid.UUID("44444444-4444-4444-4444-444444444444")

    assets = [
        make_internet_asset(),

        # Security group open to world on SSH
        make_security_group(
            sg_id, "vulnerable-sg", vpc_id,
            ingress_rules=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "UserIdGroupPairs": [],
            }],
        ),

        # EC2 instance with public IP
        make_ec2_instance(
            ec2_id, "vulnerable-instance",
            security_group_ids=[f"sg-{str(sg_id)[:17].replace('-', '')}"],
            has_public_ip=True,
            instance_profile_arn=f"arn:aws:iam::{account_id}:instance-profile/attacker-profile",
        ),

        # Attacker's initial role (Lambda + PassRole)
        make_iam_role(
            attacker_role_id, "LambdaManager",
            account_id=account_id,
            policy_statements=[
                {
                    "Sid": "LambdaFullAccess",
                    "Effect": "Allow",
                    "Action": "lambda:*",
                    "Resource": "*",
                },
                {
                    "Sid": "PassRole",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{account_id}:role/*",
                },
            ],
            trust_policy_principals=["ec2.amazonaws.com"],
        ),

        # Target admin role
        make_iam_role(
            admin_role_id, "AdminRole",
            account_id=account_id,
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
            ],
            trust_policy_principals=["lambda.amazonaws.com"],
            is_admin=True,
        ),

        # Lambda service pseudo-asset
        Asset(
            id=LAMBDA_SERVICE_ID,
            snapshot_id=SNAPSHOT_ID,
            asset_type="pseudo:lambda-service",
            name="Lambda Service",
            aws_resource_id="lambda-service",
            properties={},
        ),
    ]

    relationships = [
        # Internet -> EC2 (CAN_REACH via open SG)
        make_relationship(
            INTERNET_ASSET_ID, ec2_id, "CAN_REACH",
            properties={"protocol": "tcp", "port_range": "22-22", "source": "world"},
        ),

        # SG -> EC2 (structural)
        make_relationship(
            sg_id, ec2_id, "ALLOWS_TRAFFIC_TO",
            edge_kind=EdgeKind.STRUCTURAL,
        ),

        # EC2 -> Attacker Role (CAN_ASSUME via instance profile)
        make_relationship(
            ec2_id, attacker_role_id, "CAN_ASSUME",
            properties={"via": "instance_profile"},
        ),

        # Attacker Role -> Admin Role (CAN_PASS_TO)
        make_relationship(
            attacker_role_id, admin_role_id, "CAN_PASS_TO",
            properties={"via": "iam_pass_role"},
            evidence=EdgeEvidence(
                policy_sid="PassRole",
                permission="iam:PassRole",
                source_arn=f"arn:aws:iam::{account_id}:role/LambdaManager",
                target_arn=f"arn:aws:iam::{account_id}:role/AdminRole",
            ),
        ),

        # Attacker Role -> Lambda Service (MAY_CREATE_LAMBDA)
        make_relationship(
            attacker_role_id, LAMBDA_SERVICE_ID, "MAY_CREATE_LAMBDA",
            properties={"via": "iam_policy", "action": "lambda:CreateFunction"},
            evidence=EdgeEvidence(
                policy_sid="LambdaFullAccess",
                permission="lambda:CreateFunction",
                source_arn=f"arn:aws:iam::{account_id}:role/LambdaManager",
                target_arn="arn:aws:lambda:::service",
            ),
        ),
    ]

    expected_paths = [
        ExpectedPath(
            description="Lambda privilege escalation via PassRole",
            entry_point_name="vulnerable-instance",
            target_name="AdminRole",
            min_hops=2,
            max_hops=4,
            key_edges=["CAN_REACH", "CAN_ASSUME", "CAN_PASS_TO"],
        ),
    ]

    return assets, relationships, expected_paths


# =============================================================================
# SCENARIO 2: IAM Role Chaining (sts:AssumeRole chain)
# =============================================================================
def scenario_role_chaining() -> tuple[list[Asset], list[Relationship], list[ExpectedPath]]:
    """
    IAM Role Chaining scenario.

    Attack path:
    1. Attacker compromises EC2 with low-privilege role
    2. Low-privilege role can assume intermediate role
    3. Intermediate role can assume admin role

    This tests the new role-to-role CAN_ASSUME edge creation.
    """
    account_id = "123456789012"
    vpc_id = "vpc-12345678"

    # Asset IDs
    ec2_id = uuid.UUID("11111111-2222-1111-1111-111111111111")
    sg_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    role_a_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    role_b_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    role_c_id = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")

    role_a_arn = f"arn:aws:iam::{account_id}:role/RoleA-LowPriv"
    role_b_arn = f"arn:aws:iam::{account_id}:role/RoleB-Intermediate"
    role_c_arn = f"arn:aws:iam::{account_id}:role/RoleC-Admin"

    assets = [
        make_internet_asset(),

        make_security_group(
            sg_id, "web-sg", vpc_id,
            ingress_rules=[{
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "UserIdGroupPairs": [],
            }],
        ),

        make_ec2_instance(
            ec2_id, "web-server",
            security_group_ids=[f"sg-{str(sg_id)[:17].replace('-', '')}"],
            has_public_ip=True,
        ),

        # Role A: Low privilege, can assume Role B
        make_iam_role(
            role_a_id, "RoleA-LowPriv",
            account_id=account_id,
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": role_b_arn,
                },
            ],
            trust_policy_principals=["ec2.amazonaws.com"],
        ),

        # Role B: Intermediate, trusts Role A, can assume Role C
        make_iam_role(
            role_b_id, "RoleB-Intermediate",
            account_id=account_id,
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": role_c_arn,
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                },
            ],
            trust_policy_principals=[role_a_arn],
        ),

        # Role C: Admin role, trusts Role B
        make_iam_role(
            role_c_id, "RoleC-Admin",
            account_id=account_id,
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
            ],
            trust_policy_principals=[role_b_arn],
            is_admin=True,
        ),
    ]

    relationships = [
        # Internet -> EC2
        make_relationship(
            INTERNET_ASSET_ID, ec2_id, "CAN_REACH",
            properties={"protocol": "tcp", "port_range": "443-443", "source": "world"},
        ),

        # SG -> EC2 (structural)
        make_relationship(sg_id, ec2_id, "ALLOWS_TRAFFIC_TO", edge_kind=EdgeKind.STRUCTURAL),

        # EC2 -> Role A (instance profile)
        make_relationship(
            ec2_id, role_a_id, "CAN_ASSUME",
            properties={"via": "instance_profile"},
        ),

        # Role A -> Role B (sts:AssumeRole)
        make_relationship(
            role_a_id, role_b_id, "CAN_ASSUME",
            properties={"via": "sts_assume_role"},
            evidence=EdgeEvidence(
                permission="sts:AssumeRole",
                source_arn=role_a_arn,
                target_arn=role_b_arn,
            ),
        ),

        # Role B -> Role C (sts:AssumeRole)
        make_relationship(
            role_b_id, role_c_id, "CAN_ASSUME",
            properties={"via": "sts_assume_role"},
            evidence=EdgeEvidence(
                permission="sts:AssumeRole",
                source_arn=role_b_arn,
                target_arn=role_c_arn,
            ),
        ),
    ]

    expected_paths = [
        ExpectedPath(
            description="Role chaining: EC2 -> RoleA -> RoleB -> RoleC(Admin)",
            entry_point_name="web-server",
            target_name="RoleC-Admin",
            min_hops=4,
            max_hops=5,
            key_edges=["CAN_REACH", "CAN_ASSUME", "CAN_ASSUME", "CAN_ASSUME"],
        ),
    ]

    return assets, relationships, expected_paths


# =============================================================================
# SCENARIO 3: S3 Data Exfiltration via Secrets
# =============================================================================
def scenario_secrets_exfiltration() -> tuple[list[Asset], list[Relationship], list[ExpectedPath]]:
    """
    Secrets exfiltration scenario.

    Attack path:
    1. Compromised Lambda function
    2. Lambda role can read Secrets Manager secrets
    3. Secrets contain database credentials (sensitive target)
    """
    account_id = "123456789012"

    # Asset IDs
    lambda_id = uuid.UUID("11111111-3333-1111-1111-111111111111")
    lambda_role_id = uuid.UUID("22222222-3333-2222-2222-222222222222")
    secret_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    api_gw_id = uuid.UUID("44444444-3333-4444-4444-444444444444")

    lambda_role_arn = f"arn:aws:iam::{account_id}:role/DataProcessorRole"

    assets = [
        make_internet_asset(),

        # API Gateway (entry point)
        make_asset(
            api_gw_id, "apigateway:rest-api", "public-api",
            arn=f"arn:aws:apigateway:us-east-1::/restapis/abc123",
            is_internet_facing=True,
            properties={"endpoint_type": "REGIONAL"},
        ),

        # Lambda function
        make_lambda_function(
            lambda_id, "data-processor",
            execution_role_arn=lambda_role_arn,
        ),

        # Lambda execution role with secrets access
        make_iam_role(
            lambda_role_id, "DataProcessorRole",
            account_id=account_id,
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret",
                    ],
                    "Resource": f"arn:aws:secretsmanager:us-east-1:{account_id}:secret:*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "*",
                },
            ],
            trust_policy_principals=["lambda.amazonaws.com"],
        ),

        # Sensitive secret
        make_asset(
            secret_id, "secretsmanager:secret", "prod-database-credentials",
            arn=f"arn:aws:secretsmanager:us-east-1:{account_id}:secret:prod-database-credentials",
            is_sensitive_target=True,
            properties={"description": "Production database credentials"},
        ),
    ]

    relationships = [
        # API Gateway -> Lambda (INVOKES)
        make_relationship(
            api_gw_id, lambda_id, "INVOKES",
            properties={"integration_type": "AWS_PROXY"},
        ),

        # Internet -> API Gateway (CAN_REACH)
        make_relationship(
            INTERNET_ASSET_ID, api_gw_id, "CAN_REACH",
            properties={"protocol": "https", "port_range": "443-443", "source": "world"},
        ),

        # Lambda -> Lambda Role (CAN_ASSUME)
        make_relationship(
            lambda_id, lambda_role_id, "CAN_ASSUME",
            properties={"via": "execution_role"},
        ),

        # Lambda Role -> Secret (MAY_READ_SECRET)
        make_relationship(
            lambda_role_id, secret_id, "MAY_READ_SECRET",
            evidence=EdgeEvidence(
                permission="secretsmanager:GetSecretValue",
                source_arn=lambda_role_arn,
                target_arn=f"arn:aws:secretsmanager:us-east-1:{account_id}:secret:prod-database-credentials",
            ),
        ),
    ]

    expected_paths = [
        ExpectedPath(
            description="Lambda secrets exfiltration via API Gateway",
            entry_point_name="public-api",
            target_name="prod-database-credentials",
            min_hops=3,
            max_hops=4,
            key_edges=["CAN_REACH", "INVOKES", "CAN_ASSUME", "MAY_READ_SECRET"],
        ),
    ]

    return assets, relationships, expected_paths


# =============================================================================
# SCENARIO 4: Cross-Account Role Assumption
# =============================================================================
def scenario_cross_account_access() -> tuple[list[Asset], list[Relationship], list[ExpectedPath]]:
    """
    Cross-account access scenario.

    Attack path:
    1. Compromised EC2 in Account A
    2. Role in Account A can assume role in Account B
    3. Role in Account B has admin access

    Tests account-level trust (arn:aws:iam::ACCOUNT:root).
    """
    account_a = "111111111111"
    account_b = "222222222222"
    vpc_id = "vpc-12345678"

    # Asset IDs
    ec2_id = uuid.UUID("11111111-4444-1111-1111-111111111111")
    sg_id = uuid.UUID("22222222-4444-2222-2222-222222222222")
    role_a_id = uuid.UUID("aaaaaaaa-4444-aaaa-aaaa-aaaaaaaaaaaa")
    role_b_id = uuid.UUID("bbbbbbbb-4444-bbbb-bbbb-bbbbbbbbbbbb")

    role_a_arn = f"arn:aws:iam::{account_a}:role/CrossAccountRole"
    role_b_arn = f"arn:aws:iam::{account_b}:role/TargetAdminRole"

    assets = [
        make_internet_asset(),

        make_security_group(
            sg_id, "bastion-sg", vpc_id,
            ingress_rules=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],  # Not open to world
                "Ipv6Ranges": [],
                "UserIdGroupPairs": [],
            }],
        ),

        # This EC2 is NOT directly internet-facing (no 0.0.0.0/0 rule)
        # but we'll assume it's compromised via another vector
        make_ec2_instance(
            ec2_id, "internal-bastion",
            security_group_ids=[f"sg-{str(sg_id)[:17].replace('-', '')}"],
            has_public_ip=False,
        ),

        # Role A in Account A - can assume role in Account B
        make_iam_role(
            role_a_id, "CrossAccountRole",
            account_id=account_a,
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": role_b_arn,
                },
            ],
            trust_policy_principals=["ec2.amazonaws.com"],
        ),

        # Role B in Account B - admin role trusting Account A
        make_iam_role(
            role_b_id, "TargetAdminRole",
            account_id=account_b,
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
            ],
            # Trust the entire Account A (root)
            trust_policy_principals=[f"arn:aws:iam::{account_a}:root"],
            is_admin=True,
        ),
    ]

    relationships = [
        # Internet -> EC2 (for testing, we assume it's reachable via some exposed service)
        # In reality, this could be SSH bastion with leaked credentials, VPN compromise, etc.
        make_relationship(
            INTERNET_ASSET_ID, ec2_id, "CAN_REACH",
            properties={"protocol": "tcp", "port_range": "22-22", "source": "assumed_compromise"},
        ),

        # EC2 -> Role A (instance profile)
        make_relationship(
            ec2_id, role_a_id, "CAN_ASSUME",
            properties={"via": "instance_profile"},
        ),

        # Role A -> Role B (cross-account sts:AssumeRole)
        make_relationship(
            role_a_id, role_b_id, "CAN_ASSUME",
            properties={"via": "sts_assume_role", "cross_account": True},
            evidence=EdgeEvidence(
                permission="sts:AssumeRole",
                source_arn=role_a_arn,
                target_arn=role_b_arn,
            ),
        ),
    ]

    expected_paths = [
        ExpectedPath(
            description="Cross-account privilege escalation",
            entry_point_name="Internet",
            target_name="TargetAdminRole",
            min_hops=3,
            max_hops=4,
            key_edges=["CAN_REACH", "CAN_ASSUME", "CAN_ASSUME"],
        ),
    ]

    return assets, relationships, expected_paths


# =============================================================================
# SCENARIO 5: Lateral Movement via Security Groups
# =============================================================================
def scenario_lateral_movement() -> tuple[list[Asset], list[Relationship], list[ExpectedPath]]:
    """
    Lateral movement scenario via security groups.

    Attack path:
    1. Compromise web server (public-facing)
    2. Web server's SG allows traffic to database SG
    3. Database server has role with sensitive data access
    """
    account_id = "123456789012"
    vpc_id = "vpc-12345678"

    # Asset IDs
    web_ec2_id = uuid.UUID("11111111-5555-1111-1111-111111111111")
    db_ec2_id = uuid.UUID("22222222-5555-2222-2222-222222222222")
    web_sg_id = uuid.UUID("33333333-5555-3333-3333-333333333333")
    db_sg_id = uuid.UUID("44444444-5555-4444-4444-444444444444")
    db_role_id = uuid.UUID("55555555-5555-5555-5555-555555555555")
    s3_bucket_id = uuid.UUID("66666666-5555-6666-6666-666666666666")

    web_sg_resource_id = f"sg-{str(web_sg_id)[:17].replace('-', '')}"
    db_sg_resource_id = f"sg-{str(db_sg_id)[:17].replace('-', '')}"

    assets = [
        make_internet_asset(),

        # Web security group - open to world
        make_security_group(
            web_sg_id, "web-tier-sg", vpc_id,
            ingress_rules=[{
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "UserIdGroupPairs": [],
            }],
        ),

        # DB security group - allows traffic from web SG
        make_security_group(
            db_sg_id, "db-tier-sg", vpc_id,
            ingress_rules=[{
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [],
                "Ipv6Ranges": [],
                "UserIdGroupPairs": [{"GroupId": web_sg_resource_id}],
            }],
        ),

        # Web server
        make_ec2_instance(
            web_ec2_id, "web-server",
            security_group_ids=[web_sg_resource_id],
            has_public_ip=True,
        ),

        # Database server
        make_ec2_instance(
            db_ec2_id, "database-server",
            security_group_ids=[db_sg_resource_id],
            has_public_ip=False,
        ),

        # Database role with S3 access
        make_iam_role(
            db_role_id, "DatabaseBackupRole",
            account_id=account_id,
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                    "Resource": [
                        f"arn:aws:s3:::sensitive-data-bucket",
                        f"arn:aws:s3:::sensitive-data-bucket/*",
                    ],
                },
            ],
            trust_policy_principals=["ec2.amazonaws.com"],
        ),

        # Sensitive S3 bucket
        make_asset(
            s3_bucket_id, "s3:bucket", "sensitive-data-bucket",
            arn="arn:aws:s3:::sensitive-data-bucket",
            is_sensitive_target=True,
            properties={"contains_pii": True},
        ),
    ]

    relationships = [
        # Internet -> Web EC2 (CAN_REACH)
        make_relationship(
            INTERNET_ASSET_ID, web_ec2_id, "CAN_REACH",
            properties={"protocol": "tcp", "port_range": "443-443", "source": "world"},
        ),

        # Web SG -> Web EC2 (structural)
        make_relationship(web_sg_id, web_ec2_id, "ALLOWS_TRAFFIC_TO", edge_kind=EdgeKind.STRUCTURAL),

        # Web EC2 -> Web SG (USE_IDENTITY - network identity)
        make_relationship(web_ec2_id, web_sg_id, "USE_IDENTITY", properties={"identity_type": "security_group"}),

        # Web SG -> DB EC2 (CAN_REACH - lateral movement via SG reference)
        make_relationship(
            web_sg_id, db_ec2_id, "CAN_REACH",
            properties={"protocol": "tcp", "port_range": "5432-5432", "source": web_sg_resource_id},
        ),

        # DB SG -> DB EC2 (structural)
        make_relationship(db_sg_id, db_ec2_id, "ALLOWS_TRAFFIC_TO", edge_kind=EdgeKind.STRUCTURAL),

        # DB EC2 -> DB Role (CAN_ASSUME)
        make_relationship(
            db_ec2_id, db_role_id, "CAN_ASSUME",
            properties={"via": "instance_profile"},
        ),

        # DB Role -> S3 Bucket (MAY_READ_S3_OBJECT)
        make_relationship(
            db_role_id, s3_bucket_id, "MAY_READ_S3_OBJECT",
            evidence=EdgeEvidence(
                permission="s3:GetObject",
                source_arn=f"arn:aws:iam::{account_id}:role/DatabaseBackupRole",
                target_arn="arn:aws:s3:::sensitive-data-bucket/*",
            ),
        ),
    ]

    expected_paths = [
        ExpectedPath(
            description="Lateral movement from web to database tier",
            entry_point_name="web-server",
            target_name="sensitive-data-bucket",
            min_hops=4,
            max_hops=6,
            key_edges=["CAN_REACH", "CAN_REACH", "CAN_ASSUME", "MAY_READ_S3_OBJECT"],
        ),
    ]

    return assets, relationships, expected_paths


# =============================================================================
# SCENARIO 6: No Attack Path (Secure Configuration)
# =============================================================================
def scenario_secure_no_paths() -> tuple[list[Asset], list[Relationship], list[ExpectedPath]]:
    """
    Secure configuration with no attack paths.

    This scenario has:
    - EC2 with public IP but restricted SG (only allows specific IP)
    - Roles with least privilege
    - No cross-role trust relationships

    Expected: 0 attack paths
    """
    account_id = "123456789012"
    vpc_id = "vpc-12345678"

    ec2_id = uuid.UUID("11111111-6666-1111-1111-111111111111")
    sg_id = uuid.UUID("22222222-6666-2222-2222-222222222222")
    role_id = uuid.UUID("33333333-6666-3333-3333-333333333333")
    admin_role_id = uuid.UUID("44444444-6666-4444-4444-444444444444")

    assets = [
        make_internet_asset(),

        # Security group with restricted access (corporate IP only)
        make_security_group(
            sg_id, "restricted-sg", vpc_id,
            ingress_rules=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "203.0.113.0/24", "Description": "Corporate VPN"}],
                "Ipv6Ranges": [],
                "UserIdGroupPairs": [],
            }],
        ),

        make_ec2_instance(
            ec2_id, "secure-instance",
            security_group_ids=[f"sg-{str(sg_id)[:17].replace('-', '')}"],
            has_public_ip=True,
        ),

        # Least privilege role
        make_iam_role(
            role_id, "ReadOnlyRole",
            account_id=account_id,
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::public-assets", "arn:aws:s3:::public-assets/*"],
                },
            ],
            trust_policy_principals=["ec2.amazonaws.com"],
        ),

        # Admin role with no trust from other roles
        make_iam_role(
            admin_role_id, "AdminRole",
            account_id=account_id,
            policy_statements=[
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
            # Only trusts specific admin users, not other roles
            trust_policy_principals=[f"arn:aws:iam::{account_id}:user/admin-user"],
            is_admin=True,
        ),
    ]

    relationships = [
        # No CAN_REACH from Internet (SG doesn't allow 0.0.0.0/0)

        # SG -> EC2 (structural only)
        make_relationship(sg_id, ec2_id, "ALLOWS_TRAFFIC_TO", edge_kind=EdgeKind.STRUCTURAL),

        # EC2 -> Role (but role has no path to admin)
        make_relationship(
            ec2_id, role_id, "CAN_ASSUME",
            properties={"via": "instance_profile"},
        ),

        # No edges from ReadOnlyRole to AdminRole
    ]

    # No expected attack paths
    expected_paths = []

    return assets, relationships, expected_paths


# =============================================================================
# ALL SCENARIOS
# =============================================================================
ALL_SCENARIOS = {
    "lambda_privesc": scenario_lambda_privesc,
    "role_chaining": scenario_role_chaining,
    "secrets_exfiltration": scenario_secrets_exfiltration,
    "cross_account_access": scenario_cross_account_access,
    "lateral_movement": scenario_lateral_movement,
    "secure_no_paths": scenario_secure_no_paths,
}


def get_scenario(name: str) -> tuple[list[Asset], list[Relationship], list[ExpectedPath]]:
    """Get a scenario by name."""
    if name not in ALL_SCENARIOS:
        raise ValueError(f"Unknown scenario: {name}. Available: {list(ALL_SCENARIOS.keys())}")
    return ALL_SCENARIOS[name]()


def get_all_scenarios() -> dict[str, tuple[list[Asset], list[Relationship], list[ExpectedPath]]]:
    """Get all scenarios."""
    return {name: func() for name, func in ALL_SCENARIOS.items()}
