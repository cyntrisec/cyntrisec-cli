"""
Unit tests for RelationshipBuilder.
"""
from __future__ import annotations

import uuid
import pytest
from uuid import UUID

from cyntrisec.core.schema import Asset, EdgeKind, Relationship
from cyntrisec.aws.relationship_builder import RelationshipBuilder


def make_asset(
    snapshot_id: UUID,
    asset_id: UUID,
    asset_type: str,
    name: str,
    properties: dict = None,
    is_sensitive: bool = False,
    arn: str = None,
) -> Asset:
    return Asset(
        id=asset_id,
        snapshot_id=snapshot_id,
        asset_type=asset_type,
        aws_resource_id=str(asset_id),
        name=name,
        is_sensitive_target=is_sensitive,
        properties=properties or {},
        arn=arn,
    )


class TestRelationshipBuilder:
    
    @pytest.fixture
    def snapshot_id(self):
        return UUID("00000000-0000-0000-0000-000000000000")

    @pytest.fixture
    def builder(self, snapshot_id):
        return RelationshipBuilder(snapshot_id)

    def test_sg_to_instance(self, builder, snapshot_id):
        """Test Security Group -> Instance relationship."""
        sg_id = UUID("11111111-1111-1111-1111-111111111111")
        instance_id = UUID("22222222-2222-2222-2222-222222222222")
        
        sg = make_asset(
            snapshot_id, sg_id, "ec2:security-group", "sg-1",
            properties={
                "ingress_rules": [
                    {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ]
            }
        )
        instance = make_asset(
            snapshot_id, instance_id, "ec2:instance", "web",
            properties={"security_groups": [str(sg_id)]}
        )
        
        rels = builder.build([sg, instance])
        
        rels = builder.build([sg, instance])
        
        # Expect 3 relationships:
        # 1. SG -> Instance (ALLOWS_TRAFFIC_TO)
        # 2. Internet -> Instance (CAN_REACH) - due to 0.0.0.0/0 rule
        # 3. Instance -> SG (USE_IDENTITY)
        assert len(rels) == 3
        
        allows = next(r for r in rels if r.relationship_type == "ALLOWS_TRAFFIC_TO")
        assert allows.source_asset_id == sg_id
        assert allows.target_asset_id == instance_id
        assert allows.edge_kind == EdgeKind.STRUCTURAL
        assert allows.properties["open_to_world"] is True
        
        use_identity = next(r for r in rels if r.relationship_type == "USE_IDENTITY")
        assert use_identity.source_asset_id == instance_id
        assert use_identity.target_asset_id == sg_id
        
        can_reach = next(r for r in rels if r.relationship_type == "CAN_REACH")
        assert can_reach.target_asset_id == instance_id
        # source is internet, but we don't have internet asset id in this scope easily unless imported
        # but we know it's not sg or instance.

    def test_subnet_to_instance(self, builder, snapshot_id):
        """Test Subnet -> Instance relationship."""
        subnet_id = UUID("33333333-3333-3333-3333-333333333333")
        instance_id = UUID("22222222-2222-2222-2222-222222222222")
        
        subnet = make_asset(
            snapshot_id, subnet_id, "ec2:subnet", "subnet-1"
        )
        instance = make_asset(
            snapshot_id, instance_id, "ec2:instance", "web",
            properties={"subnet_id": str(subnet_id)}
        )
        
        rels = builder.build([subnet, instance])
        
        assert len(rels) == 1
        assert rels[0].relationship_type == "CONTAINS"
        assert rels[0].edge_kind == EdgeKind.STRUCTURAL
        assert rels[0].source_asset_id == subnet_id
        assert rels[0].target_asset_id == instance_id

    def test_instance_profile_to_role(self, builder, snapshot_id):
        """Test Instance -> Role (via profile) relationship."""
        role_id = UUID("44444444-4444-4444-4444-444444444444")
        instance_id = UUID("22222222-2222-2222-2222-222222222222")
        profile_arn = "arn:aws:iam::123456789012:instance-profile/Ec2RoleProfile"
        role_arn = "arn:aws:iam::123456789012:role/Ec2Role"

        role = make_asset(
            snapshot_id, role_id, "iam:role", "Ec2Role", arn=role_arn
        )
        profile = make_asset(
            snapshot_id,
            UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "iam:instance-profile",
            "Ec2RoleProfile",
            properties={"role_arns": [role_arn]},
            arn=profile_arn,
        )
        instance = make_asset(
            snapshot_id, instance_id, "ec2:instance", "web",
            properties={
                "iam_instance_profile": profile_arn
            }
        )
        
        rels = builder.build([role, profile, instance])
        
        assert len(rels) == 1
        assert rels[0].relationship_type == "CAN_ASSUME"
        assert rels[0].edge_kind == EdgeKind.CAPABILITY
        assert rels[0].source_asset_id == instance_id
        assert rels[0].target_asset_id == role_id
        assert rels[0].properties["via"] == "instance_profile"

    def test_lambda_to_role(self, builder, snapshot_id):
        """Test Lambda -> Role relationship."""
        role_id = UUID("44444444-4444-4444-4444-444444444444")
        func_id = UUID("55555555-5555-5555-5555-555555555555")
        role_arn = "arn:aws:iam::123456789012:role/LambdaRole"
        
        role = make_asset(
            snapshot_id, role_id, "iam:role", "LambdaRole",
            arn=role_arn
        )
        func = make_asset(
            snapshot_id, func_id, "lambda:function", "my-func",
            properties={"role": role_arn}
        )
        
        rels = builder.build([role, func])
        
        assert len(rels) == 1
        rel = rels[0]
        assert rel.relationship_type == "CAN_ASSUME"
        assert rel.edge_kind == EdgeKind.CAPABILITY
        assert rel.source_asset_id == func_id
        assert rel.target_asset_id == role_id
        assert rel.properties["via"] == "execution_role"

    def test_load_balancer_to_sg(self, builder, snapshot_id):
        """Test ALB -> SG relationship."""
        sg_id = UUID("11111111-1111-1111-1111-111111111111")
        lb_id = UUID("66666666-6666-6666-6666-666666666666")
        
        sg = make_asset(snapshot_id, sg_id, "ec2:security-group", "sg-1")
        lb = make_asset(
            snapshot_id, lb_id, "elbv2:load-balancer", "alb",
            properties={"security_groups": [str(sg_id)]}
        )
        
        rels = builder.build([sg, lb])
        
        # Expect 2 relationships: USES (Structural) + USE_IDENTITY (Capability)
        assert len(rels) == 2
        
        uses = next(r for r in rels if r.relationship_type == "USES")
        assert uses.edge_kind == EdgeKind.STRUCTURAL
        assert uses.source_asset_id == lb_id
        assert uses.target_asset_id == sg_id
        
        use_identity = next(r for r in rels if r.relationship_type == "USE_IDENTITY")
        assert use_identity.edge_kind == EdgeKind.CAPABILITY
        assert use_identity.source_asset_id == lb_id
        assert use_identity.target_asset_id == sg_id

    def test_role_to_sensitive_target(self, builder, snapshot_id):
        """Test Role -> Sensitive Target with action-specific edges (MAY_READ_S3_OBJECT)."""
        role_id = UUID("44444444-4444-4444-4444-444444444444")
        instance_id = UUID("22222222-2222-2222-2222-222222222222")
        target_id = UUID("77777777-7777-7777-7777-777777777777")
        profile_arn = "arn:aws:iam::123:instance-profile/ComputeRole"
        role_arn = "arn:aws:iam::123:role/ComputeRole"
        bucket_arn = "arn:aws:s3:::secrets"
        statement = {
            "Sid": "AllowS3Read",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::secrets*",  # Wildcard to match bucket ARN
        }
        role = make_asset(
            snapshot_id,
            role_id,
            "iam:role",
            "ComputeRole",
            arn=role_arn,
            properties={
                "policy_documents": [
                    {
                        "PolicyArn": "arn:aws:iam::123:policy/S3ReadPolicy",
                        "Statement": [statement]
                    }
                ]
            },
        )
        profile = make_asset(
            snapshot_id,
            UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "iam:instance-profile",
            "ComputeRole",
            properties={"role_arns": [role_arn]},
            arn=profile_arn,
        )
        instance = make_asset(
            snapshot_id, instance_id, "ec2:instance", "web",
            properties={
                "iam_instance_profile": profile_arn
            }
        )
        target = make_asset(
            snapshot_id, target_id, "s3:bucket", "secrets",
            is_sensitive=True,
            arn=bucket_arn,
        )
        
        rels = builder.build([role, profile, instance, target])
        
        # Expect:
        # 1. Instance -> Role (CAN_ASSUME)
        # 2. Role -> Target (MAY_READ_S3_OBJECT) - action-specific edge with evidence
        
        assert len(rels) == 2
        types = {r.relationship_type for r in rels}
        assert "CAN_ASSUME" in types
        assert "MAY_READ_S3_OBJECT" in types
        
        may_read = next(r for r in rels if r.relationship_type == "MAY_READ_S3_OBJECT")
        assert may_read.source_asset_id == role_id
        assert may_read.target_asset_id == target_id
        assert may_read.edge_kind == EdgeKind.CAPABILITY
        assert may_read.properties["action"] == "s3:GetObject"
        
        # Verify evidence is included
        assert may_read.evidence is not None
        assert may_read.evidence.policy_sid == "AllowS3Read"
        assert may_read.evidence.policy_arn == "arn:aws:iam::123:policy/S3ReadPolicy"
        assert may_read.evidence.source_arn == role_arn
        assert may_read.evidence.target_arn == bucket_arn
        assert may_read.evidence.permission == "s3:GetObject"
        assert may_read.evidence.raw_statement == statement

    def test_role_to_secret_target(self, builder, snapshot_id):
        """Test Role -> Secret with MAY_READ_SECRET edge."""
        role_id = UUID("44444444-4444-4444-4444-444444444444")
        instance_id = UUID("22222222-2222-2222-2222-222222222222")
        target_id = UUID("77777777-7777-7777-7777-777777777777")
        profile_arn = "arn:aws:iam::123:instance-profile/ComputeRole"
        role_arn = "arn:aws:iam::123:role/ComputeRole"
        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret"
        
        role = make_asset(
            snapshot_id,
            role_id,
            "iam:role",
            "ComputeRole",
            arn=role_arn,
            properties={
                "policy_documents": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "secretsmanager:GetSecretValue",
                                "Resource": secret_arn,
                            }
                        ]
                    }
                ]
            },
        )
        profile = make_asset(
            snapshot_id,
            UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "iam:instance-profile",
            "ComputeRole",
            properties={"role_arns": [role_arn]},
            arn=profile_arn,
        )
        instance = make_asset(
            snapshot_id, instance_id, "ec2:instance", "web",
            properties={
                "iam_instance_profile": profile_arn
            }
        )
        target = make_asset(
            snapshot_id, target_id, "secretsmanager:secret", "my-secret",
            is_sensitive=True,
            arn=secret_arn,
        )
        
        rels = builder.build([role, profile, instance, target])
        
        types = {r.relationship_type for r in rels}
        assert "CAN_ASSUME" in types
        assert "MAY_READ_SECRET" in types
        
        may_read = next(r for r in rels if r.relationship_type == "MAY_READ_SECRET")
        assert may_read.source_asset_id == role_id
        assert may_read.target_asset_id == target_id
        assert may_read.edge_kind == EdgeKind.CAPABILITY

    def test_role_to_kms_key(self, builder, snapshot_id):
        """Test Role -> KMS Key with MAY_DECRYPT edge."""
        role_id = UUID("44444444-4444-4444-4444-444444444444")
        instance_id = UUID("22222222-2222-2222-2222-222222222222")
        target_id = UUID("77777777-7777-7777-7777-777777777777")
        profile_arn = "arn:aws:iam::123:instance-profile/ComputeRole"
        role_arn = "arn:aws:iam::123:role/ComputeRole"
        key_arn = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        
        role = make_asset(
            snapshot_id,
            role_id,
            "iam:role",
            "ComputeRole",
            arn=role_arn,
            properties={
                "policy_documents": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "kms:Decrypt",
                                "Resource": key_arn,
                            }
                        ]
                    }
                ]
            },
        )
        profile = make_asset(
            snapshot_id,
            UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "iam:instance-profile",
            "ComputeRole",
            properties={"role_arns": [role_arn]},
            arn=profile_arn,
        )
        instance = make_asset(
            snapshot_id, instance_id, "ec2:instance", "web",
            properties={
                "iam_instance_profile": profile_arn
            }
        )
        target = make_asset(
            snapshot_id, target_id, "kms:key", "my-key",
            is_sensitive=True,
            arn=key_arn,
        )
        
        rels = builder.build([role, profile, instance, target])
        
        types = {r.relationship_type for r in rels}
        assert "CAN_ASSUME" in types
        assert "MAY_DECRYPT" in types
        
        may_decrypt = next(r for r in rels if r.relationship_type == "MAY_DECRYPT")
        assert may_decrypt.source_asset_id == role_id
        assert may_decrypt.target_asset_id == target_id
        assert may_decrypt.edge_kind == EdgeKind.CAPABILITY

    def test_role_to_ssm_parameter(self, builder, snapshot_id):
        """Test Role -> SSM Parameter with MAY_READ_PARAMETER edge."""
        role_id = UUID("44444444-4444-4444-4444-444444444444")
        instance_id = UUID("22222222-2222-2222-2222-222222222222")
        target_id = UUID("77777777-7777-7777-7777-777777777777")
        profile_arn = "arn:aws:iam::123:instance-profile/ComputeRole"
        role_arn = "arn:aws:iam::123:role/ComputeRole"
        param_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/my-param"
        
        role = make_asset(
            snapshot_id,
            role_id,
            "iam:role",
            "ComputeRole",
            arn=role_arn,
            properties={
                "policy_documents": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "ssm:GetParameter",
                                "Resource": param_arn,
                            }
                        ]
                    }
                ]
            },
        )
        profile = make_asset(
            snapshot_id,
            UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "iam:instance-profile",
            "ComputeRole",
            properties={"role_arns": [role_arn]},
            arn=profile_arn,
        )
        instance = make_asset(
            snapshot_id, instance_id, "ec2:instance", "web",
            properties={
                "iam_instance_profile": profile_arn
            }
        )
        target = make_asset(
            snapshot_id, target_id, "ssm:parameter", "my-param",
            is_sensitive=True,
            arn=param_arn,
        )
        
        rels = builder.build([role, profile, instance, target])
        
        types = {r.relationship_type for r in rels}
        assert "CAN_ASSUME" in types
        assert "MAY_READ_PARAMETER" in types
        
        may_read = next(r for r in rels if r.relationship_type == "MAY_READ_PARAMETER")
        assert may_read.source_asset_id == role_id
        assert may_read.target_asset_id == target_id
        assert may_read.edge_kind == EdgeKind.CAPABILITY

    def test_pass_role_with_evidence(self, builder, snapshot_id):
        """Test CAN_PASS_TO edge includes evidence."""
        source_role_id = UUID("44444444-4444-4444-4444-444444444444")
        target_role_id = UUID("55555555-5555-5555-5555-555555555555")
        source_role_arn = "arn:aws:iam::123456789012:role/SourceRole"
        target_role_arn = "arn:aws:iam::123456789012:role/TargetRole"
        
        statement = {
            "Sid": "AllowPassRole",
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": target_role_arn,
        }
        
        source_role = make_asset(
            snapshot_id,
            source_role_id,
            "iam:role",
            "SourceRole",
            arn=source_role_arn,
            properties={
                "policy_documents": [
                    {
                        "PolicyArn": "arn:aws:iam::123456789012:policy/PassRolePolicy",
                        "Statement": [statement]
                    }
                ]
            },
        )
        target_role = make_asset(
            snapshot_id,
            target_role_id,
            "iam:role",
            "TargetRole",
            arn=target_role_arn,
        )
        
        rels = builder.build([source_role, target_role])
        
        assert len(rels) == 1
        rel = rels[0]
        assert rel.relationship_type == "CAN_PASS_TO"
        assert rel.edge_kind == EdgeKind.CAPABILITY
        assert rel.source_asset_id == source_role_id
        assert rel.target_asset_id == target_role_id
        
        # Verify evidence is included
        assert rel.evidence is not None
        assert rel.evidence.policy_sid == "AllowPassRole"
        assert rel.evidence.policy_arn == "arn:aws:iam::123456789012:policy/PassRolePolicy"
        assert rel.evidence.source_arn == source_role_arn
        assert rel.evidence.target_arn == target_role_arn
        assert rel.evidence.permission == "iam:PassRole"
        assert rel.evidence.raw_statement == statement

    def test_may_create_lambda_edge(self, builder, snapshot_id):
        """Test MAY_CREATE_LAMBDA edge creation for lambda:CreateFunction permission."""
        role_id = UUID("44444444-4444-4444-4444-444444444444")
        role_arn = "arn:aws:iam::123456789012:role/LambdaCreatorRole"
        lambda_service_id = UUID("00000000-0000-0000-0000-00000000000a")
        
        statement = {
            "Sid": "AllowLambdaCreate",
            "Effect": "Allow",
            "Action": "lambda:CreateFunction",
            "Resource": "*",
        }
        
        role = make_asset(
            snapshot_id,
            role_id,
            "iam:role",
            "LambdaCreatorRole",
            arn=role_arn,
            properties={
                "policy_documents": [
                    {
                        "PolicyArn": "arn:aws:iam::123456789012:policy/LambdaCreatePolicy",
                        "Statement": [statement]
                    }
                ]
            },
        )
        
        rels = builder.build([role])
        
        # Should have one MAY_CREATE_LAMBDA edge
        assert len(rels) == 1
        rel = rels[0]
        assert rel.relationship_type == "MAY_CREATE_LAMBDA"
        assert rel.edge_kind == EdgeKind.CAPABILITY
        assert rel.source_asset_id == role_id
        assert rel.target_asset_id == lambda_service_id
        
        # Verify evidence
        assert rel.evidence is not None
        assert rel.evidence.policy_sid == "AllowLambdaCreate"
        assert rel.evidence.permission == "lambda:CreateFunction"
        assert rel.evidence.raw_statement == statement

    def test_may_create_lambda_edge_update_config(self, builder, snapshot_id):
        """Test MAY_CREATE_LAMBDA edge creation for lambda:UpdateFunctionConfiguration permission."""
        role_id = UUID("44444444-4444-4444-4444-444444444444")
        role_arn = "arn:aws:iam::123456789012:role/LambdaUpdaterRole"
        lambda_service_id = UUID("00000000-0000-0000-0000-00000000000a")
        
        statement = {
            "Sid": "AllowLambdaUpdate",
            "Effect": "Allow",
            "Action": "lambda:UpdateFunctionConfiguration",
            "Resource": "*",
        }
        
        role = make_asset(
            snapshot_id,
            role_id,
            "iam:role",
            "LambdaUpdaterRole",
            arn=role_arn,
            properties={
                "policy_documents": [
                    {
                        "PolicyArn": "arn:aws:iam::123456789012:policy/LambdaUpdatePolicy",
                        "Statement": [statement]
                    }
                ]
            },
        )
        
        rels = builder.build([role])
        
        # Should have one MAY_CREATE_LAMBDA edge
        assert len(rels) == 1
        rel = rels[0]
        assert rel.relationship_type == "MAY_CREATE_LAMBDA"
        assert rel.edge_kind == EdgeKind.CAPABILITY
        assert rel.evidence.permission == "lambda:UpdateFunctionConfiguration"

    def test_may_create_lambda_wildcard_action(self, builder, snapshot_id):
        """Test MAY_CREATE_LAMBDA edge creation with wildcard action lambda:*."""
        role_id = UUID("44444444-4444-4444-4444-444444444444")
        role_arn = "arn:aws:iam::123456789012:role/LambdaAdminRole"
        lambda_service_id = UUID("00000000-0000-0000-0000-00000000000a")
        
        role = make_asset(
            snapshot_id,
            role_id,
            "iam:role",
            "LambdaAdminRole",
            arn=role_arn,
            properties={
                "policy_documents": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "lambda:*",
                                "Resource": "*",
                            }
                        ]
                    }
                ]
            },
        )
        
        rels = builder.build([role])
        
        # Should have one MAY_CREATE_LAMBDA edge (wildcard matches CreateFunction)
        assert len(rels) == 1
        rel = rels[0]
        assert rel.relationship_type == "MAY_CREATE_LAMBDA"
        assert rel.edge_kind == EdgeKind.CAPABILITY

    def test_role_to_role_assume_with_trust(self, builder, snapshot_id):
        """Test Role -> Role CAN_ASSUME edge via sts:AssumeRole + trust policy."""
        source_role_id = UUID("44444444-4444-4444-4444-444444444444")
        target_role_id = UUID("55555555-5555-5555-5555-555555555555")
        source_role_arn = "arn:aws:iam::123456789012:role/SourceRole"
        target_role_arn = "arn:aws:iam::123456789012:role/TargetRole"

        statement = {
            "Sid": "AllowAssumeRole",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": target_role_arn,
        }

        source_role = make_asset(
            snapshot_id,
            source_role_id,
            "iam:role",
            "SourceRole",
            arn=source_role_arn,
            properties={
                "policy_documents": [
                    {
                        "PolicyArn": "arn:aws:iam::123456789012:policy/AssumeRolePolicy",
                        "Statement": [statement]
                    }
                ]
            },
        )
        target_role = make_asset(
            snapshot_id,
            target_role_id,
            "iam:role",
            "TargetRole",
            arn=target_role_arn,
            properties={
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": source_role_arn},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                }
            },
        )

        rels = builder.build([source_role, target_role])

        assert len(rels) == 1
        rel = rels[0]
        assert rel.relationship_type == "CAN_ASSUME"
        assert rel.edge_kind == EdgeKind.CAPABILITY
        assert rel.source_asset_id == source_role_id
        assert rel.target_asset_id == target_role_id
        assert rel.properties["via"] == "sts_assume_role"

        # Verify evidence
        assert rel.evidence is not None
        assert rel.evidence.policy_sid == "AllowAssumeRole"
        assert rel.evidence.permission == "sts:AssumeRole"
        assert rel.evidence.source_arn == source_role_arn
        assert rel.evidence.target_arn == target_role_arn

    def test_role_to_role_assume_no_trust(self, builder, snapshot_id):
        """Test Role -> Role CAN_ASSUME edge NOT created when trust policy doesn't allow."""
        source_role_id = UUID("44444444-4444-4444-4444-444444444444")
        target_role_id = UUID("55555555-5555-5555-5555-555555555555")
        source_role_arn = "arn:aws:iam::123456789012:role/SourceRole"
        target_role_arn = "arn:aws:iam::123456789012:role/TargetRole"

        source_role = make_asset(
            snapshot_id,
            source_role_id,
            "iam:role",
            "SourceRole",
            arn=source_role_arn,
            properties={
                "policy_documents": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Resource": target_role_arn,
                            }
                        ]
                    }
                ]
            },
        )
        target_role = make_asset(
            snapshot_id,
            target_role_id,
            "iam:role",
            "TargetRole",
            arn=target_role_arn,
            properties={
                # Trust policy allows a DIFFERENT role, not source
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789012:role/OtherRole"},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                }
            },
        )

        rels = builder.build([source_role, target_role])

        # Should NOT create CAN_ASSUME edge because trust policy doesn't allow source
        assert len(rels) == 0

    def test_role_to_role_assume_account_trust(self, builder, snapshot_id):
        """Test Role -> Role CAN_ASSUME edge with account-level trust."""
        source_role_id = UUID("44444444-4444-4444-4444-444444444444")
        target_role_id = UUID("55555555-5555-5555-5555-555555555555")
        source_role_arn = "arn:aws:iam::123456789012:role/SourceRole"
        target_role_arn = "arn:aws:iam::123456789012:role/TargetRole"

        source_role = make_asset(
            snapshot_id,
            source_role_id,
            "iam:role",
            "SourceRole",
            arn=source_role_arn,
            properties={
                "policy_documents": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Resource": target_role_arn,
                            }
                        ]
                    }
                ]
            },
        )
        target_role = make_asset(
            snapshot_id,
            target_role_id,
            "iam:role",
            "TargetRole",
            arn=target_role_arn,
            properties={
                # Trust policy allows entire account (root)
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                }
            },
        )

        rels = builder.build([source_role, target_role])

        # Should create CAN_ASSUME edge because account-level trust allows any role in account
        assert len(rels) == 1
        assert rels[0].relationship_type == "CAN_ASSUME"
        assert rels[0].properties["via"] == "sts_assume_role"

    def test_role_to_role_assume_wildcard_resource(self, builder, snapshot_id):
        """Test Role -> Role CAN_ASSUME edge with wildcard resource."""
        source_role_id = UUID("44444444-4444-4444-4444-444444444444")
        target_role_id = UUID("55555555-5555-5555-5555-555555555555")
        source_role_arn = "arn:aws:iam::123456789012:role/SourceRole"
        target_role_arn = "arn:aws:iam::123456789012:role/TargetRole"

        source_role = make_asset(
            snapshot_id,
            source_role_id,
            "iam:role",
            "SourceRole",
            arn=source_role_arn,
            properties={
                "policy_documents": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Resource": "*",  # Wildcard - can assume any role
                            }
                        ]
                    }
                ]
            },
        )
        target_role = make_asset(
            snapshot_id,
            target_role_id,
            "iam:role",
            "TargetRole",
            arn=target_role_arn,
            properties={
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": source_role_arn},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                }
            },
        )

        rels = builder.build([source_role, target_role])

        assert len(rels) == 1
        assert rels[0].relationship_type == "CAN_ASSUME"
