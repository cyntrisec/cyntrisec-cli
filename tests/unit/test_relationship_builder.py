"""
Unit tests for RelationshipBuilder.
"""
from __future__ import annotations

import uuid
import pytest
from uuid import UUID

from cyntrisec.core.schema import Asset, Relationship
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
        
        assert len(rels) == 1
        rel = rels[0]
        assert rel.source_asset_id == sg_id
        assert rel.target_asset_id == instance_id
        assert rel.relationship_type == "ALLOWS_TRAFFIC_TO"
        assert rel.properties["open_to_world"] is True

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
        assert rels[0].source_asset_id == subnet_id
        assert rels[0].target_asset_id == instance_id

    def test_instance_profile_to_role(self, builder, snapshot_id):
        """Test Instance -> Role (via profile) relationship."""
        role_id = UUID("44444444-4444-4444-4444-444444444444")
        instance_id = UUID("22222222-2222-2222-2222-222222222222")
        
        role = make_asset(
            snapshot_id, role_id, "iam:role", "Ec2Role"
        )
        instance = make_asset(
            snapshot_id, instance_id, "ec2:instance", "web",
            properties={
                "iam_instance_profile": "arn:aws:iam::123456789012:instance-profile/Ec2Role"
            }
        )
        
        rels = builder.build([role, instance])
        
        assert len(rels) == 1
        assert rels[0].relationship_type == "CAN_ASSUME"
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
        
        assert len(rels) == 1
        assert rels[0].relationship_type == "USES"
        assert rels[0].source_asset_id == lb_id
        assert rels[0].target_asset_id == sg_id

    def test_role_to_sensitive_target(self, builder, snapshot_id):
        """Test Role -> Sensitive Target (MAY_ACCESS)."""
        role_id = UUID("44444444-4444-4444-4444-444444444444")
        instance_id = UUID("22222222-2222-2222-2222-222222222222")
        target_id = UUID("77777777-7777-7777-7777-777777777777")
        
        role = make_asset(snapshot_id, role_id, "iam:role", "ComputeRole")
        instance = make_asset(
            snapshot_id, instance_id, "ec2:instance", "web",
            properties={
                "iam_instance_profile": "arn:aws:iam::123:instance-profile/ComputeRole"
            }
        )
        target = make_asset(
            snapshot_id, target_id, "s3:bucket", "secrets",
            is_sensitive=True
        )
        
        rels = builder.build([role, instance, target])
        
        # Expect:
        # 1. Instance -> Role (CAN_ASSUME)
        # 2. Role -> Target (MAY_ACCESS)
        
        assert len(rels) == 2
        types = {r.relationship_type for r in rels}
        assert "CAN_ASSUME" in types
        assert "MAY_ACCESS" in types
        
        may_access = next(r for r in rels if r.relationship_type == "MAY_ACCESS")
        assert may_access.source_asset_id == role_id
        assert may_access.target_asset_id == target_id
