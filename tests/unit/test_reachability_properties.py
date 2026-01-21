
from __future__ import annotations

import contextlib
import uuid
from typing import Any

import pytest
from hypothesis import given, strategies as st

from cyntrisec.aws.relationship_builder import RelationshipBuilder
from cyntrisec.core.schema import Asset, EdgeKind, INTERNET_ASSET_ID, Relationship

# Strategies for generating assets
def asset_id_strategy():
    return st.uuids()

def security_group_strategy():
    """Generate a security group with random ingress rules."""
    def gen_sg(draw):
        sg_id = str(uuid.uuid4())
        rules = []
        
        # 50% chance of open to world
        if draw(st.booleans()):
            rules.append({
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            })
            
        # 50% chance of specific CIDR
        if draw(st.booleans()):
             rules.append({
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
            })
            
        return Asset(
            id=uuid.UUID(sg_id),
            snapshot_id=uuid.uuid4(),
            asset_type="ec2:security-group",
            aws_resource_id=sg_id,
            name=f"sg-{sg_id[:8]}",
            properties={
                "ingress_rules": rules,
                "vpc_id": "vpc-123"
            }
        )
    return st.composite(gen_sg)()

def instance_strategy(sg_ids: list[str]):
    """Generate an EC2 instance attached to one of the SGs."""
    def gen_instance(draw):
        inst_id = str(uuid.uuid4())
        sg_id = draw(st.sampled_from(sg_ids)) if sg_ids else "sg-unknown"
        return Asset(
            id=uuid.UUID(inst_id),
            snapshot_id=uuid.uuid4(),
            asset_type="ec2:instance",
            aws_resource_id=inst_id,
            name=f"i-{inst_id[:8]}",
            properties={
                "security_groups": [sg_id],
                "vpc_id": "vpc-123"
            }
        )
    return st.composite(gen_instance)()


class TestReachabilityProperties:
    """Property 6: CAN_REACH Precondition Enforcement (Structural)."""

    def test_open_sg_creates_internet_edge(self):
        """Verify that open security groups create CAN_REACH edges from Internet."""
        snapshot_id = uuid.uuid4()
        
        # Create an open SG
        sg_id = str(uuid.uuid4())
        sg = Asset(
            id=uuid.UUID(sg_id),
            snapshot_id=snapshot_id,
            asset_type="ec2:security-group",
            aws_resource_id=sg_id,
            name="open-sg",
            properties={
                "ingress_rules": [{
                    "IpProtocol": "tcp",
                    "FromPort": 80, 
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            }
        )
        
        # Create an instance in that SG
        inst = Asset(
            id=uuid.uuid4(),
            snapshot_id=snapshot_id,
            asset_type="ec2:instance",
            aws_resource_id="i-1",
            name="web",
            properties={"security_groups": [sg_id]}
        )
        
        builder = RelationshipBuilder(snapshot_id)
        rels = builder.build([sg, inst])
        
        # Must have CAN_REACH from INTERNET_ASSET_ID to inst.id
        internet_edges = [
            r for r in rels 
            if r.source_asset_id == INTERNET_ASSET_ID 
            and r.target_asset_id == inst.id
            and r.relationship_type == "CAN_REACH"
        ]
        
        assert len(internet_edges) >= 1
        edge = internet_edges[0]
        assert edge.edge_kind == EdgeKind.CAPABILITY
        assert edge.properties["port_range"] == "80-80"

    def test_closed_sg_creates_no_internet_edge(self):
        """Verify that closed security groups do not create CAN_REACH edges from Internet."""
        snapshot_id = uuid.uuid4()
        
        # Create a closed SG (only internal CIDR)
        sg_id = str(uuid.uuid4())
        sg = Asset(
            id=uuid.UUID(sg_id),
            snapshot_id=snapshot_id,
            asset_type="ec2:security-group",
            aws_resource_id=sg_id,
            name="internal-sg",
            properties={
                "ingress_rules": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22, 
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
                }]
            }
        )
        
        inst = Asset(
            id=uuid.uuid4(),
            snapshot_id=snapshot_id,
            asset_type="ec2:instance",
            aws_resource_id="i-1",
            name="db",
            properties={"security_groups": [sg_id]}
        )
        
        builder = RelationshipBuilder(snapshot_id)
        rels = builder.build([sg, inst])
        
        internet_edges = [
            r for r in rels 
            if r.source_asset_id == INTERNET_ASSET_ID 
            and r.target_asset_id == inst.id
            and r.relationship_type == "CAN_REACH"
        ]
        
        assert len(internet_edges) == 0

    def test_lateral_sg_access(self):
        """Verify SG-to-SG rules create lateral CAN_REACH edges."""
        snapshot_id = uuid.uuid4()
        
        # Source SG
        src_sg_id = str(uuid.uuid4())
        src_sg = Asset(
            id=uuid.UUID(src_sg_id),
            snapshot_id=snapshot_id,
            asset_type="ec2:security-group",
            aws_resource_id=src_sg_id,
            name="app-sg",
            properties={}
        )
        
        # Target SG allowing Source SG
        tgt_sg_id = str(uuid.uuid4())
        tgt_sg = Asset(
            id=uuid.UUID(tgt_sg_id),
            snapshot_id=snapshot_id,
            asset_type="ec2:security-group",
            aws_resource_id=tgt_sg_id,
            name="db-sg",
            properties={
                "ingress_rules": [{
                    "IpProtocol": "tcp",
                    "FromPort": 5432, 
                    "ToPort": 5432,
                    "UserIdGroupPairs": [{"GroupId": src_sg_id}]
                }]
            }
        )
        
        # Instances
        src_inst = Asset(
            id=uuid.uuid4(),
            snapshot_id=snapshot_id,
            asset_type="ec2:instance",
            aws_resource_id="i-app",
            name="app",
            properties={"security_groups": [src_sg_id]}
        )
        
        tgt_inst = Asset(
            id=uuid.uuid4(),
            snapshot_id=snapshot_id,
            asset_type="ec2:instance",
            aws_resource_id="i-db",
            name="db",
            properties={"security_groups": [tgt_sg_id]}
        )
        
        builder = RelationshipBuilder(snapshot_id)
        rels = builder.build([src_sg, tgt_sg, src_inst, tgt_inst])
        
        # Should have CAN_REACH from src_sg to tgt_inst
        # Note: Current impl creates edge from Source SG Asset to Target Asset
        # (See relationship_builder.py line 630: source_asset_id=source_sg.id)
        
        lateral_edges = [
            r for r in rels 
            if r.source_asset_id == src_sg.id 
            and r.target_asset_id == tgt_inst.id
            and r.relationship_type == "CAN_REACH"
        ]
        
        assert len(lateral_edges) >= 1
        assert lateral_edges[0].properties["port_range"] == "5432-5432"

