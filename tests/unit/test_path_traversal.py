
from __future__ import annotations

import uuid
from decimal import Decimal

import pytest
from cyntrisec.core.graph import AwsGraph, GraphBuilder
from cyntrisec.core.paths import PathFinder, PathFinderConfig, AttackerState, NetworkIdentity
from cyntrisec.core.schema import Asset, EdgeKind, INTERNET_ASSET_ID, Relationship

class TestPathTraversal:
    """Verify PathFinder traversal logic with AttackerState."""

    def test_lateral_movement_via_sg(self):
        """
        Verify path: Instance1 -> SG1 -> Instance2
        Where Instance1 has SG1, and SG1 has CAN_REACH to Instance2.
        """
        snapshot_id = uuid.uuid4()
        
        # 1. Assets
        # SG1
        sg1_id = uuid.uuid4()
        sg1 = Asset(
            id=sg1_id,
            snapshot_id=snapshot_id,
            asset_type="ec2:security-group",
            aws_resource_id="sg-1",
            name="app-sg",
            properties={}
        )
        
        # Instance1 (compromised entry point) in SG1
        inst1_id = uuid.uuid4()
        inst1 = Asset(
            id=inst1_id,
            snapshot_id=snapshot_id,
            asset_type="ec2:instance",
            aws_resource_id="i-1",
            name="app-server",
            properties={
                "public_ip": "1.2.3.4", 
                "security_groups": ["sg-1"] # logical ID reference
            },
            is_internet_facing=True
        )
        
        # Instance2 (target)
        inst2_id = uuid.uuid4()
        inst2 = Asset(
            id=inst2_id,
            snapshot_id=snapshot_id,
            asset_type="ec2:instance",
            aws_resource_id="i-2",
            name="db-server",
            properties={"security_groups": ["sg-2"]},
            is_internet_facing=False
        )
        
        # Mark Instance2 as sensitive target for path finding
        # (This is usually done by BusinessLogic or implicit rules)
        # For this test, we might need to mock sensitive_targets or use a type that is sensitive
        # RDS is sensitive by default in _impact_score, but sensitive_targets() in Graph needs logic.
        # Let's use RDS type for target to be automatically sensitive? 
        # Actually graph.sensitive_targets() relies on logic.
        
        # Let's mock inst2 as sensitive by making it an RDS instance
        inst2.asset_type = "rds:db-instance"
        
        assets = [sg1, inst1, inst2]
        
        # 2. Relationships
        rels = []
        
        # USE_IDENTITY: Instance1 -> SG1
        rels.append(Relationship(
            snapshot_id=snapshot_id,
            source_asset_id=inst1_id,
            target_asset_id=sg1_id,
            relationship_type="USE_IDENTITY",
            edge_kind=EdgeKind.CAPABILITY,
            properties={}
        ))
        
        # CAN_REACH: SG1 -> Instance2
        rels.append(Relationship(
            snapshot_id=snapshot_id,
            source_asset_id=sg1_id,
            target_asset_id=inst2_id,
            relationship_type="CAN_REACH",
            edge_kind=EdgeKind.CAPABILITY,
            properties={"port_range": "3306-3306"}
        ))
        
        # Build Graph
        graph = GraphBuilder().build(assets=assets, relationships=rels)
        
        # 3. Find Paths
        finder = PathFinder()
        paths = finder.find_paths(graph, snapshot_id)
        
        # Should find path: Instance1 -> SG1 -> Instance2
        # Note: Instance1 is entry point because it has public IP (is_internet_facing)
        
        assert len(paths) >= 1
        path = paths[0]
        assert path.source_asset_id == inst1_id
        assert path.target_asset_id == inst2_id
        assert len(path.path_asset_ids) == 3 # Inst1, SG1, Inst2
        assert path.path_asset_ids == [inst1_id, sg1_id, inst2_id]
        
    def test_precondition_enforcement_fail(self):
        """
        Verify that CAN_REACH fails if attacker is not at the source SG.
        """
        snapshot_id = uuid.uuid4()
        
        # SG1
        sg1_id = uuid.uuid4()
        sg1 = Asset(
            id=sg1_id,
            snapshot_id=snapshot_id,
            asset_type="ec2:security-group",
            aws_resource_id="sg-1",
            name="app-sg",
            properties={}
        )
        
        # Instance1 in SG-Other (NOT SG1)
        inst1_id = uuid.uuid4()
        inst1 = Asset(
            id=inst1_id,
            snapshot_id=snapshot_id,
            asset_type="ec2:instance",
            aws_resource_id="i-1",
            name="app-server",
            properties={
                "public_ip": "1.2.3.4", 
                "security_groups": ["sg-other"]
            },
            is_internet_facing=True
        )
        
        # Instance2 (Target)
        inst2_id = uuid.uuid4()
        inst2 = Asset(
            id=inst2_id,
            snapshot_id=snapshot_id,
            asset_type="rds:db-instance",
            aws_resource_id="i-2",
            name="db-server",
            properties={}
        )
        
        # Relationships
        rels = []
        
        # USE_IDENTITY: Instance1 -> SG1 (This edge shouldn't exist ideally if not in SG, 
        # but let's say it exists explicitly or we try to traverse a jump)
        # Actually USE_IDENTITY is created by RelationshipBuilder based on membership.
        # So check: if we somehow reach SG1 without having it in identity?
        
        # Let's simulate: Instance1 -> InstanceJump -> SG1
        # InstanceJump has SG1. Instance1 has SG-Other.
        # Instance1 CAN_ASSUME Role -> InstanceJump ??? 
        # (Lateral movement usually requires network reachability first).
        
        # Let's simplify:
        # Connect Instance1 -> SG1 via a dummy relationship to force traversal attempt
        # But Instance1's identity does NOT contain sg-1.
        
        rels.append(Relationship(
            snapshot_id=snapshot_id,
            source_asset_id=inst1_id,
            target_asset_id=sg1_id,
            relationship_type="DUMMY_LINK",
            edge_kind=EdgeKind.CAPABILITY,
            properties={}
        ))
        
        # SG1 -> Instance2 (CAN_REACH)
        rels.append(Relationship(
            snapshot_id=snapshot_id,
            source_asset_id=sg1_id,
            target_asset_id=inst2_id,
            relationship_type="CAN_REACH",
            edge_kind=EdgeKind.CAPABILITY,
            properties={}
        ))
        
        graph = GraphBuilder().build(assets=[sg1, inst1, inst2], relationships=rels)
        
        finder = PathFinder()
        paths = finder.find_paths(graph, snapshot_id)
        
        # Should NOT find a path because traversing SG1 -> Instance2 (CAN_REACH)
        # requires the attacker to have SG1 in identity.
        # Instance1 has "sg-other", not "sg-1".
        # Even though we hopped to SG1 node via DUMMY_LINK using CAPABILITY,
        # _update_attacker_state for SG node doesn't update identity matching.
        # And DUMMY_LINK doesn't grant identity.
        
        # The precondition check on SG1 -> Instance2 should fail.
        
        assert len(paths) == 0

