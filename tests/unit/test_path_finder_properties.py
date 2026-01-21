
from __future__ import annotations

import uuid
import pytest
from cyntrisec.core.graph import AwsGraph, GraphBuilder
from cyntrisec.core.paths import PathFinder, AttackerState, NetworkIdentity, PathFinderConfig
from cyntrisec.core.schema import Asset, EdgeKind, INTERNET_ASSET_ID, Relationship

class TestPathFinderProperties:
    """Property verification for PathFinder logic (Tasks 7.6, 7.7)."""

    def test_capability_only_traversal(self):
        """
        Property 2: PathFinder MUST ONLY traverse edges with edge_kind=CAPABILITY.
        """
        snapshot_id = uuid.uuid4()
        
        # Create a graph with mixed edge kinds
        # Internet -> A (CAPABILITY)
        # A -> B (STRUCTURAL)
        # B -> C (CAPABILITY) -- unreachable if STRUCTURAL skipped
        # A -> C (CAPABILITY) -- reachable
        
        internet = Asset(
            id=INTERNET_ASSET_ID,
            snapshot_id=snapshot_id,
            asset_type="pseudo:internet",
            aws_resource_id="internet", 
            name="Internet",
            is_internet_facing=True
        )
        
        a = Asset(
            id=uuid.uuid4(), snapshot_id=snapshot_id, asset_type="ec2:instance",
            aws_resource_id="a", name="A", properties={"public_ip": "1.1.1.1"}
        )
        b = Asset(
            id=uuid.uuid4(), snapshot_id=snapshot_id, asset_type="ec2:security-group",
            aws_resource_id="b", name="B", properties={}
        )
        c = Asset(
            id=uuid.uuid4(), snapshot_id=snapshot_id, asset_type="rds:db-instance",
            aws_resource_id="c", name="C", properties={}
        )
        
        assets = [internet, a, b, c]
        rels = []
        
        # Internet -> A (CAPABILITY: CAN_REACH)
        rels.append(Relationship(
            snapshot_id=snapshot_id, source_asset_id=internet.id, target_asset_id=a.id,
            relationship_type="CAN_REACH", edge_kind=EdgeKind.CAPABILITY, properties={}
        ))
        
        # A -> B (STRUCTURAL: ALLOWS_TRAFFIC)
        rels.append(Relationship(
            snapshot_id=snapshot_id, source_asset_id=a.id, target_asset_id=b.id,
            relationship_type="ALLOWS_TRAFFIC", edge_kind=EdgeKind.STRUCTURAL, properties={}
        ))
        
        # B -> C (CAPABILITY: CAN_REACH)
        rels.append(Relationship(
            snapshot_id=snapshot_id, source_asset_id=b.id, target_asset_id=c.id,
            relationship_type="CAN_REACH", edge_kind=EdgeKind.CAPABILITY, properties={}
        ))
        
        # A -> C (CAPABILITY: MAY_ACCESS)
        rels.append(Relationship(
            snapshot_id=snapshot_id, source_asset_id=a.id, target_asset_id=c.id,
            relationship_type="MAY_ACCESS", edge_kind=EdgeKind.CAPABILITY, properties={}
        ))
        
        graph = GraphBuilder().build(assets=assets, relationships=rels)
        finder = PathFinder()
        paths = finder.find_paths(graph, snapshot_id)
        
        # We expect a path: Internet -> A -> C
        # We expect NO path: Internet -> A -> B -> C (because A->B is Structural)
        
        assert len(paths) >= 1
        for path in paths:
            path_assets = path.path_asset_ids
            # Ensure B is not in the path
            assert b.id not in path_assets, "Path traversed STRUCTURAL edge A->B"
            
            # Verify all edges used are CAPABILITY
            for i in range(len(path_assets) - 1):
                src = path_assets[i]
                dst = path_assets[i+1]
                # Find edge
                edges = [e for e in graph.edges_from(src) if e.target_asset_id == dst]
                assert any(e.edge_kind == EdgeKind.CAPABILITY for e in edges)

    def test_attacker_state_progression(self):
        """
        Property 7: Attacker State Progression.
        Verifies that state is correctly updated when traversing edges.
        """
        snapshot_id = uuid.uuid4()
        finder = PathFinder()
        
        # Initial State
        state = AttackerState(origin="internet")
        
        # Mock Graph/Assets
        inst_id = uuid.uuid4()
        inst = Asset(
            id=inst_id, snapshot_id=snapshot_id, asset_type="ec2:instance", 
            aws_resource_id="i-1", name="inst", 
            properties={"security_groups": ["sg-1"], "vpc_id": "vpc-1"}
        )
        
        role_id = uuid.uuid4()
        role = Asset(
            id=role_id, snapshot_id=snapshot_id, asset_type="iam:role",
            aws_resource_id="role-1", name="role", properties={}
        )
        
        graph = GraphBuilder().build(assets=[inst, role], relationships=[]) 
        
        # 1. Update state traversing to Instance (CAN_REACH)
        rel1 = Relationship(
            snapshot_id=snapshot_id, source_asset_id=uuid.uuid4(), target_asset_id=inst_id,
            relationship_type="CAN_REACH", edge_kind=EdgeKind.CAPABILITY, properties={}
        )
        
        new_state = finder._update_attacker_state(graph, rel1, inst_id, state)
        
        # Property: Moving to instance updates network identity
        assert new_state.network_identity.security_group_ids == ("sg-1",)
        assert new_state.network_identity.vpc_id == "vpc-1"
        assert str(inst_id) in new_state.compromised_assets
        
        # 2. Update state traversing to Role (CAN_ASSUME)
        rel2 = Relationship(
            snapshot_id=snapshot_id, source_asset_id=inst_id, target_asset_id=role_id,
            relationship_type="CAN_ASSUME", edge_kind=EdgeKind.CAPABILITY, properties={}
        )
        
        final_state = finder._update_attacker_state(graph, rel2, role_id, new_state)
        
        # Property: CAN_ASSUME adds to active principals
        assert str(role_id) in final_state.active_principals
        # Property: Network identity is preserved
        assert final_state.network_identity == new_state.network_identity

    def test_passrole_motif_validation(self):
        """
        Property 9: PassRole Motif Validation.
        Verifies that confidence is downgraded if execution capability is unverified.
        """
        snapshot_id = uuid.uuid4()
        
        # Scenario 1: Non-Admin User (Confidence should be MED)
        user1 = Asset(
            id=uuid.uuid4(), snapshot_id=snapshot_id, asset_type="iam:user",
            aws_resource_id="user-1", name="DevUser", properties={}
        )
        role = Asset(
            id=uuid.uuid4(), snapshot_id=snapshot_id, asset_type="iam:role",
            aws_resource_id="role-1", name="ServiceRole", properties={}
        )
        target = Asset(
            id=uuid.uuid4(), snapshot_id=snapshot_id, asset_type="s3:bucket",
            aws_resource_id="bucket-1", name="SecretBucket", properties={},
            is_sensitive_target=True
        )
        # Entry point needed or we just mock candidate
        internet = Asset(
            id=INTERNET_ASSET_ID, snapshot_id=snapshot_id, asset_type="pseudo:internet",
            aws_resource_id="internet", name="Internet", is_internet_facing=True
        )

        assets = [internet, user1, role, target]
        rels = []
        
        # Internet -> User (Assume compromised for test or reachable)
        # To make it a path, we need connectivity.
        rels.append(Relationship(
            snapshot_id=snapshot_id, source_asset_id=internet.id, target_asset_id=user1.id,
            relationship_type="CAN_REACH", edge_kind=EdgeKind.CAPABILITY, properties={}
        ))
        
        # User -> Role (CAN_PASS_TO)
        rels.append(Relationship(
            snapshot_id=snapshot_id, source_asset_id=user1.id, target_asset_id=role.id,
            relationship_type="CAN_PASS_TO", edge_kind=EdgeKind.CAPABILITY, properties={}
        ))
        
        # Role -> Target (MAY_READ)
        rels.append(Relationship(
            snapshot_id=snapshot_id, source_asset_id=role.id, target_asset_id=target.id,
            relationship_type="MAY_READ", edge_kind=EdgeKind.CAPABILITY, properties={}
        ))
        
        graph = GraphBuilder().build(assets=assets, relationships=rels)
        finder = PathFinder()
        
        # We expect path: Internet -> User -> Role -> Target
        paths = finder.find_paths(graph, snapshot_id)
        assert len(paths) >= 1
        path = paths[0]
        
        # Check Confidence
        # Should be MED because DevUser is not Admin
        assert path.confidence_level == "med", f"Expected 'med' confidence for non-admin user, got {path.confidence_level}"
        assert "execution permission" in path.confidence_reason
        
        # Scenario 2: Admin User (Confidence should be HIGH)
        user2 = Asset(
            id=uuid.uuid4(), snapshot_id=snapshot_id, asset_type="iam:user",
            aws_resource_id="user-2", name="AdminUser", properties={}
        )
        assets2 = [internet, user2, role, target]
        rels2 = [
            Relationship(
                snapshot_id=snapshot_id, source_asset_id=internet.id, target_asset_id=user2.id,
                relationship_type="CAN_REACH", edge_kind=EdgeKind.CAPABILITY, properties={}
            ),
             Relationship(
                snapshot_id=snapshot_id, source_asset_id=user2.id, target_asset_id=role.id,
                relationship_type="CAN_PASS_TO", edge_kind=EdgeKind.CAPABILITY, properties={}
            ),
             Relationship(
                snapshot_id=snapshot_id, source_asset_id=role.id, target_asset_id=target.id,
                relationship_type="MAY_READ", edge_kind=EdgeKind.CAPABILITY, properties={}
            )
        ]
        
        graph2 = GraphBuilder().build(assets=assets2, relationships=rels2)
        paths2 = finder.find_paths(graph2, snapshot_id)
        assert len(paths2) >= 1
        path2 = paths2[0]
        
        # Should be HIGH because AdminUser is Admin
        # Current logic checks "admin" in name
        assert path2.confidence_level == "high", f"Expected 'high' confidence for AdminUser, got {path2.confidence_level}"

    def test_risk_scoring_differentiation(self):
        """
        Property 10: Risk Scoring Differentiation.
        Verifies that paths with lighter edges (CAN_ASSUME) have higher risk scores 
        than paths with heavier edges (CAN_REACH) given same length/impact.
        """
        snapshot_id = uuid.uuid4()
        
        # Helper to create standard assets
        def make_graph(edge_type: str) -> tuple[AwsGraph, Asset]:
            internet = Asset(id=INTERNET_ASSET_ID, snapshot_id=snapshot_id, asset_type="pseudo:internet",
                            aws_resource_id="internet", name="Internet", is_internet_facing=True)
            a = Asset(id=uuid.uuid4(), snapshot_id=snapshot_id, asset_type="iam:user", 
                     aws_resource_id="user-1", name="User", properties={})
            target = Asset(id=uuid.uuid4(), snapshot_id=snapshot_id, asset_type="s3:bucket",
                          aws_resource_id="bucket-1", name="Target", properties={}, is_sensitive_target=True)
            
            rels = [
                Relationship(snapshot_id=snapshot_id, source_asset_id=internet.id, target_asset_id=a.id,
                            relationship_type="CAN_REACH", edge_kind=EdgeKind.CAPABILITY, properties={}),
                Relationship(snapshot_id=snapshot_id, source_asset_id=a.id, target_asset_id=target.id,
                            relationship_type=edge_type, edge_kind=EdgeKind.CAPABILITY, properties={})
            ]
            return GraphBuilder().build(assets=[internet, a, target], relationships=rels), target

        finder = PathFinder()

        # Path 1: User CAN_ASSUME TargetRole (Weight 0.1 -> Exploitability ~0.985)
        graph1, target1 = make_graph("CAN_ASSUME")
        paths1 = finder.find_paths(graph1, snapshot_id)
        assert len(paths1) > 0
        score1 = paths1[0].risk_score
        
        # Path 2: User CAN_REACH TargetInstance (Weight 0.5 -> Exploitability ~0.925)
        # Note: We use User->Target with CAN_REACH just for scoring test, ignoring network validities for now
        graph2, target2 = make_graph("CAN_REACH")
        paths2 = finder.find_paths(graph2, snapshot_id)
        assert len(paths2) > 0
        score2 = paths2[0].risk_score
        
        # Path 1 (PrivEsc) should be riskier than Path 2 (Network Pivot)
        assert score1 > score2, f"Expected higher risk for CAN_ASSUME ({score1}) than CAN_REACH ({score2})"

    def test_edge_kind_inference(self):
        """
        Property 11: Edge Kind Inference.
        Verifies that GraphBuilder infers correct edge_kind for legacy data (UNKNOWN input).
        """
        snapshot_id = uuid.uuid4()
        
        # Define legacy relationships (no edge_kind, defaulting to UNKNOWN)
        rels = [
            Relationship(snapshot_id=snapshot_id, source_asset_id=uuid.uuid4(), target_asset_id=uuid.uuid4(),
                        relationship_type="CONTAINS", properties={}),
            Relationship(snapshot_id=snapshot_id, source_asset_id=uuid.uuid4(), target_asset_id=uuid.uuid4(),
                        relationship_type="CAN_ASSUME", properties={}),
            Relationship(snapshot_id=snapshot_id, source_asset_id=uuid.uuid4(), target_asset_id=uuid.uuid4(),
                        relationship_type="RandomType", properties={}),
        ]
        
        # We need assets for them to be included in graph
        assets = []
        for r in rels:
            assets.append(Asset(id=r.source_asset_id, snapshot_id=snapshot_id, asset_type="misc", aws_resource_id=str(r.source_asset_id), name="src"))
            assets.append(Asset(id=r.target_asset_id, snapshot_id=snapshot_id, asset_type="misc", aws_resource_id=str(r.target_asset_id), name="tgt"))
            
        graph = GraphBuilder().build(assets=assets, relationships=rels)
        
        # Verify edge kinds
        edges = graph.all_relationships()
        
        contains = next(e for e in edges if e.relationship_type == "CONTAINS")
        assert contains.edge_kind == EdgeKind.STRUCTURAL
        
        can_assume = next(e for e in edges if e.relationship_type == "CAN_ASSUME")
        assert can_assume.edge_kind == EdgeKind.CAPABILITY
        
        random = next(e for e in edges if e.relationship_type == "RandomType")
        assert random.edge_kind == EdgeKind.UNKNOWN

    def test_include_unknown_flag(self):
        """
        Verifies behavior of include_unknown flag in PathFinder.
        """
        snapshot_id = uuid.uuid4()
        internet = Asset(id=INTERNET_ASSET_ID, snapshot_id=snapshot_id, asset_type="pseudo:internet",
                        aws_resource_id="internet", name="Internet", is_internet_facing=True)
        target = Asset(id=uuid.uuid4(), snapshot_id=snapshot_id, asset_type="s3:bucket",
                      aws_resource_id="bucket-1", name="Target", properties={}, is_sensitive_target=True)
        
        # Internet -> Target via UNKNOWN edge
        rel = Relationship(
            snapshot_id=snapshot_id, source_asset_id=internet.id, target_asset_id=target.id,
            relationship_type="CustomFlow", edge_kind=EdgeKind.UNKNOWN, properties={}
        )
        
        graph = GraphBuilder().build(assets=[internet, target], relationships=[rel])
        
        # Case 1: Default (False)
        finder = PathFinder()
        paths = finder.find_paths(graph, snapshot_id)
        assert len(paths) == 0, "Should not traverse UNKNOWN edge by default"
        
        # Case 2: Enabled (True)
        config = PathFinderConfig(include_unknown=True)
        finder_inclusive = PathFinder(config=config)
        paths_inclusive = finder_inclusive.find_paths(graph, snapshot_id)
        assert len(paths_inclusive) == 1, "Should traverse UNKNOWN edge when include_unknown=True"