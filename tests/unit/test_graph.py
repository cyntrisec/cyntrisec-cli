"""
Unit tests for GraphBuilder and AwsGraph.

Tests:
1. GraphBuilder correctly builds graph from assets/relationships
2. AwsGraph lookups (neighbors, predecessors, by type)
3. Entry point and sensitive target detection
4. Edge cases (empty graph, missing relationships)
"""
from __future__ import annotations

import uuid

import pytest

from cyntrisec.core.graph import AwsGraph, GraphBuilder
from cyntrisec.core.schema import Asset, Relationship


def make_asset(
    snapshot_id: uuid.UUID,
    asset_id: uuid.UUID,
    asset_type: str,
    name: str,
    *,
    is_internet_facing: bool = False,
    is_sensitive_target: bool = False,
    properties: dict = None,
) -> Asset:
    """Helper to create test assets."""
    return Asset(
        id=asset_id,
        snapshot_id=snapshot_id,
        asset_type=asset_type,
        aws_resource_id=str(asset_id),
        name=name,
        is_internet_facing=is_internet_facing,
        is_sensitive_target=is_sensitive_target,
        properties=properties or {},
    )


def make_relationship(
    snapshot_id: uuid.UUID,
    rel_id: uuid.UUID,
    source_id: uuid.UUID,
    target_id: uuid.UUID,
    rel_type: str = "CONNECTS_TO",
) -> Relationship:
    """Helper to create test relationships."""
    return Relationship(
        id=rel_id,
        snapshot_id=snapshot_id,
        source_asset_id=source_id,
        target_asset_id=target_id,
        relationship_type=rel_type,
    )


class TestGraphBuilder:
    """Test GraphBuilder.build()."""

    def test_builds_empty_graph(self):
        """Empty assets and relationships should create empty graph."""
        builder = GraphBuilder()
        graph = builder.build(assets=[], relationships=[])
        
        assert graph.asset_count() == 0
        assert graph.relationship_count() == 0

    def test_builds_graph_with_assets(self):
        """Assets without relationships should all be present."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        id2 = uuid.UUID("22222222-2222-2222-2222-222222222222")
        
        assets = [
            make_asset(snapshot_id, id1, "ec2:instance", "web"),
            make_asset(snapshot_id, id2, "ec2:instance", "app"),
        ]
        
        builder = GraphBuilder()
        graph = builder.build(assets=assets, relationships=[])
        
        assert graph.asset_count() == 2
        assert graph.asset(id1) is not None
        assert graph.asset(id2) is not None
        assert graph.relationship_count() == 0

    def test_builds_graph_with_relationships(self):
        """Relationships should be indexed for lookups."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        id2 = uuid.UUID("22222222-2222-2222-2222-222222222222")
        rel_id = uuid.UUID("aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        
        assets = [
            make_asset(snapshot_id, id1, "ec2:instance", "web"),
            make_asset(snapshot_id, id2, "rds:db-instance", "db"),
        ]
        relationships = [
            make_relationship(snapshot_id, rel_id, id1, id2, "CONNECTS_TO"),
        ]
        
        builder = GraphBuilder()
        graph = builder.build(assets=assets, relationships=relationships)
        
        assert graph.relationship_count() == 1
        assert id2 in graph.neighbors(id1)
        assert id1 in graph.predecessors(id2)

    def test_skips_orphan_relationships(self):
        """Relationships with missing asset IDs should be ignored."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        missing_id = uuid.UUID("99999999-9999-9999-9999-999999999999")
        rel_id = uuid.UUID("aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        
        assets = [
            make_asset(snapshot_id, id1, "ec2:instance", "web"),
        ]
        relationships = [
            make_relationship(snapshot_id, rel_id, id1, missing_id),
        ]
        
        builder = GraphBuilder()
        graph = builder.build(assets=assets, relationships=relationships)
        
        # Relationship should be skipped
        assert graph.relationship_count() == 0


class TestAwsGraphLookups:
    """Test AwsGraph lookup methods."""

    @pytest.fixture
    def sample_graph(self):
        """Create a sample graph for testing."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        ids = [uuid.UUID(f"{i:08x}-0000-0000-0000-000000000000") for i in range(1, 5)]
        
        assets = [
            make_asset(snapshot_id, ids[0], "ec2:instance", "web", is_internet_facing=True),
            make_asset(snapshot_id, ids[1], "ec2:instance", "app"),
            make_asset(snapshot_id, ids[2], "rds:db-instance", "db", is_sensitive_target=True),
            make_asset(snapshot_id, ids[3], "s3:bucket", "logs"),
        ]
        
        rel_ids = [uuid.UUID(f"aaaa000{i}-0000-0000-0000-000000000000") for i in range(1, 4)]
        relationships = [
            make_relationship(snapshot_id, rel_ids[0], ids[0], ids[1]),
            make_relationship(snapshot_id, rel_ids[1], ids[1], ids[2]),
            make_relationship(snapshot_id, rel_ids[2], ids[1], ids[3]),
        ]
        
        return GraphBuilder().build(assets=assets, relationships=relationships), ids

    def test_neighbors(self, sample_graph):
        """neighbors() returns correct outgoing edges."""
        graph, ids = sample_graph
        
        # id1 (app) has 2 outgoing edges
        neighbors = graph.neighbors(ids[1])
        assert len(neighbors) == 2
        assert ids[2] in neighbors  # db
        assert ids[3] in neighbors  # logs

    def test_predecessors(self, sample_graph):
        """predecessors() returns correct incoming edges."""
        graph, ids = sample_graph
        
        # id2 (db) has 1 incoming edge from id1 (app)
        preds = graph.predecessors(ids[2])
        assert len(preds) == 1
        assert ids[1] in preds

    def test_assets_by_type(self, sample_graph):
        """assets_by_type() filters correctly."""
        graph, ids = sample_graph
        
        ec2_assets = graph.assets_by_type("ec2:instance")
        assert len(ec2_assets) == 2
        
        rds_assets = graph.assets_by_type("rds:db-instance")
        assert len(rds_assets) == 1

    def test_all_assets(self, sample_graph):
        """all_assets() returns all assets."""
        graph, ids = sample_graph
        
        all_assets = graph.all_assets()
        assert len(all_assets) == 4

    def test_all_relationships(self, sample_graph):
        """all_relationships() returns all edges."""
        graph, ids = sample_graph
        
        all_rels = graph.all_relationships()
        assert len(all_rels) == 3


class TestAwsGraphEntryPoints:
    """Test entry point detection."""

    def test_detects_internet_facing_flag(self):
        """Assets with is_internet_facing=True are entry points."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        
        assets = [
            make_asset(snapshot_id, id1, "ec2:instance", "web", is_internet_facing=True),
        ]
        
        graph = GraphBuilder().build(assets=assets, relationships=[])
        entries = graph.entry_points()
        
        assert len(entries) == 1
        assert entries[0].id == id1

    def test_detects_elb_internet_facing(self):
        """Load balancers with internet-facing scheme are entry points."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        
        assets = [
            make_asset(
                snapshot_id, id1, "elbv2:load-balancer", "alb",
                properties={"scheme": "internet-facing"},
            ),
        ]
        
        graph = GraphBuilder().build(assets=assets, relationships=[])
        entries = graph.entry_points()
        
        assert len(entries) == 1


class TestAwsGraphSensitiveTargets:
    """Test sensitive target detection."""

    def test_detects_sensitive_flag(self):
        """Assets with is_sensitive_target=True are targets."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        
        assets = [
            make_asset(snapshot_id, id1, "s3:bucket", "secrets", is_sensitive_target=True),
        ]
        
        graph = GraphBuilder().build(assets=assets, relationships=[])
        targets = graph.sensitive_targets()
        
        assert len(targets) == 1

    def test_detects_rds_as_sensitive(self):
        """RDS instances are automatically sensitive."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        
        assets = [
            make_asset(snapshot_id, id1, "rds:db-instance", "prod-db"),
        ]
        
        graph = GraphBuilder().build(assets=assets, relationships=[])
        targets = graph.sensitive_targets()
        
        assert len(targets) == 1

    def test_detects_admin_role_as_sensitive(self):
        """IAM roles with 'admin' in name are sensitive."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        
        assets = [
            make_asset(snapshot_id, id1, "iam:role", "AdminRole"),
        ]
        
        graph = GraphBuilder().build(assets=assets, relationships=[])
        targets = graph.sensitive_targets()
        
        assert len(targets) == 1
