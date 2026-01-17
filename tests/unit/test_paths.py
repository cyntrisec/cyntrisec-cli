"""
Unit tests for PathFinder - Attack path discovery.

Tests:
1. Determinism - Same graph produces same paths in same order
2. Simple path - Entry -> Target finds expected path
3. No paths - Graph with no entry points returns empty
"""
from __future__ import annotations

import uuid
from decimal import Decimal

import pytest

from cyntrisec.core.graph import AwsGraph, GraphBuilder
from cyntrisec.core.paths import PathFinder, PathFinderConfig
from cyntrisec.core.schema import Asset, Relationship


def make_asset(
    snapshot_id: uuid.UUID,
    asset_id: uuid.UUID,
    asset_type: str,
    name: str,
    *,
    is_internet_facing: bool = False,
    is_sensitive_target: bool = False,
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


class TestPathFinderDeterminism:
    """Test that PathFinder produces deterministic results."""

    def test_same_graph_produces_same_paths(self):
        """Running path finding twice on same graph yields identical results."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        
        # Create fixed UUIDs for determinism
        entry_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
        middle_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
        target_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
        rel1_id = uuid.UUID("aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        rel2_id = uuid.UUID("aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        
        assets = [
            make_asset(snapshot_id, entry_id, "ec2:instance", "entry", is_internet_facing=True),
            make_asset(snapshot_id, middle_id, "ec2:instance", "middle"),
            make_asset(snapshot_id, target_id, "rds:db-instance", "database", is_sensitive_target=True),
        ]
        
        relationships = [
            make_relationship(snapshot_id, rel1_id, entry_id, middle_id),
            make_relationship(snapshot_id, rel2_id, middle_id, target_id),
        ]
        
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        finder = PathFinder()
        
        # Run twice
        paths1 = finder.find_paths(graph, snapshot_id)
        paths2 = finder.find_paths(graph, snapshot_id)
        
        # Should have same number of paths
        assert len(paths1) == len(paths2)
        assert len(paths1) > 0, "Should find at least one path"
        
        # Path order and content should be identical
        for p1, p2 in zip(paths1, paths2):
            assert p1.path_asset_ids == p2.path_asset_ids
            assert p1.risk_score == p2.risk_score
            assert p1.attack_vector == p2.attack_vector


class TestPathFinderSimplePath:
    """Test that PathFinder finds expected paths."""

    def test_finds_direct_path(self):
        """Entry point directly connected to target should produce a path."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
        
        entry_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
        target_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
        rel_id = uuid.UUID("aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        
        assets = [
            make_asset(snapshot_id, entry_id, "elbv2:load-balancer", "alb", is_internet_facing=True),
            make_asset(snapshot_id, target_id, "rds:db-instance", "prod-db", is_sensitive_target=True),
        ]
        
        relationships = [
            make_relationship(snapshot_id, rel_id, entry_id, target_id, "ROUTES_TO"),
        ]
        
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        finder = PathFinder()
        
        paths = finder.find_paths(graph, snapshot_id)
        
        assert len(paths) == 1
        path = paths[0]
        assert path.path_length == 1  # 1 edge connecting 2 nodes
        assert path.path_asset_ids == [entry_id, target_id]
        assert path.source_asset_id == entry_id
        assert path.target_asset_id == target_id
        assert float(path.risk_score) > 0

    def test_finds_multi_hop_path(self):
        """Path through multiple nodes should be discovered."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000002")
        
        # Fixed UUIDs
        ids = [uuid.UUID(f"{i:08x}-0000-0000-0000-000000000000") for i in range(1, 5)]
        entry_id, hop1_id, hop2_id, target_id = ids
        
        assets = [
            make_asset(snapshot_id, entry_id, "ec2:instance", "bastion", is_internet_facing=True),
            make_asset(snapshot_id, hop1_id, "ec2:instance", "app-server"),
            make_asset(snapshot_id, hop2_id, "lambda:function", "data-processor"),
            make_asset(snapshot_id, target_id, "secretsmanager:secret", "db-creds", is_sensitive_target=True),
        ]
        
        rel_ids = [uuid.UUID(f"aaaa000{i}-0000-0000-0000-000000000000") for i in range(1, 4)]
        relationships = [
            make_relationship(snapshot_id, rel_ids[0], entry_id, hop1_id),
            make_relationship(snapshot_id, rel_ids[1], hop1_id, hop2_id),
            make_relationship(snapshot_id, rel_ids[2], hop2_id, target_id),
        ]
        
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        finder = PathFinder()
        
        paths = finder.find_paths(graph, snapshot_id)
        
        assert len(paths) >= 1
        path = paths[0]
        assert path.path_length == 3  # 3 edges connecting 4 nodes
        assert path.source_asset_id == entry_id
        assert path.target_asset_id == target_id


class TestPathFinderNoPaths:
    """Test edge cases where no paths should be found."""

    def test_no_entry_points_returns_empty(self):
        """Graph with no internet-facing assets should return no paths."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000003")
        
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        id2 = uuid.UUID("22222222-2222-2222-2222-222222222222")
        rel_id = uuid.UUID("aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        
        assets = [
            make_asset(snapshot_id, id1, "ec2:instance", "internal-1"),  # Not internet facing
            make_asset(snapshot_id, id2, "rds:db-instance", "db", is_sensitive_target=True),
        ]
        
        relationships = [
            make_relationship(snapshot_id, rel_id, id1, id2),
        ]
        
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        finder = PathFinder()
        
        paths = finder.find_paths(graph, snapshot_id)
        
        assert len(paths) == 0

    def test_no_targets_returns_empty(self):
        """Graph with no sensitive targets should return no paths."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000004")
        
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        id2 = uuid.UUID("22222222-2222-2222-2222-222222222222")
        rel_id = uuid.UUID("aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        
        assets = [
            make_asset(snapshot_id, id1, "ec2:instance", "bastion", is_internet_facing=True),
            make_asset(snapshot_id, id2, "ec2:instance", "app"),  # Not sensitive
        ]
        
        relationships = [
            make_relationship(snapshot_id, rel_id, id1, id2),
        ]
        
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        finder = PathFinder()
        
        paths = finder.find_paths(graph, snapshot_id)
        
        assert len(paths) == 0

    def test_disconnected_graph_returns_empty(self):
        """Entry and target not connected should return no paths."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000005")
        
        entry_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
        target_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
        
        assets = [
            make_asset(snapshot_id, entry_id, "ec2:instance", "bastion", is_internet_facing=True),
            make_asset(snapshot_id, target_id, "rds:db-instance", "db", is_sensitive_target=True),
        ]
        
        # No relationships - disconnected graph
        graph = GraphBuilder().build(assets=assets, relationships=[])
        finder = PathFinder()
        
        paths = finder.find_paths(graph, snapshot_id)
        
        assert len(paths) == 0
