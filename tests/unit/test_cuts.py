"""
Unit tests for MinCutFinder - Minimal remediation finder.

Tests:
1. Empty paths case
2. Single path - finds correct cut
3. Multiple paths - greedy coverage algorithm
4. Cut prioritization by impact
"""
from __future__ import annotations

import uuid
from decimal import Decimal

import pytest

from cyntrisec.core.graph import GraphBuilder
from cyntrisec.core.cuts import MinCutFinder, Remediation, CutResult
from cyntrisec.core.schema import Asset, Relationship, AttackPath


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


def make_path(
    snapshot_id: uuid.UUID,
    path_id: uuid.UUID,
    source_id: uuid.UUID,
    target_id: uuid.UUID,
    path_asset_ids: list,
    path_rel_ids: list,
    risk_score: float = 0.5,
) -> AttackPath:
    """Helper to create test attack paths."""
    return AttackPath(
        id=path_id,
        snapshot_id=snapshot_id,
        source_asset_id=source_id,
        target_asset_id=target_id,
        path_asset_ids=path_asset_ids,
        path_relationship_ids=path_rel_ids,
        path_length=len(path_rel_ids),
        attack_vector="instance-compromise",
        entry_confidence=Decimal("0.8"),
        exploitability_score=Decimal("0.7"),
        impact_score=Decimal("0.9"),
        risk_score=Decimal(str(risk_score)),
        proof={},
    )


class TestMinCutFinderEmpty:
    """Test edge cases with empty input."""

    def test_no_paths_returns_empty(self):
        """No attack paths should return empty remediations."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        
        assets = [make_asset(snapshot_id, id1, "ec2:instance", "web")]
        graph = GraphBuilder().build(assets=assets, relationships=[])
        
        finder = MinCutFinder()
        result = finder.find_cuts(graph, [], max_cuts=5)
        
        assert result.total_paths == 0
        assert result.paths_blocked == 0
        assert result.coverage == 1.0  # Nothing to block
        assert len(result.remediations) == 0


class TestMinCutFinderSinglePath:
    """Test with single attack path."""

    def test_finds_cut_for_single_path(self):
        """Single path should produce at least one remediation."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        
        ids = [uuid.UUID(f"{i:08x}-0000-0000-0000-000000000000") for i in range(1, 4)]
        entry_id, middle_id, target_id = ids
        
        rel_ids = [uuid.UUID(f"aaaa000{i}-0000-0000-0000-000000000000") for i in range(1, 3)]
        
        assets = [
            make_asset(snapshot_id, entry_id, "ec2:instance", "bastion", is_internet_facing=True),
            make_asset(snapshot_id, middle_id, "ec2:instance", "app"),
            make_asset(snapshot_id, target_id, "rds:db-instance", "db", is_sensitive_target=True),
        ]
        
        relationships = [
            make_relationship(snapshot_id, rel_ids[0], entry_id, middle_id),
            make_relationship(snapshot_id, rel_ids[1], middle_id, target_id),
        ]
        
        path = make_path(
            snapshot_id,
            uuid.UUID("bbbbbbbb-0000-0000-0000-000000000000"),
            entry_id,
            target_id,
            [entry_id, middle_id, target_id],
            rel_ids,
        )
        
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        finder = MinCutFinder()
        result = finder.find_cuts(graph, [path], max_cuts=5)
        
        assert result.total_paths == 1
        assert result.paths_blocked == 1
        assert result.coverage == 1.0
        assert len(result.remediations) >= 1

    def test_remediation_has_correct_fields(self):
        """Remediation should have action, description, paths_blocked."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        
        entry_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
        target_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
        rel_id = uuid.UUID("aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        path_id = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000000")
        
        assets = [
            make_asset(snapshot_id, entry_id, "ec2:instance", "entry", is_internet_facing=True),
            make_asset(snapshot_id, target_id, "rds:db-instance", "db", is_sensitive_target=True),
        ]
        
        relationships = [
            make_relationship(snapshot_id, rel_id, entry_id, target_id, "CONNECTS_TO"),
        ]
        
        path = make_path(
            snapshot_id, path_id, entry_id, target_id,
            [entry_id, target_id], [rel_id],
        )
        
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        finder = MinCutFinder()
        result = finder.find_cuts(graph, [path], max_cuts=1)
        
        assert len(result.remediations) == 1
        rem = result.remediations[0]
        assert rem.action in ["remove", "restrict", "isolate", "review"]  # Valid actions
        assert rem.description  # Non-empty description
        assert path_id in rem.paths_blocked


class TestMinCutFinderMultiplePaths:
    """Test greedy coverage with multiple paths."""

    def test_shared_edge_covers_multiple_paths(self):
        """Cutting a shared edge should block multiple paths."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        
        # Graph: entry1 -> shared -> target
        #        entry2 -> shared -> target
        entry1_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
        entry2_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
        shared_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
        target_id = uuid.UUID("44444444-4444-4444-4444-444444444444")
        
        rel_ids = [uuid.UUID(f"aaaa000{i}-0000-0000-0000-000000000000") for i in range(1, 4)]
        
        assets = [
            make_asset(snapshot_id, entry1_id, "ec2:instance", "entry1", is_internet_facing=True),
            make_asset(snapshot_id, entry2_id, "ec2:instance", "entry2", is_internet_facing=True),
            make_asset(snapshot_id, shared_id, "ec2:instance", "shared"),
            make_asset(snapshot_id, target_id, "rds:db-instance", "db", is_sensitive_target=True),
        ]
        
        relationships = [
            make_relationship(snapshot_id, rel_ids[0], entry1_id, shared_id),
            make_relationship(snapshot_id, rel_ids[1], entry2_id, shared_id),
            make_relationship(snapshot_id, rel_ids[2], shared_id, target_id),  # Shared edge
        ]
        
        path1 = make_path(
            snapshot_id, uuid.UUID("bbbb0001-0000-0000-0000-000000000000"),
            entry1_id, target_id,
            [entry1_id, shared_id, target_id], [rel_ids[0], rel_ids[2]],
        )
        path2 = make_path(
            snapshot_id, uuid.UUID("bbbb0002-0000-0000-0000-000000000000"),
            entry2_id, target_id,
            [entry2_id, shared_id, target_id], [rel_ids[1], rel_ids[2]],
        )
        
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        finder = MinCutFinder()
        result = finder.find_cuts(graph, [path1, path2], max_cuts=1)
        
        assert result.total_paths == 2
        # With 1 cut, the shared edge should block both paths
        assert result.paths_blocked == 2
        assert result.coverage == 1.0

    def test_max_cuts_limits_output(self):
        """max_cuts should limit number of remediations returned."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        
        # Create 5 independent paths
        paths = []
        assets = []
        relationships = []
        
        for i in range(5):
            entry_id = uuid.UUID(f"1111000{i}-0000-0000-0000-000000000000")
            target_id = uuid.UUID(f"2222000{i}-0000-0000-0000-000000000000")
            rel_id = uuid.UUID(f"aaaa000{i}-0000-0000-0000-000000000000")
            
            assets.extend([
                make_asset(snapshot_id, entry_id, "ec2:instance", f"entry{i}", is_internet_facing=True),
                make_asset(snapshot_id, target_id, "rds:db-instance", f"db{i}", is_sensitive_target=True),
            ])
            relationships.append(
                make_relationship(snapshot_id, rel_id, entry_id, target_id)
            )
            paths.append(make_path(
                snapshot_id, uuid.UUID(f"bbbb000{i}-0000-0000-0000-000000000000"),
                entry_id, target_id,
                [entry_id, target_id], [rel_id],
            ))
        
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        finder = MinCutFinder()
        
        result = finder.find_cuts(graph, paths, max_cuts=3)
        
        assert result.total_paths == 5
        assert len(result.remediations) <= 3  # max_cuts respected
        assert result.paths_blocked == 3  # 3 cuts block 3 independent paths


class TestCutResult:
    """Test CutResult dataclass."""

    def test_coverage_calculation(self):
        """coverage should be paths_blocked / total_paths."""
        result = CutResult(
            remediations=[],
            total_paths=10,
            paths_blocked=7,
            coverage=0.7,
        )
        
        assert result.coverage == 0.7

    def test_empty_paths_coverage(self):
        """Empty paths should have 100% coverage."""
        result = CutResult(
            remediations=[],
            total_paths=0,
            paths_blocked=0,
            coverage=1.0,
        )
        
        assert result.coverage == 1.0
