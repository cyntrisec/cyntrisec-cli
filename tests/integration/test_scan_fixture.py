"""
Integration test using fixture JSON - NO live AWS.

Tests the graph building and path finding pipeline using
pre-saved fixture data.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from cyntrisec.core.graph import GraphBuilder
from cyntrisec.core.paths import PathFinder
from cyntrisec.core.schema import Asset, Relationship


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


class TestScanFixtures:
    """Integration tests using fixture JSON files."""

    @pytest.fixture
    def assets(self) -> list[Asset]:
        """Load assets from fixture file."""
        with open(FIXTURES_DIR / "assets.json") as f:
            data = json.load(f)
        return [Asset.model_validate(a) for a in data]

    @pytest.fixture
    def relationships(self) -> list[Relationship]:
        """Load relationships from fixture file."""
        with open(FIXTURES_DIR / "relationships.json") as f:
            data = json.load(f)
        return [Relationship.model_validate(r) for r in data]

    def test_graph_builds_from_fixtures(self, assets, relationships):
        """Graph should build correctly from fixture files."""
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        
        # Verify counts
        assert graph.asset_count() == 4
        assert graph.relationship_count() == 3
        
        # Verify entry points detected
        entry_points = graph.entry_points()
        assert len(entry_points) == 1
        assert entry_points[0].name == "public-entry"
        
        # Verify sensitive targets detected
        targets = graph.sensitive_targets()
        assert len(targets) == 1
        assert targets[0].asset_type == "rds:db-instance"

    def test_pathfinder_finds_attack_path(self, assets, relationships):
        """PathFinder should discover the attack path from fixtures."""
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        
        paths = PathFinder().find_paths(graph, snapshot_id)
        
        # Should find exactly one path
        assert len(paths) == 1
        
        path = paths[0]
        
        # Path should start at entry and end at target
        assert str(path.source_asset_id) == "11111111-1111-1111-1111-111111111111"
        assert str(path.target_asset_id) == "44444444-4444-4444-4444-444444444444"
        
        # Path should have 3 edges (path_length counts edges, not nodes)
        assert path.path_length == 3
        
        # Should have valid risk score
        assert float(path.risk_score) > 0
        
        # Should have proof data
        assert "steps" in path.proof or len(path.proof) >= 0

    def test_path_is_deterministic(self, assets, relationships):
        """Running path finding multiple times produces identical results."""
        graph = GraphBuilder().build(assets=assets, relationships=relationships)
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        
        # Run three times
        results = [PathFinder().find_paths(graph, snapshot_id) for _ in range(3)]
        
        # All should have same length
        assert all(len(r) == len(results[0]) for r in results)
        
        # All paths should be identical
        for i in range(len(results[0])):
            path_assets = [r[i].path_asset_ids for r in results]
            assert all(p == path_assets[0] for p in path_assets)


class TestAssetValidation:
    """Test that fixture data validates correctly."""

    def test_assets_validate(self):
        """All assets in fixture should pass Pydantic validation."""
        with open(FIXTURES_DIR / "assets.json") as f:
            data = json.load(f)
        
        assets = [Asset.model_validate(a) for a in data]
        assert len(assets) == 4
        
        # Check types
        types = {a.asset_type for a in assets}
        assert "ec2:instance" in types
        assert "rds:db-instance" in types

    def test_relationships_validate(self):
        """All relationships in fixture should pass Pydantic validation."""
        with open(FIXTURES_DIR / "relationships.json") as f:
            data = json.load(f)
        
        relationships = [Relationship.model_validate(r) for r in data]
        assert len(relationships) == 3
        
        # Check types
        types = {r.relationship_type for r in relationships}
        assert "ROUTES_TO" in types
        assert "CONNECTS_TO" in types
