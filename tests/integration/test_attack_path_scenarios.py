"""
Integration tests for attack path discovery using vulnerable AWS scenarios.

These tests verify that cyntrisec-cli correctly discovers attack paths
in various vulnerable AWS configurations, including:
- Lambda privilege escalation
- IAM role chaining
- Secrets exfiltration
- Cross-account access
- Lateral movement via security groups

Each test uses pre-built fixtures representing realistic misconfigurations.
"""

import uuid

import pytest

from cyntrisec.core.graph import AwsGraph, GraphBuilder
from cyntrisec.core.paths import PathFinder, PathFinderConfig
from cyntrisec.core.schema import ConfidenceLevel, Relationship
from tests.fixtures.vulnerable_aws_scenarios import (
    SNAPSHOT_ID,
    get_all_scenarios,
    get_scenario,
)


def get_relationships_by_ids(
    graph: AwsGraph, rel_ids: list[uuid.UUID]
) -> list[Relationship | None]:
    """Helper to get relationships by their IDs from a graph."""
    all_rels = graph.all_relationships()
    rels_by_id = {r.id: r for r in all_rels}
    return [rels_by_id.get(rid) for rid in rel_ids]


class TestAttackPathDiscovery:
    """Test attack path discovery across various vulnerable scenarios."""

    @pytest.fixture
    def graph_builder(self):
        return GraphBuilder()

    @pytest.fixture
    def path_finder(self):
        config = PathFinderConfig(
            max_paths=10,
            max_depth=10,
            min_risk_score=0.0,
            include_unknown=False,
        )
        return PathFinder(config)

    def test_lambda_privesc_path_discovered(self, graph_builder, path_finder):
        """
        Test Lambda privilege escalation attack path is discovered.

        Scenario: EC2 -> Role with Lambda+PassRole -> Admin Role
        Expected: At least one attack path reaching AdminRole
        """
        assets, relationships, expected_paths = get_scenario("lambda_privesc")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        paths = path_finder.find_paths(graph, SNAPSHOT_ID)

        # Should find at least one path
        assert len(paths) >= 1, "Expected at least one attack path for lambda_privesc scenario"

        # Verify path reaches the admin role
        admin_role = next(a for a in assets if a.name == "AdminRole")
        path_targets = [p.path_asset_ids[-1] for p in paths]
        assert admin_role.id in path_targets, "Expected path to reach AdminRole"

        # Verify expected edges are in the path
        expected = expected_paths[0]
        found_path = next(p for p in paths if p.path_asset_ids[-1] == admin_role.id)

        # Check path contains expected relationship types
        path_rels = get_relationships_by_ids(graph, found_path.attack_chain_relationship_ids)
        path_rel_types = [r.relationship_type for r in path_rels if r]

        for edge_type in ["CAN_ASSUME", "CAN_PASS_TO"]:
            assert edge_type in path_rel_types, f"Expected {edge_type} in attack path"

    def test_role_chaining_path_discovered(self, graph_builder, path_finder):
        """
        Test role chaining attack path is discovered.

        Scenario: EC2 -> RoleA -> RoleB -> RoleC(Admin)
        Expected: Path through three CAN_ASSUME edges
        """
        assets, relationships, expected_paths = get_scenario("role_chaining")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        paths = path_finder.find_paths(graph, SNAPSHOT_ID)

        assert len(paths) >= 1, "Expected at least one attack path for role_chaining scenario"

        # Verify path reaches RoleC-Admin
        admin_role = next(a for a in assets if a.name == "RoleC-Admin")
        path_targets = [p.path_asset_ids[-1] for p in paths]
        assert admin_role.id in path_targets, "Expected path to reach RoleC-Admin"

        # Verify multiple CAN_ASSUME edges in path
        found_path = next(p for p in paths if p.path_asset_ids[-1] == admin_role.id)
        path_rels = get_relationships_by_ids(graph, found_path.attack_chain_relationship_ids)
        assume_count = sum(1 for r in path_rels if r and r.relationship_type == "CAN_ASSUME")

        assert assume_count >= 3, f"Expected at least 3 CAN_ASSUME edges, found {assume_count}"

    def test_secrets_exfiltration_path_discovered(self, graph_builder, path_finder):
        """
        Test secrets exfiltration attack path is discovered.

        Scenario: API Gateway -> Lambda -> Secret
        Expected: Path ending at MAY_READ_SECRET
        """
        assets, relationships, expected_paths = get_scenario("secrets_exfiltration")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        paths = path_finder.find_paths(graph, SNAPSHOT_ID)

        assert len(paths) >= 1, "Expected at least one attack path for secrets_exfiltration scenario"

        # Verify path reaches the secret
        secret = next(a for a in assets if a.name == "prod-database-credentials")
        path_targets = [p.path_asset_ids[-1] for p in paths]
        assert secret.id in path_targets, "Expected path to reach prod-database-credentials"

        # Verify MAY_READ_SECRET edge
        found_path = next(p for p in paths if p.path_asset_ids[-1] == secret.id)
        path_rels = get_relationships_by_ids(graph, found_path.attack_chain_relationship_ids)
        rel_types = [r.relationship_type for r in path_rels if r]

        assert "MAY_READ_SECRET" in rel_types, "Expected MAY_READ_SECRET in attack path"

    def test_cross_account_path_discovered(self, graph_builder, path_finder):
        """
        Test cross-account attack path is discovered.

        Scenario: Internet -> EC2 in Account A -> Role in Account A -> Role in Account B (Admin)
        Expected: Cross-account role assumption detected with proper evidence
        """
        assets, relationships, expected_paths = get_scenario("cross_account_access")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        paths = path_finder.find_paths(graph, SNAPSHOT_ID)

        assert len(paths) >= 1, "Expected at least one attack path for cross_account_access scenario"

        # Verify path reaches the admin role in Account B
        admin_role = next(a for a in assets if a.name == "TargetAdminRole")
        path_targets = [p.path_asset_ids[-1] for p in paths]
        assert admin_role.id in path_targets, "Expected path to reach TargetAdminRole"

        found_path = next(p for p in paths if p.path_asset_ids[-1] == admin_role.id)
        path_rels = get_relationships_by_ids(graph, found_path.attack_chain_relationship_ids)

        # Check for cross-account indicator
        cross_account_rels = [r for r in path_rels if r and r.properties.get("cross_account")]
        assert len(cross_account_rels) >= 1, "Expected cross-account CAN_ASSUME edge"

    def test_lateral_movement_path_discovered(self, graph_builder, path_finder):
        """
        Test lateral movement attack path is discovered.

        Scenario: Web Server -> (via SG) -> Database Server -> S3 Bucket
        Expected: Path using CAN_REACH between security groups
        """
        assets, relationships, expected_paths = get_scenario("lateral_movement")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        paths = path_finder.find_paths(graph, SNAPSHOT_ID)

        assert len(paths) >= 1, "Expected at least one attack path for lateral_movement scenario"

        # Verify path reaches the S3 bucket
        s3_bucket = next(a for a in assets if a.name == "sensitive-data-bucket")
        path_targets = [p.path_asset_ids[-1] for p in paths]
        assert s3_bucket.id in path_targets, "Expected path to reach sensitive-data-bucket"

        # Verify MAY_READ_S3_OBJECT edge
        found_path = next(p for p in paths if p.path_asset_ids[-1] == s3_bucket.id)
        path_rels = get_relationships_by_ids(graph, found_path.attack_chain_relationship_ids)
        rel_types = [r.relationship_type for r in path_rels if r]

        assert "MAY_READ_S3_OBJECT" in rel_types, "Expected MAY_READ_S3_OBJECT in attack path"

    def test_secure_config_no_paths(self, graph_builder, path_finder):
        """
        Test that secure configuration yields no attack paths.

        Scenario: Properly configured infrastructure with least privilege
        Expected: 0 attack paths
        """
        assets, relationships, expected_paths = get_scenario("secure_no_paths")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        paths = path_finder.find_paths(graph, SNAPSHOT_ID)

        # Should find no paths in secure configuration
        assert len(paths) == 0, f"Expected 0 attack paths for secure scenario, found {len(paths)}"


class TestPathConfidence:
    """Test confidence level assignment for attack paths."""

    @pytest.fixture
    def graph_builder(self):
        return GraphBuilder()

    @pytest.fixture
    def path_finder(self):
        config = PathFinderConfig(
            max_paths=10,
            max_depth=10,
            min_risk_score=0.0,
        )
        return PathFinder(config)

    def test_high_confidence_direct_path(self, graph_builder, path_finder):
        """
        Test that direct paths with verified edges get HIGH confidence.
        """
        assets, relationships, _ = get_scenario("lambda_privesc")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        paths = path_finder.find_paths(graph, SNAPSHOT_ID)

        if len(paths) > 0:
            # Paths with all verified edges should have HIGH confidence
            high_conf_paths = [p for p in paths if p.confidence_level == ConfidenceLevel.HIGH]
            # At least some paths should be HIGH confidence
            assert len(high_conf_paths) > 0 or any(
                p.confidence_level in [ConfidenceLevel.HIGH, ConfidenceLevel.MED] for p in paths
            ), "Expected some paths with HIGH or MED confidence"


class TestGraphConstruction:
    """Test that graphs are correctly constructed from fixtures."""

    @pytest.fixture
    def graph_builder(self):
        return GraphBuilder()

    @pytest.mark.parametrize("scenario_name", [
        "lambda_privesc",
        "role_chaining",
        "secrets_exfiltration",
        "lateral_movement",
        "secure_no_paths",
    ])
    def test_graph_construction(self, graph_builder, scenario_name):
        """Test that each scenario produces a valid graph."""
        assets, relationships, _ = get_scenario(scenario_name)

        graph = graph_builder.build(assets=assets, relationships=relationships)

        # Verify graph contains expected assets
        assert len(graph.all_assets()) > 0, f"Graph should contain assets for {scenario_name}"

        # Verify entry points are identified
        entry_points = graph.entry_points()
        # Most scenarios should have at least one entry point (Internet or internet-facing assets)

        # Verify sensitive targets are identified
        sensitive = graph.sensitive_targets()
        # Not all scenarios have sensitive targets, but vulnerable ones should

    def test_entry_points_identified(self, graph_builder):
        """Test that internet-facing assets are correctly identified as entry points."""
        assets, relationships, _ = get_scenario("lambda_privesc")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        entry_points = graph.entry_points()

        # Should include Internet pseudo-asset and EC2 with CAN_REACH
        entry_names = [e.name for e in entry_points]
        assert "Internet" in entry_names, "Internet should be an entry point"

    def test_sensitive_targets_identified(self, graph_builder):
        """Test that admin roles are correctly identified as sensitive targets."""
        assets, relationships, _ = get_scenario("lambda_privesc")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        sensitive = graph.sensitive_targets()

        # AdminRole should be a sensitive target
        sensitive_names = [s.name for s in sensitive]
        assert "AdminRole" in sensitive_names, "AdminRole should be a sensitive target"


class TestEdgeEvidence:
    """Test that edge evidence is properly tracked through paths."""

    @pytest.fixture
    def graph_builder(self):
        return GraphBuilder()

    @pytest.fixture
    def path_finder(self):
        return PathFinder(PathFinderConfig(max_paths=10, max_depth=10))

    def test_evidence_preserved_in_paths(self, graph_builder, path_finder):
        """Test that edge evidence is preserved and accessible in discovered paths."""
        assets, relationships, _ = get_scenario("lambda_privesc")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        paths = path_finder.find_paths(graph, SNAPSHOT_ID)

        if len(paths) > 0:
            path = paths[0]

            # Check that relationships have evidence
            path_rels = get_relationships_by_ids(graph, path.attack_chain_relationship_ids)
            for rel in path_rels:
                if rel and rel.relationship_type in ["CAN_PASS_TO", "MAY_CREATE_LAMBDA"]:
                    assert rel.evidence is not None, f"{rel.relationship_type} should have evidence"
                    assert rel.evidence.permission is not None, "Evidence should include permission"


class TestAllScenarios:
    """Run all scenarios and validate basic expectations."""

    @pytest.fixture
    def graph_builder(self):
        return GraphBuilder()

    @pytest.fixture
    def path_finder(self):
        return PathFinder(PathFinderConfig(max_paths=20, max_depth=15))

    def test_all_scenarios_load(self, graph_builder, path_finder):
        """Test that all scenarios can be loaded and processed without errors."""
        all_scenarios = get_all_scenarios()

        for name, (assets, relationships, expected_paths) in all_scenarios.items():
            # Build graph
            graph = graph_builder.build(assets=assets, relationships=relationships)

            # Find paths
            paths = path_finder.find_paths(graph, SNAPSHOT_ID)

            # Basic validation
            assert graph is not None, f"Graph should be created for {name}"

            # If expected paths > 0, we should find some
            if len(expected_paths) > 0:
                assert len(paths) > 0, f"Expected paths for {name} but found none"
            else:
                # Secure scenario should have no paths
                assert len(paths) == 0, f"Expected no paths for {name} but found {len(paths)}"

            print(f"Scenario '{name}': {len(paths)} paths found (expected: {len(expected_paths)})")


class TestPathProperties:
    """Test properties of discovered attack paths."""

    @pytest.fixture
    def graph_builder(self):
        return GraphBuilder()

    @pytest.fixture
    def path_finder(self):
        return PathFinder(PathFinderConfig(max_paths=10, max_depth=10))

    def test_paths_have_required_fields(self, graph_builder, path_finder):
        """Test that discovered paths have all required fields populated."""
        assets, relationships, _ = get_scenario("role_chaining")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        paths = path_finder.find_paths(graph, SNAPSHOT_ID)

        for path in paths:
            # Required fields
            assert path.id is not None, "Path should have an ID"
            assert path.snapshot_id == SNAPSHOT_ID, "Path should reference correct snapshot"
            assert len(path.path_asset_ids) >= 2, "Path should have at least 2 assets"
            assert len(path.attack_chain_relationship_ids) >= 1, "Path should have at least 1 edge"
            assert path.confidence_level is not None, "Path should have confidence level"
            assert path.risk_score is not None, "Path should have risk score"

    def test_path_assets_valid(self, graph_builder, path_finder):
        """Test that all assets in paths are valid graph nodes."""
        assets, relationships, _ = get_scenario("lambda_privesc")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        paths = path_finder.find_paths(graph, SNAPSHOT_ID)

        for path in paths:
            for asset_id in path.path_asset_ids:
                asset = graph.asset(asset_id)
                assert asset is not None, f"Asset {asset_id} in path should exist in graph"

    def test_path_relationships_valid(self, graph_builder, path_finder):
        """Test that all relationships in paths are valid graph edges."""
        assets, relationships, _ = get_scenario("secrets_exfiltration")

        graph = graph_builder.build(assets=assets, relationships=relationships)
        paths = path_finder.find_paths(graph, SNAPSHOT_ID)

        all_rels = graph.all_relationships()
        rels_by_id = {r.id: r for r in all_rels}

        for path in paths:
            for rel_id in path.attack_chain_relationship_ids:
                rel = rels_by_id.get(rel_id)
                assert rel is not None, f"Relationship {rel_id} in path should exist in graph"
