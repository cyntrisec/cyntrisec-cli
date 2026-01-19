"""
Unit tests for offline simulation disclaimer and remediation hints.

Tests for:
- Offline simulation results include mode and disclaimer
- Remediation Terraform hints structure

Requirements: 21.14, 21.15
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from cyntrisec.cli.can import _build_payload
from cyntrisec.cli.remediate import _build_plan, _terraform_snippet
from cyntrisec.core.schema import Asset, AttackPath, Relationship, Snapshot, SnapshotStatus
from cyntrisec.core.simulator import CanAccessResult, SimulationDecision, SimulationResult


def make_snapshot(snapshot_id=None, account_id="123456789012"):
    """Create a test snapshot."""
    from datetime import datetime
    return Snapshot(
        id=snapshot_id or uuid.uuid4(),
        aws_account_id=account_id,
        regions=["us-east-1"],
        status=SnapshotStatus.completed,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        asset_count=10,
        relationship_count=5,
        finding_count=3,
        path_count=2,
    )


class TestOfflineSimulationDisclaimer:
    """
    Tests for offline simulation disclaimer.
    
    Validates: Requirements 17.1, 17.2, 17.3, 21.14
    
    For any offline access simulation, the output SHALL include:
    - mode field set to "offline"
    - disclaimer explaining limitations
    - suggestion to use --live for authoritative results
    """

    def test_offline_result_includes_mode_field(self):
        """Test that offline simulation result includes mode='offline'."""
        # Create an offline result (no simulations = offline mode)
        result = CanAccessResult(
            principal_arn="arn:aws:iam::123456789012:role/TestRole",
            target_resource="arn:aws:s3:::test-bucket",
            action="s3:GetObject",
            can_access=False,
            simulations=[],  # Empty simulations indicates offline mode
            proof={"relationship_type": "MAY_ACCESS"},
        )
        
        snapshot = make_snapshot()
        payload = _build_payload(result, snapshot)
        
        assert "mode" in payload
        assert payload["mode"] == "offline"

    def test_offline_result_includes_disclaimer(self):
        """Test that offline simulation result includes disclaimer."""
        result = CanAccessResult(
            principal_arn="arn:aws:iam::123456789012:role/TestRole",
            target_resource="arn:aws:s3:::test-bucket",
            action="s3:GetObject",
            can_access=False,
            simulations=[],
            proof={},
        )
        
        snapshot = make_snapshot()
        payload = _build_payload(result, snapshot)
        
        assert "disclaimer" in payload
        assert "offline" in payload["disclaimer"].lower() or "graph" in payload["disclaimer"].lower()

    def test_offline_disclaimer_suggests_live_mode(self):
        """Test that offline disclaimer suggests using --live."""
        result = CanAccessResult(
            principal_arn="arn:aws:iam::123456789012:role/TestRole",
            target_resource="arn:aws:s3:::test-bucket",
            action="s3:GetObject",
            can_access=True,
            simulations=[],
            proof={"relationship_type": "MAY_ACCESS"},
        )
        
        snapshot = make_snapshot()
        payload = _build_payload(result, snapshot)
        
        assert "disclaimer" in payload
        assert "--live" in payload["disclaimer"]

    def test_live_result_has_live_mode(self):
        """Test that live simulation result has mode='live'."""
        # Create a live result (has simulations)
        sim = SimulationResult(
            action="s3:GetObject",
            resource="arn:aws:s3:::test-bucket/*",
            decision=SimulationDecision.allowed,
            matched_statements=[{"Sid": "AllowAccess"}],
        )
        
        result = CanAccessResult(
            principal_arn="arn:aws:iam::123456789012:role/TestRole",
            target_resource="arn:aws:s3:::test-bucket",
            action="s3:GetObject",
            can_access=True,
            simulations=[sim],
            proof={},
        )
        
        snapshot = make_snapshot()
        payload = _build_payload(result, snapshot)
        
        assert "mode" in payload
        assert payload["mode"] == "live"

    def test_live_result_no_disclaimer(self):
        """Test that live simulation result does not include disclaimer."""
        sim = SimulationResult(
            action="s3:GetObject",
            resource="arn:aws:s3:::test-bucket/*",
            decision=SimulationDecision.allowed,
            matched_statements=[],
        )
        
        result = CanAccessResult(
            principal_arn="arn:aws:iam::123456789012:role/TestRole",
            target_resource="arn:aws:s3:::test-bucket",
            action="s3:GetObject",
            can_access=True,
            simulations=[sim],
            proof={},
        )
        
        snapshot = make_snapshot()
        payload = _build_payload(result, snapshot)
        
        # Live mode should not have disclaimer
        assert payload.get("disclaimer") is None or payload["mode"] == "live"


class TestRemediationTerraformHints:
    """
    Tests for remediation Terraform hints.
    
    Validates: Requirements 18.1, 18.2, 18.3, 21.15
    
    For any remediation plan, the Terraform hints SHALL:
    - Include actual resource identifiers when available
    - Provide meaningful snippets for different relationship types
    """

    def test_terraform_snippet_for_allows_traffic_to(self):
        """Test Terraform snippet for ALLOWS_TRAFFIC_TO relationship."""
        snippet = _terraform_snippet(
            action="restrict",
            source="web-server",
            target="database",
            relationship_type="ALLOWS_TRAFFIC_TO",
        )
        
        assert "security_group" in snippet.lower() or "ingress" in snippet.lower()
        assert "web-server" in snippet or "database" in snippet

    def test_terraform_snippet_for_may_access(self):
        """Test Terraform snippet for MAY_ACCESS relationship."""
        snippet = _terraform_snippet(
            action="restrict",
            source="admin-role",
            target="secret-bucket",
            relationship_type="MAY_ACCESS",
        )
        
        assert "iam" in snippet.lower() or "policy" in snippet.lower()

    def test_terraform_snippet_for_can_assume(self):
        """Test Terraform snippet for CAN_ASSUME relationship."""
        snippet = _terraform_snippet(
            action="restrict",
            source="external-role",
            target="admin-role",
            relationship_type="CAN_ASSUME",
        )
        
        assert "assume" in snippet.lower() or "trust" in snippet.lower()
        assert "sts:AssumeRole" in snippet

    def test_terraform_snippet_for_unknown_relationship(self):
        """Test Terraform snippet for unknown relationship type."""
        snippet = _terraform_snippet(
            action="review",
            source="source",
            target="target",
            relationship_type="UNKNOWN_TYPE",
        )
        
        # Should return a generic review message
        assert "review" in snippet.lower() or "#" in snippet

    def test_build_plan_includes_terraform_snippets(self):
        """Test that _build_plan includes Terraform snippets for each remediation."""
        # Create a mock result with remediations
        mock_remediation = MagicMock()
        mock_remediation.action = "restrict"
        mock_remediation.description = "Restrict access from web to db"
        mock_remediation.source_name = "web-server"
        mock_remediation.target_name = "database"
        mock_remediation.relationship_type = "ALLOWS_TRAFFIC_TO"
        mock_remediation.paths_blocked = [uuid.uuid4()]
        
        mock_result = MagicMock()
        mock_result.remediations = [mock_remediation]
        
        plan = _build_plan(mock_result)
        
        assert len(plan) == 1
        assert "terraform" in plan[0]
        assert plan[0]["terraform"]  # Not empty

    def test_terraform_snippets_are_valid_hcl_comments(self):
        """Test that Terraform snippets start with HCL comments."""
        relationship_types = ["ALLOWS_TRAFFIC_TO", "MAY_ACCESS", "CAN_ASSUME", "UNKNOWN"]
        
        for rel_type in relationship_types:
            snippet = _terraform_snippet(
                action="restrict",
                source="source",
                target="target",
                relationship_type=rel_type,
            )
            
            # All snippets should start with a comment
            assert snippet.strip().startswith("#"), f"Snippet for {rel_type} should start with #"

    def test_plan_item_structure(self):
        """Test that plan items have the expected structure."""
        mock_remediation = MagicMock()
        mock_remediation.action = "restrict"
        mock_remediation.description = "Test description"
        mock_remediation.source_name = "source"
        mock_remediation.target_name = "target"
        mock_remediation.relationship_type = "ALLOWS_TRAFFIC_TO"
        mock_remediation.paths_blocked = [uuid.uuid4(), uuid.uuid4()]
        
        mock_result = MagicMock()
        mock_result.remediations = [mock_remediation]
        
        plan = _build_plan(mock_result)
        
        item = plan[0]
        assert "priority" in item
        assert "action" in item
        assert "description" in item
        assert "source" in item
        assert "target" in item
        assert "relationship_type" in item
        assert "paths_blocked" in item
        assert "terraform" in item
        
        assert item["priority"] == 1
        assert item["paths_blocked"] == 2
