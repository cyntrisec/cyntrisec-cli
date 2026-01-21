"""
Property tests for Edge Kind Assignment Consistency.

**Feature: capability-graph-upgrade, Property 1: Edge Kind Assignment Consistency**
**Validates: Requirements 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10**

For any relationship created by the RelationshipBuilder, the assigned edge_kind SHALL match
the expected mapping based on relationship_type:
- CONTAINS, USES, ALLOWS_TRAFFIC_TO → STRUCTURAL
- CAN_ASSUME, CAN_PASS_TO, CAN_REACH, MAY_READ_SECRET, MAY_READ_PARAMETER, 
  MAY_DECRYPT, MAY_READ_S3_OBJECT, MAY_CREATE_LAMBDA → CAPABILITY
"""
from __future__ import annotations

import uuid

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

from cyntrisec.core.schema import (
    EdgeKind,
    ConditionResult,
    ConfidenceLevel,
    EdgeEvidence,
    Relationship,
    AttackPath,
)
from decimal import Decimal


# Mapping of relationship types to expected edge kinds
EDGE_KIND_MAPPING = {
    # Structural edges - context only, not traversed during attack path discovery
    "CONTAINS": EdgeKind.STRUCTURAL,
    "USES": EdgeKind.STRUCTURAL,
    "ALLOWS_TRAFFIC_TO": EdgeKind.STRUCTURAL,
    # Capability edges - attacker movement, traversed during attack path discovery
    "CAN_ASSUME": EdgeKind.CAPABILITY,
    "CAN_PASS_TO": EdgeKind.CAPABILITY,
    "CAN_REACH": EdgeKind.CAPABILITY,
    "MAY_READ_SECRET": EdgeKind.CAPABILITY,
    "MAY_READ_PARAMETER": EdgeKind.CAPABILITY,
    "MAY_DECRYPT": EdgeKind.CAPABILITY,
    "MAY_READ_S3_OBJECT": EdgeKind.CAPABILITY,
    "MAY_CREATE_LAMBDA": EdgeKind.CAPABILITY,
    "MAY_ACCESS": EdgeKind.CAPABILITY,  # Legacy, will be replaced by action-specific edges
}


def get_expected_edge_kind(relationship_type: str) -> EdgeKind:
    """Get the expected edge kind for a relationship type."""
    return EDGE_KIND_MAPPING.get(relationship_type, EdgeKind.UNKNOWN)


class TestEdgeKindEnums:
    """Test that EdgeKind, ConditionResult, and ConfidenceLevel enums are correctly defined."""

    def test_edge_kind_values(self):
        """Test EdgeKind enum has correct values."""
        assert EdgeKind.STRUCTURAL == "structural"
        assert EdgeKind.CAPABILITY == "capability"
        assert EdgeKind.UNKNOWN == "unknown"

    def test_condition_result_values(self):
        """Test ConditionResult enum has correct values."""
        assert ConditionResult.TRUE == "true"
        assert ConditionResult.FALSE == "false"
        assert ConditionResult.UNKNOWN == "unknown"

    def test_confidence_level_values(self):
        """Test ConfidenceLevel enum has correct values."""
        assert ConfidenceLevel.HIGH == "high"
        assert ConfidenceLevel.MED == "med"
        assert ConfidenceLevel.LOW == "low"


class TestEdgeEvidenceModel:
    """Test EdgeEvidence model."""

    def test_edge_evidence_creation(self):
        """Test EdgeEvidence can be created with all fields."""
        evidence = EdgeEvidence(
            policy_sid="AllowS3Access",
            policy_arn="arn:aws:iam::123456789012:policy/S3Access",
            rule_id="sgr-12345",
            source_arn="arn:aws:iam::123456789012:role/MyRole",
            target_arn="arn:aws:s3:::my-bucket",
            permission="s3:GetObject",
            raw_statement={"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        )
        assert evidence.policy_sid == "AllowS3Access"
        assert evidence.policy_arn == "arn:aws:iam::123456789012:policy/S3Access"
        assert evidence.rule_id == "sgr-12345"
        assert evidence.source_arn == "arn:aws:iam::123456789012:role/MyRole"
        assert evidence.target_arn == "arn:aws:s3:::my-bucket"
        assert evidence.permission == "s3:GetObject"
        assert evidence.raw_statement["Effect"] == "Allow"

    def test_edge_evidence_optional_fields(self):
        """Test EdgeEvidence can be created with minimal fields."""
        evidence = EdgeEvidence()
        assert evidence.policy_sid is None
        assert evidence.policy_arn is None
        assert evidence.rule_id is None


class TestRelationshipModelUpdates:
    """Test updated Relationship model with edge_kind and related fields."""

    @pytest.fixture
    def snapshot_id(self):
        return uuid.uuid4()

    def test_relationship_default_edge_kind(self, snapshot_id):
        """Test Relationship defaults to UNKNOWN edge_kind."""
        rel = Relationship(
            snapshot_id=snapshot_id,
            source_asset_id=uuid.uuid4(),
            target_asset_id=uuid.uuid4(),
            relationship_type="SOME_TYPE",
        )
        assert rel.edge_kind == EdgeKind.UNKNOWN

    def test_relationship_with_edge_kind(self, snapshot_id):
        """Test Relationship can be created with explicit edge_kind."""
        rel = Relationship(
            snapshot_id=snapshot_id,
            source_asset_id=uuid.uuid4(),
            target_asset_id=uuid.uuid4(),
            relationship_type="CAN_ASSUME",
            edge_kind=EdgeKind.CAPABILITY,
        )
        assert rel.edge_kind == EdgeKind.CAPABILITY

    def test_relationship_with_evidence(self, snapshot_id):
        """Test Relationship can include EdgeEvidence."""
        evidence = EdgeEvidence(
            policy_sid="AllowAccess",
            permission="s3:GetObject",
        )
        rel = Relationship(
            snapshot_id=snapshot_id,
            source_asset_id=uuid.uuid4(),
            target_asset_id=uuid.uuid4(),
            relationship_type="MAY_READ_S3_OBJECT",
            edge_kind=EdgeKind.CAPABILITY,
            evidence=evidence,
        )
        assert rel.evidence is not None
        assert rel.evidence.policy_sid == "AllowAccess"

    def test_relationship_condition_fields(self, snapshot_id):
        """Test Relationship condition evaluation fields."""
        rel = Relationship(
            snapshot_id=snapshot_id,
            source_asset_id=uuid.uuid4(),
            target_asset_id=uuid.uuid4(),
            relationship_type="MAY_ACCESS",
            conditions_evaluated=False,
            condition_result=ConditionResult.UNKNOWN,
        )
        assert rel.conditions_evaluated is False
        assert rel.condition_result == ConditionResult.UNKNOWN

    def test_relationship_edge_weight(self, snapshot_id):
        """Test Relationship edge_weight field."""
        rel = Relationship(
            snapshot_id=snapshot_id,
            source_asset_id=uuid.uuid4(),
            target_asset_id=uuid.uuid4(),
            relationship_type="CAN_ASSUME",
            edge_weight=0.8,
        )
        assert rel.edge_weight == 0.8


class TestAttackPathModelUpdates:
    """Test updated AttackPath model with confidence and chain fields."""

    @pytest.fixture
    def snapshot_id(self):
        return uuid.uuid4()

    def test_attack_path_default_confidence(self, snapshot_id):
        """Test AttackPath defaults to HIGH confidence."""
        source_id = uuid.uuid4()
        target_id = uuid.uuid4()
        rel_id = uuid.uuid4()
        
        path = AttackPath(
            snapshot_id=snapshot_id,
            source_asset_id=source_id,
            target_asset_id=target_id,
            path_asset_ids=[source_id, target_id],
            path_relationship_ids=[rel_id],
            attack_vector="network",
            path_length=1,
            entry_confidence=Decimal("0.9"),
            exploitability_score=Decimal("5.0"),
            impact_score=Decimal("8.0"),
            risk_score=Decimal("36.0"),
        )
        assert path.confidence_level == ConfidenceLevel.HIGH
        assert path.confidence_reason == ""

    def test_attack_path_with_confidence(self, snapshot_id):
        """Test AttackPath can be created with explicit confidence."""
        source_id = uuid.uuid4()
        target_id = uuid.uuid4()
        rel_id = uuid.uuid4()
        
        path = AttackPath(
            snapshot_id=snapshot_id,
            source_asset_id=source_id,
            target_asset_id=target_id,
            path_asset_ids=[source_id, target_id],
            path_relationship_ids=[rel_id],
            attack_vector="network",
            path_length=1,
            entry_confidence=Decimal("0.9"),
            exploitability_score=Decimal("5.0"),
            impact_score=Decimal("8.0"),
            risk_score=Decimal("36.0"),
            confidence_level=ConfidenceLevel.MED,
            confidence_reason="IAM conditions not fully evaluated",
        )
        assert path.confidence_level == ConfidenceLevel.MED
        assert path.confidence_reason == "IAM conditions not fully evaluated"

    def test_attack_path_chain_fields(self, snapshot_id):
        """Test AttackPath attack_chain and context fields."""
        source_id = uuid.uuid4()
        target_id = uuid.uuid4()
        capability_rel_id = uuid.uuid4()
        context_rel_id = uuid.uuid4()
        
        path = AttackPath(
            snapshot_id=snapshot_id,
            source_asset_id=source_id,
            target_asset_id=target_id,
            path_asset_ids=[source_id, target_id],
            path_relationship_ids=[capability_rel_id],
            attack_chain_relationship_ids=[capability_rel_id],
            context_relationship_ids=[context_rel_id],
            attack_vector="network",
            path_length=1,
            entry_confidence=Decimal("0.9"),
            exploitability_score=Decimal("5.0"),
            impact_score=Decimal("8.0"),
            risk_score=Decimal("36.0"),
        )
        assert path.attack_chain_relationship_ids == [capability_rel_id]
        assert path.context_relationship_ids == [context_rel_id]

    def test_attack_path_backward_compatibility(self, snapshot_id):
        """Test AttackPath maintains backward compatibility with path_relationship_ids."""
        source_id = uuid.uuid4()
        target_id = uuid.uuid4()
        rel_id = uuid.uuid4()
        
        # Create path without new fields - should still work
        path = AttackPath(
            snapshot_id=snapshot_id,
            source_asset_id=source_id,
            target_asset_id=target_id,
            path_asset_ids=[source_id, target_id],
            path_relationship_ids=[rel_id],
            attack_vector="network",
            path_length=1,
            entry_confidence=Decimal("0.9"),
            exploitability_score=Decimal("5.0"),
            impact_score=Decimal("8.0"),
            risk_score=Decimal("36.0"),
        )
        # path_relationship_ids should still work
        assert path.path_relationship_ids == [rel_id]
        # New fields should have defaults
        assert path.attack_chain_relationship_ids == []
        assert path.context_relationship_ids == []


class TestEdgeKindAssignmentConsistency:
    """
    Property tests for edge kind assignment consistency.
    
    **Feature: capability-graph-upgrade, Property 1: Edge Kind Assignment Consistency**
    **Validates: Requirements 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10**
    """

    @pytest.fixture
    def snapshot_id(self):
        return uuid.uuid4()

    @given(st.sampled_from(list(EDGE_KIND_MAPPING.keys())))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_edge_kind_mapping_consistency(self, relationship_type):
        """
        Property test: For any known relationship type, the expected edge_kind
        should be deterministic and match the defined mapping.
        
        **Feature: capability-graph-upgrade, Property 1: Edge Kind Assignment Consistency**
        **Validates: Requirements 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10**
        """
        expected_kind = get_expected_edge_kind(relationship_type)
        
        # Verify structural edges
        if relationship_type in ["CONTAINS", "USES", "ALLOWS_TRAFFIC_TO"]:
            assert expected_kind == EdgeKind.STRUCTURAL, (
                f"{relationship_type} should be STRUCTURAL"
            )
        # Verify capability edges
        elif relationship_type in [
            "CAN_ASSUME", "CAN_PASS_TO", "CAN_REACH",
            "MAY_READ_SECRET", "MAY_READ_PARAMETER", "MAY_DECRYPT",
            "MAY_READ_S3_OBJECT", "MAY_CREATE_LAMBDA", "MAY_ACCESS"
        ]:
            assert expected_kind == EdgeKind.CAPABILITY, (
                f"{relationship_type} should be CAPABILITY"
            )

    @given(st.text(min_size=1, max_size=50).filter(lambda x: x not in EDGE_KIND_MAPPING))
    @settings(max_examples=100)
    def test_unknown_relationship_types_default_to_unknown(self, relationship_type):
        """
        Property test: For any unknown relationship type, the expected edge_kind
        should be UNKNOWN.
        
        **Feature: capability-graph-upgrade, Property 1: Edge Kind Assignment Consistency**
        """
        expected_kind = get_expected_edge_kind(relationship_type)
        assert expected_kind == EdgeKind.UNKNOWN, (
            f"Unknown relationship type '{relationship_type}' should map to UNKNOWN"
        )

    def test_structural_edge_types(self, snapshot_id):
        """Test that structural relationship types map to STRUCTURAL edge_kind."""
        structural_types = ["CONTAINS", "USES", "ALLOWS_TRAFFIC_TO"]
        
        for rel_type in structural_types:
            expected = get_expected_edge_kind(rel_type)
            assert expected == EdgeKind.STRUCTURAL, (
                f"{rel_type} should be STRUCTURAL, got {expected}"
            )

    def test_capability_edge_types(self, snapshot_id):
        """Test that capability relationship types map to CAPABILITY edge_kind."""
        capability_types = [
            "CAN_ASSUME", "CAN_PASS_TO", "CAN_REACH",
            "MAY_READ_SECRET", "MAY_READ_PARAMETER", "MAY_DECRYPT",
            "MAY_READ_S3_OBJECT", "MAY_CREATE_LAMBDA", "MAY_ACCESS"
        ]
        
        for rel_type in capability_types:
            expected = get_expected_edge_kind(rel_type)
            assert expected == EdgeKind.CAPABILITY, (
                f"{rel_type} should be CAPABILITY, got {expected}"
            )

    def test_relationship_can_be_created_with_correct_edge_kind(self, snapshot_id):
        """Test that relationships can be created with the correct edge_kind based on type."""
        # Test a structural relationship
        contains_rel = Relationship(
            snapshot_id=snapshot_id,
            source_asset_id=uuid.uuid4(),
            target_asset_id=uuid.uuid4(),
            relationship_type="CONTAINS",
            edge_kind=get_expected_edge_kind("CONTAINS"),
        )
        assert contains_rel.edge_kind == EdgeKind.STRUCTURAL
        
        # Test a capability relationship
        can_assume_rel = Relationship(
            snapshot_id=snapshot_id,
            source_asset_id=uuid.uuid4(),
            target_asset_id=uuid.uuid4(),
            relationship_type="CAN_ASSUME",
            edge_kind=get_expected_edge_kind("CAN_ASSUME"),
        )
        assert can_assume_rel.edge_kind == EdgeKind.CAPABILITY
