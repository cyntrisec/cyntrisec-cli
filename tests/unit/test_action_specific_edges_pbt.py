"""
Property tests for Action-Specific Edge Creation.

**Feature: capability-graph-upgrade, Property 3: Action-Specific Edge Creation**
**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.6, 3.7**

For any IAM role with a capability-granting permission (secretsmanager:GetSecretValue,
ssm:GetParameter*, kms:Decrypt, s3:GetObject) on a target resource, the RelationshipBuilder
SHALL create the corresponding action-specific capability edge (MAY_READ_SECRET,
MAY_READ_PARAMETER, MAY_DECRYPT, MAY_READ_S3_OBJECT) and SHALL NOT create a generic
MAY_ACCESS edge.
"""
from __future__ import annotations

import uuid
from uuid import UUID

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

from cyntrisec.core.schema import Asset, EdgeKind, Relationship
from cyntrisec.aws.relationship_builder import RelationshipBuilder, ActionParser


# Mapping of capability actions to expected edge types
CAPABILITY_ACTION_TO_EDGE_TYPE = {
    "secretsmanager:GetSecretValue": "MAY_READ_SECRET",
    "ssm:GetParameter": "MAY_READ_PARAMETER",
    "ssm:GetParameters": "MAY_READ_PARAMETER",
    "ssm:GetParametersByPath": "MAY_READ_PARAMETER",
    "kms:Decrypt": "MAY_DECRYPT",
    "s3:GetObject": "MAY_READ_S3_OBJECT",
}

# Mapping of target asset types to relevant capability actions
TARGET_TYPE_TO_ACTIONS = {
    "secretsmanager:secret": ["secretsmanager:GetSecretValue"],
    "ssm:parameter": ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"],
    "kms:key": ["kms:Decrypt"],
    "s3:bucket": ["s3:GetObject"],
}


def make_asset(
    snapshot_id: UUID,
    asset_id: UUID,
    asset_type: str,
    name: str,
    properties: dict = None,
    is_sensitive: bool = False,
    arn: str = None,
) -> Asset:
    return Asset(
        id=asset_id,
        snapshot_id=snapshot_id,
        asset_type=asset_type,
        aws_resource_id=str(asset_id),
        name=name,
        is_sensitive_target=is_sensitive,
        properties=properties or {},
        arn=arn,
    )


# Strategy for generating valid IAM actions that grant capabilities
capability_action_strategy = st.sampled_from(list(CAPABILITY_ACTION_TO_EDGE_TYPE.keys()))

# Strategy for generating target asset types
target_type_strategy = st.sampled_from(list(TARGET_TYPE_TO_ACTIONS.keys()))


@st.composite
def capability_scenario(draw):
    """Generate a scenario with a role, target, and matching capability action."""
    target_type = draw(target_type_strategy)
    relevant_actions = TARGET_TYPE_TO_ACTIONS[target_type]
    action = draw(st.sampled_from(relevant_actions))
    
    # Generate unique IDs
    role_id = uuid.uuid4()
    target_id = uuid.uuid4()
    instance_id = uuid.uuid4()
    profile_id = uuid.uuid4()
    
    # Generate ARNs
    account_id = "123456789012"
    region = "us-east-1"
    
    if target_type == "secretsmanager:secret":
        target_arn = f"arn:aws:secretsmanager:{region}:{account_id}:secret:test-secret"
    elif target_type == "ssm:parameter":
        target_arn = f"arn:aws:ssm:{region}:{account_id}:parameter/test-param"
    elif target_type == "kms:key":
        target_arn = f"arn:aws:kms:{region}:{account_id}:key/{uuid.uuid4()}"
    else:  # s3:bucket
        target_arn = f"arn:aws:s3:::test-bucket-{uuid.uuid4().hex[:8]}"
    
    role_arn = f"arn:aws:iam::{account_id}:role/TestRole"
    profile_arn = f"arn:aws:iam::{account_id}:instance-profile/TestProfile"
    
    return {
        "action": action,
        "target_type": target_type,
        "target_arn": target_arn,
        "role_id": role_id,
        "target_id": target_id,
        "instance_id": instance_id,
        "profile_id": profile_id,
        "role_arn": role_arn,
        "profile_arn": profile_arn,
        "expected_edge_type": CAPABILITY_ACTION_TO_EDGE_TYPE[action],
    }


class TestActionSpecificEdgeCreation:
    """
    Property tests for action-specific edge creation.
    
    **Feature: capability-graph-upgrade, Property 3: Action-Specific Edge Creation**
    **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.6, 3.7**
    """

    @pytest.fixture
    def snapshot_id(self):
        return UUID("00000000-0000-0000-0000-000000000000")

    @given(scenario=capability_scenario())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_action_specific_edge_creation(self, scenario):
        """
        Property test: For any IAM role with a capability-granting permission on a target
        resource, the RelationshipBuilder SHALL create the corresponding action-specific
        capability edge and SHALL NOT create a generic MAY_ACCESS edge.
        
        **Feature: capability-graph-upgrade, Property 3: Action-Specific Edge Creation**
        **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.6, 3.7**
        """
        snapshot_id = UUID("00000000-0000-0000-0000-000000000000")
        builder = RelationshipBuilder(snapshot_id)
        
        # Create role with the capability-granting permission
        role = make_asset(
            snapshot_id,
            scenario["role_id"],
            "iam:role",
            "TestRole",
            arn=scenario["role_arn"],
            properties={
                "policy_documents": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": scenario["action"],
                                "Resource": scenario["target_arn"],
                            }
                        ]
                    }
                ]
            },
        )
        
        # Create instance profile
        profile = make_asset(
            snapshot_id,
            scenario["profile_id"],
            "iam:instance-profile",
            "TestProfile",
            arn=scenario["profile_arn"],
            properties={"role_arns": [scenario["role_arn"]]},
        )
        
        # Create EC2 instance to make the role a "compute role"
        instance = make_asset(
            snapshot_id,
            scenario["instance_id"],
            "ec2:instance",
            "TestInstance",
            properties={"iam_instance_profile": scenario["profile_arn"]},
        )
        
        # Create sensitive target
        target = make_asset(
            snapshot_id,
            scenario["target_id"],
            scenario["target_type"],
            "TestTarget",
            is_sensitive=True,
            arn=scenario["target_arn"],
        )
        
        # Build relationships
        rels = builder.build([role, profile, instance, target])
        
        # Filter to only edges from role to target
        role_to_target_rels = [
            r for r in rels
            if r.source_asset_id == scenario["role_id"]
            and r.target_asset_id == scenario["target_id"]
        ]
        
        # Property 1: Should create the expected action-specific edge
        edge_types = {r.relationship_type for r in role_to_target_rels}
        assert scenario["expected_edge_type"] in edge_types, (
            f"Expected {scenario['expected_edge_type']} edge for action {scenario['action']}, "
            f"but got {edge_types}"
        )
        
        # Property 2: Should NOT create generic MAY_ACCESS edge
        assert "MAY_ACCESS" not in edge_types, (
            f"Should not create MAY_ACCESS edge when action-specific edge exists, "
            f"but got {edge_types}"
        )
        
        # Property 3: All edges should be CAPABILITY type
        for rel in role_to_target_rels:
            assert rel.edge_kind == EdgeKind.CAPABILITY, (
                f"Edge {rel.relationship_type} should have edge_kind=CAPABILITY"
            )

    @given(action=capability_action_strategy)
    @settings(max_examples=100)
    def test_action_parser_returns_correct_edge_type(self, action):
        """
        Property test: For any capability-granting action, the ActionParser
        SHALL return the correct edge type.
        
        **Feature: capability-graph-upgrade, Property 3: Action-Specific Edge Creation**
        **Validates: Requirements 3.6**
        """
        parser = ActionParser()
        
        # Create a statement with the action
        statement = {
            "Effect": "Allow",
            "Action": action,
            "Resource": "*",
        }
        
        # Get matched capabilities
        matched = parser.get_matched_capabilities(statement)
        
        # The action should be in the matched set
        assert action in matched, (
            f"Action {action} should be matched by ActionParser"
        )
        
        # The edge type should be correct
        edge_type = parser.get_edge_type_for_action(action)
        expected_edge_type = CAPABILITY_ACTION_TO_EDGE_TYPE[action]
        assert edge_type == expected_edge_type, (
            f"Action {action} should map to {expected_edge_type}, got {edge_type}"
        )

    @given(
        action=capability_action_strategy,
        use_wildcard=st.booleans(),
    )
    @settings(max_examples=100)
    def test_wildcard_action_matching(self, action, use_wildcard):
        """
        Property test: For any capability-granting action, wildcard patterns
        that match the action SHALL also be recognized.
        
        **Feature: capability-graph-upgrade, Property 3: Action-Specific Edge Creation**
        **Validates: Requirements 3.6**
        """
        parser = ActionParser()
        
        # Create action pattern (either exact or wildcard)
        if use_wildcard:
            # Create a wildcard pattern that matches the action
            service, _ = action.split(":", 1)
            action_pattern = f"{service}:*"
        else:
            action_pattern = action
        
        statement = {
            "Effect": "Allow",
            "Action": action_pattern,
            "Resource": "*",
        }
        
        # Get matched capabilities
        matched = parser.get_matched_capabilities(statement)
        
        # The action should be in the matched set
        assert action in matched, (
            f"Action {action} should be matched by pattern {action_pattern}"
        )


class TestNoGenericMayAccessEdges:
    """
    Tests to verify that generic MAY_ACCESS edges are not created.
    
    **Feature: capability-graph-upgrade, Property 3: Action-Specific Edge Creation**
    **Validates: Requirements 3.7**
    """

    @pytest.fixture
    def snapshot_id(self):
        return UUID("00000000-0000-0000-0000-000000000000")

    def test_no_may_access_for_s3_get_object(self, snapshot_id):
        """Test that s3:GetObject creates MAY_READ_S3_OBJECT, not MAY_ACCESS."""
        builder = RelationshipBuilder(snapshot_id)
        
        role_id = uuid.uuid4()
        target_id = uuid.uuid4()
        instance_id = uuid.uuid4()
        profile_id = uuid.uuid4()
        
        role_arn = "arn:aws:iam::123456789012:role/TestRole"
        profile_arn = "arn:aws:iam::123456789012:instance-profile/TestProfile"
        bucket_arn = "arn:aws:s3:::test-bucket"
        
        role = make_asset(
            snapshot_id, role_id, "iam:role", "TestRole",
            arn=role_arn,
            properties={
                "policy_documents": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": f"{bucket_arn}*",
                            }
                        ]
                    }
                ]
            },
        )
        profile = make_asset(
            snapshot_id, profile_id, "iam:instance-profile", "TestProfile",
            arn=profile_arn,
            properties={"role_arns": [role_arn]},
        )
        instance = make_asset(
            snapshot_id, instance_id, "ec2:instance", "TestInstance",
            properties={"iam_instance_profile": profile_arn},
        )
        target = make_asset(
            snapshot_id, target_id, "s3:bucket", "test-bucket",
            is_sensitive=True,
            arn=bucket_arn,
        )
        
        rels = builder.build([role, profile, instance, target])
        
        # Get all relationship types
        rel_types = {r.relationship_type for r in rels}
        
        # Should have MAY_READ_S3_OBJECT
        assert "MAY_READ_S3_OBJECT" in rel_types
        
        # Should NOT have MAY_ACCESS
        assert "MAY_ACCESS" not in rel_types

    def test_no_may_access_for_secrets_manager(self, snapshot_id):
        """Test that secretsmanager:GetSecretValue creates MAY_READ_SECRET, not MAY_ACCESS."""
        builder = RelationshipBuilder(snapshot_id)
        
        role_id = uuid.uuid4()
        target_id = uuid.uuid4()
        instance_id = uuid.uuid4()
        profile_id = uuid.uuid4()
        
        role_arn = "arn:aws:iam::123456789012:role/TestRole"
        profile_arn = "arn:aws:iam::123456789012:instance-profile/TestProfile"
        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret"
        
        role = make_asset(
            snapshot_id, role_id, "iam:role", "TestRole",
            arn=role_arn,
            properties={
                "policy_documents": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "secretsmanager:GetSecretValue",
                                "Resource": secret_arn,
                            }
                        ]
                    }
                ]
            },
        )
        profile = make_asset(
            snapshot_id, profile_id, "iam:instance-profile", "TestProfile",
            arn=profile_arn,
            properties={"role_arns": [role_arn]},
        )
        instance = make_asset(
            snapshot_id, instance_id, "ec2:instance", "TestInstance",
            properties={"iam_instance_profile": profile_arn},
        )
        target = make_asset(
            snapshot_id, target_id, "secretsmanager:secret", "test-secret",
            is_sensitive=True,
            arn=secret_arn,
        )
        
        rels = builder.build([role, profile, instance, target])
        
        # Get all relationship types
        rel_types = {r.relationship_type for r in rels}
        
        # Should have MAY_READ_SECRET
        assert "MAY_READ_SECRET" in rel_types
        
        # Should NOT have MAY_ACCESS
        assert "MAY_ACCESS" not in rel_types
