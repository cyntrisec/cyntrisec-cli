"""
Property tests for Evidence Provenance.

**Feature: capability-graph-upgrade, Property 5: Evidence Provenance**
**Validates: Requirements 0.1, 0.2, 3.5**

For any capability edge created by the RelationshipBuilder, the edge SHALL include
evidence containing at minimum: the source policy SID or rule ID, target resource ARN,
and the specific permission that grants access. The raw policy statement SHALL be
stored in evidence.
"""
from __future__ import annotations

import uuid
from uuid import UUID

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

from cyntrisec.core.schema import Asset, EdgeKind, EdgeEvidence, Relationship
from cyntrisec.aws.relationship_builder import RelationshipBuilder


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


# Strategy for generating target asset types
target_type_strategy = st.sampled_from(list(TARGET_TYPE_TO_ACTIONS.keys()))

# Strategy for generating policy SIDs
policy_sid_strategy = st.one_of(
    st.none(),
    st.text(
        alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
        min_size=1,
        max_size=20,
    ),
)

# Strategy for generating policy ARNs
policy_arn_strategy = st.one_of(
    st.none(),
    st.just("arn:aws:iam::123456789012:policy/TestPolicy"),
)


@st.composite
def evidence_scenario(draw):
    """Generate a scenario with a role, target, and policy statement with evidence fields."""
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
    
    # Generate policy statement with optional SID
    policy_sid = draw(policy_sid_strategy)
    policy_arn = draw(policy_arn_strategy)
    
    statement = {
        "Effect": "Allow",
        "Action": action,
        "Resource": target_arn,
    }
    if policy_sid:
        statement["Sid"] = policy_sid
    
    policy_doc = {"Statement": [statement]}
    if policy_arn:
        policy_doc["PolicyArn"] = policy_arn
    
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
        "policy_sid": policy_sid,
        "policy_arn": policy_arn,
        "statement": statement,
        "policy_doc": policy_doc,
    }


class TestEvidenceProvenance:
    """
    Property tests for evidence provenance.
    
    **Feature: capability-graph-upgrade, Property 5: Evidence Provenance**
    **Validates: Requirements 0.1, 0.2, 3.5**
    """

    @pytest.fixture
    def snapshot_id(self):
        return UUID("00000000-0000-0000-0000-000000000000")

    @given(scenario=evidence_scenario())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
    def test_capability_edge_includes_evidence(self, scenario):
        """
        Property test: For any capability edge created by the RelationshipBuilder,
        the edge SHALL include evidence containing at minimum: the source policy SID
        or rule ID, target resource ARN, and the specific permission that grants access.
        
        **Feature: capability-graph-upgrade, Property 5: Evidence Provenance**
        **Validates: Requirements 0.1, 0.2, 3.5**
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
                "policy_documents": [scenario["policy_doc"]]
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
        
        # Filter to only capability edges from role to target
        capability_edges = [
            r for r in rels
            if r.source_asset_id == scenario["role_id"]
            and r.target_asset_id == scenario["target_id"]
            and r.edge_kind == EdgeKind.CAPABILITY
        ]
        
        # Should have at least one capability edge
        assert len(capability_edges) >= 1, (
            f"Expected at least one capability edge for action {scenario['action']}"
        )
        
        for edge in capability_edges:
            # Property 1: Evidence should be present
            assert edge.evidence is not None, (
                f"Capability edge {edge.relationship_type} should have evidence"
            )
            
            # Property 2: Evidence should contain target_arn
            assert edge.evidence.target_arn == scenario["target_arn"], (
                f"Evidence target_arn should be {scenario['target_arn']}, "
                f"got {edge.evidence.target_arn}"
            )
            
            # Property 3: Evidence should contain permission
            assert edge.evidence.permission == scenario["action"], (
                f"Evidence permission should be {scenario['action']}, "
                f"got {edge.evidence.permission}"
            )
            
            # Property 4: Evidence should contain raw_statement
            assert edge.evidence.raw_statement is not None, (
                "Evidence should contain raw_statement"
            )
            assert edge.evidence.raw_statement == scenario["statement"], (
                f"Evidence raw_statement should match the original statement"
            )
            
            # Property 5: If policy_sid was provided, it should be in evidence
            if scenario["policy_sid"]:
                assert edge.evidence.policy_sid == scenario["policy_sid"], (
                    f"Evidence policy_sid should be {scenario['policy_sid']}, "
                    f"got {edge.evidence.policy_sid}"
                )
            
            # Property 6: If policy_arn was provided, it should be in evidence
            if scenario["policy_arn"]:
                assert edge.evidence.policy_arn == scenario["policy_arn"], (
                    f"Evidence policy_arn should be {scenario['policy_arn']}, "
                    f"got {edge.evidence.policy_arn}"
                )
            
            # Property 7: Evidence should contain source_arn
            assert edge.evidence.source_arn == scenario["role_arn"], (
                f"Evidence source_arn should be {scenario['role_arn']}, "
                f"got {edge.evidence.source_arn}"
            )

    @given(
        policy_sid=st.text(
            alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
            min_size=1,
            max_size=20,
        ),
    )
    @settings(max_examples=50)
    def test_pass_role_edge_includes_evidence(self, policy_sid):
        """
        Property test: For any CAN_PASS_TO edge, the edge SHALL include evidence
        with policy_sid, target_arn, permission, and raw_statement.
        
        **Feature: capability-graph-upgrade, Property 5: Evidence Provenance**
        **Validates: Requirements 0.1, 0.2**
        """
        snapshot_id = UUID("00000000-0000-0000-0000-000000000000")
        builder = RelationshipBuilder(snapshot_id)
        
        source_role_id = uuid.uuid4()
        target_role_id = uuid.uuid4()
        source_role_arn = "arn:aws:iam::123456789012:role/SourceRole"
        target_role_arn = "arn:aws:iam::123456789012:role/TargetRole"
        policy_arn = "arn:aws:iam::123456789012:policy/PassRolePolicy"
        
        statement = {
            "Sid": policy_sid,
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": target_role_arn,
        }
        
        source_role = make_asset(
            snapshot_id,
            source_role_id,
            "iam:role",
            "SourceRole",
            arn=source_role_arn,
            properties={
                "policy_documents": [
                    {
                        "PolicyArn": policy_arn,
                        "Statement": [statement]
                    }
                ]
            },
        )
        target_role = make_asset(
            snapshot_id,
            target_role_id,
            "iam:role",
            "TargetRole",
            arn=target_role_arn,
        )
        
        rels = builder.build([source_role, target_role])
        
        # Should have one CAN_PASS_TO edge
        pass_role_edges = [r for r in rels if r.relationship_type == "CAN_PASS_TO"]
        assert len(pass_role_edges) == 1
        
        edge = pass_role_edges[0]
        
        # Property 1: Evidence should be present
        assert edge.evidence is not None
        
        # Property 2: Evidence should contain policy_sid
        assert edge.evidence.policy_sid == policy_sid
        
        # Property 3: Evidence should contain policy_arn
        assert edge.evidence.policy_arn == policy_arn
        
        # Property 4: Evidence should contain target_arn
        assert edge.evidence.target_arn == target_role_arn
        
        # Property 5: Evidence should contain permission
        assert edge.evidence.permission == "iam:PassRole"
        
        # Property 6: Evidence should contain raw_statement
        assert edge.evidence.raw_statement == statement
        
        # Property 7: Evidence should contain source_arn
        assert edge.evidence.source_arn == source_role_arn


class TestMayCreateLambdaEvidence:
    """
    Tests for MAY_CREATE_LAMBDA edge evidence.
    
    **Feature: capability-graph-upgrade, Property 5: Evidence Provenance**
    **Validates: Requirements 0.1, 0.2**
    """

    @pytest.fixture
    def snapshot_id(self):
        return UUID("00000000-0000-0000-0000-000000000000")

    @given(
        action=st.sampled_from(["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"]),
        policy_sid=st.one_of(st.none(), st.text(min_size=1, max_size=20, alphabet="abcdefghijklmnopqrstuvwxyz")),
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_may_create_lambda_includes_evidence(self, action, policy_sid):
        """
        Property test: For any MAY_CREATE_LAMBDA edge, the edge SHALL include
        evidence with permission and raw_statement.
        
        **Feature: capability-graph-upgrade, Property 5: Evidence Provenance**
        **Validates: Requirements 0.1, 0.2**
        """
        snapshot_id = UUID("00000000-0000-0000-0000-000000000000")
        builder = RelationshipBuilder(snapshot_id)
        
        role_id = uuid.uuid4()
        role_arn = "arn:aws:iam::123456789012:role/LambdaCreatorRole"
        policy_arn = "arn:aws:iam::123456789012:policy/LambdaCreatePolicy"
        
        statement = {
            "Effect": "Allow",
            "Action": action,
            "Resource": "*",
        }
        if policy_sid:
            statement["Sid"] = policy_sid
        
        role = make_asset(
            snapshot_id,
            role_id,
            "iam:role",
            "LambdaCreatorRole",
            arn=role_arn,
            properties={
                "policy_documents": [
                    {
                        "PolicyArn": policy_arn,
                        "Statement": [statement]
                    }
                ]
            },
        )
        
        rels = builder.build([role])
        
        # Should have one MAY_CREATE_LAMBDA edge
        lambda_edges = [r for r in rels if r.relationship_type == "MAY_CREATE_LAMBDA"]
        assert len(lambda_edges) == 1
        
        edge = lambda_edges[0]
        
        # Property 1: Evidence should be present
        assert edge.evidence is not None
        
        # Property 2: Evidence should contain permission
        assert edge.evidence.permission == action
        
        # Property 3: Evidence should contain raw_statement
        assert edge.evidence.raw_statement == statement
        
        # Property 4: If policy_sid was provided, it should be in evidence
        if policy_sid:
            assert edge.evidence.policy_sid == policy_sid
        
        # Property 5: Evidence should contain policy_arn
        assert edge.evidence.policy_arn == policy_arn
