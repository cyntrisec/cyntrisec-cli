"""
Property tests for ActionParser wildcard action matching.

**Feature: capability-graph-upgrade, Property 4: Wildcard Action Matching**
**Validates: Requirements 4.4**

For any IAM policy action pattern containing wildcards (e.g., "s3:Get*"), the ActionParser
SHALL correctly match all actions that the wildcard covers (e.g., s3:GetObject, s3:GetBucketPolicy),
and the RelationshipBuilder SHALL create capability edges for all matched capability-granting actions.
"""
from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck, assume

from cyntrisec.aws.relationship_builder import ActionParser


class TestActionParserBasic:
    """Basic unit tests for ActionParser."""

    @pytest.fixture
    def parser(self):
        return ActionParser()

    def test_exact_action_match(self, parser):
        """Test exact action matching."""
        statement = {"Action": "secretsmanager:GetSecretValue"}
        matched = parser.get_matched_capabilities(statement)
        assert "secretsmanager:GetSecretValue" in matched

    def test_wildcard_service_match(self, parser):
        """Test service-level wildcard matching (s3:*)."""
        statement = {"Action": "s3:*"}
        matched = parser.get_matched_capabilities(statement)
        assert "s3:GetObject" in matched

    def test_wildcard_action_prefix_match(self, parser):
        """Test action prefix wildcard matching (s3:Get*)."""
        statement = {"Action": "s3:Get*"}
        matched = parser.get_matched_capabilities(statement)
        assert "s3:GetObject" in matched

    def test_full_wildcard_match(self, parser):
        """Test full wildcard (*) matches all capabilities."""
        statement = {"Action": "*"}
        matched = parser.get_matched_capabilities(statement)
        # Should match all capability actions
        assert len(matched) == len(parser.CAPABILITY_ACTIONS)

    def test_no_match_for_unrelated_action(self, parser):
        """Test that unrelated actions don't match capabilities."""
        statement = {"Action": "ec2:DescribeInstances"}
        matched = parser.get_matched_capabilities(statement)
        assert len(matched) == 0

    def test_multiple_actions_in_list(self, parser):
        """Test multiple actions in a list."""
        statement = {"Action": ["s3:GetObject", "kms:Decrypt"]}
        matched = parser.get_matched_capabilities(statement)
        assert "s3:GetObject" in matched
        assert "kms:Decrypt" in matched

    def test_not_action_excludes_capability(self, parser):
        """Test NotAction excludes specific capabilities."""
        # NotAction means "allow everything EXCEPT these"
        statement = {"NotAction": "s3:GetObject"}
        matched = parser.get_matched_capabilities(statement)
        # s3:GetObject should NOT be in matched
        assert "s3:GetObject" not in matched
        # But other capabilities should be matched
        assert "secretsmanager:GetSecretValue" in matched
        assert "kms:Decrypt" in matched

    def test_not_action_with_wildcard(self, parser):
        """Test NotAction with wildcard excludes matching capabilities."""
        statement = {"NotAction": "s3:*"}
        matched = parser.get_matched_capabilities(statement)
        # s3:GetObject should NOT be in matched
        assert "s3:GetObject" not in matched
        # But other capabilities should be matched
        assert "secretsmanager:GetSecretValue" in matched

    def test_empty_statement(self, parser):
        """Test empty statement returns no matches."""
        statement = {}
        matched = parser.get_matched_capabilities(statement)
        assert len(matched) == 0

    def test_case_insensitive_matching(self, parser):
        """Test that action matching is case-insensitive."""
        statement = {"Action": "S3:GETOBJECT"}
        matched = parser.get_matched_capabilities(statement)
        assert "s3:GetObject" in matched

    def test_ssm_parameter_actions(self, parser):
        """Test SSM parameter actions are matched."""
        statement = {"Action": ["ssm:GetParameter", "ssm:GetParameters"]}
        matched = parser.get_matched_capabilities(statement)
        assert "ssm:GetParameter" in matched
        assert "ssm:GetParameters" in matched

    def test_ssm_wildcard_match(self, parser):
        """Test SSM wildcard matches parameter actions."""
        statement = {"Action": "ssm:Get*"}
        matched = parser.get_matched_capabilities(statement)
        assert "ssm:GetParameter" in matched
        assert "ssm:GetParameters" in matched
        assert "ssm:GetParametersByPath" in matched

    def test_lambda_create_function(self, parser):
        """Test Lambda CreateFunction is matched."""
        statement = {"Action": "lambda:CreateFunction"}
        matched = parser.get_matched_capabilities(statement)
        assert "lambda:CreateFunction" in matched

    def test_lambda_wildcard_match(self, parser):
        """Test Lambda wildcard matches create/update actions."""
        statement = {"Action": "lambda:*"}
        matched = parser.get_matched_capabilities(statement)
        assert "lambda:CreateFunction" in matched
        assert "lambda:UpdateFunctionConfiguration" in matched

    def test_iam_pass_role(self, parser):
        """Test iam:PassRole is matched."""
        statement = {"Action": "iam:PassRole"}
        matched = parser.get_matched_capabilities(statement)
        assert "iam:PassRole" in matched

    def test_get_edge_type_for_action(self, parser):
        """Test get_edge_type_for_action returns correct edge types."""
        assert parser.get_edge_type_for_action("secretsmanager:GetSecretValue") == "MAY_READ_SECRET"
        assert parser.get_edge_type_for_action("ssm:GetParameter") == "MAY_READ_PARAMETER"
        assert parser.get_edge_type_for_action("kms:Decrypt") == "MAY_DECRYPT"
        assert parser.get_edge_type_for_action("s3:GetObject") == "MAY_READ_S3_OBJECT"
        assert parser.get_edge_type_for_action("lambda:CreateFunction") == "MAY_CREATE_LAMBDA"
        assert parser.get_edge_type_for_action("iam:PassRole") == "CAN_PASS_TO"
        assert parser.get_edge_type_for_action("ec2:DescribeInstances") is None


class TestActionParserWildcardProperty:
    """
    Property tests for wildcard action matching.
    
    **Feature: capability-graph-upgrade, Property 4: Wildcard Action Matching**
    **Validates: Requirements 4.4**
    """

    @pytest.fixture
    def parser(self):
        return ActionParser()

    # Strategy for generating valid IAM action patterns
    @st.composite
    def iam_action_pattern(draw):
        """Generate valid IAM action patterns."""
        services = ["s3", "secretsmanager", "ssm", "kms", "lambda", "iam", "ec2", "rds"]
        service = draw(st.sampled_from(services))
        
        # Generate action part: either specific, prefix wildcard, or full wildcard
        action_type = draw(st.sampled_from(["specific", "prefix", "full_wildcard", "service_wildcard"]))
        
        if action_type == "specific":
            actions = {
                "s3": ["GetObject", "PutObject", "DeleteObject"],
                "secretsmanager": ["GetSecretValue", "CreateSecret"],
                "ssm": ["GetParameter", "GetParameters", "GetParametersByPath"],
                "kms": ["Decrypt", "Encrypt"],
                "lambda": ["CreateFunction", "UpdateFunctionConfiguration", "InvokeFunction"],
                "iam": ["PassRole", "CreateRole"],
                "ec2": ["DescribeInstances", "RunInstances"],
                "rds": ["DescribeDBInstances"],
            }
            action = draw(st.sampled_from(actions.get(service, ["Action"])))
            return f"{service}:{action}"
        elif action_type == "prefix":
            prefixes = ["Get", "Put", "Create", "Delete", "Describe", "Update"]
            prefix = draw(st.sampled_from(prefixes))
            return f"{service}:{prefix}*"
        elif action_type == "service_wildcard":
            return f"{service}:*"
        else:  # full_wildcard
            return "*"

    @given(st.lists(iam_action_pattern(), min_size=1, max_size=5))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
    def test_wildcard_matching_consistency(self, action_patterns):
        """
        Property test: For any set of action patterns, the matched capabilities
        should be consistent with fnmatch semantics.
        
        **Feature: capability-graph-upgrade, Property 4: Wildcard Action Matching**
        **Validates: Requirements 4.4**
        """
        parser = ActionParser()
        statement = {"Action": action_patterns}
        matched = parser.get_matched_capabilities(statement)
        
        # Verify: every matched capability should be matchable by at least one pattern
        for capability in matched:
            found_match = False
            for pattern in action_patterns:
                if parser._any_pattern_matches([pattern], capability):
                    found_match = True
                    break
            assert found_match, (
                f"Capability {capability} was matched but no pattern in {action_patterns} matches it"
            )

    @given(st.sampled_from(list(ActionParser.CAPABILITY_ACTIONS.keys())))
    @settings(max_examples=100)
    def test_exact_capability_always_matches_itself(self, capability_action):
        """
        Property test: Any capability action should always match when specified exactly.
        
        **Feature: capability-graph-upgrade, Property 4: Wildcard Action Matching**
        **Validates: Requirements 4.4**
        """
        parser = ActionParser()
        statement = {"Action": capability_action}
        matched = parser.get_matched_capabilities(statement)
        
        assert capability_action in matched, (
            f"Exact action {capability_action} should match itself"
        )

    @given(st.sampled_from(["s3", "secretsmanager", "ssm", "kms", "lambda", "iam"]))
    @settings(max_examples=100)
    def test_service_wildcard_matches_all_service_capabilities(self, service):
        """
        Property test: A service wildcard (service:*) should match all capabilities
        for that service.
        
        **Feature: capability-graph-upgrade, Property 4: Wildcard Action Matching**
        **Validates: Requirements 4.4**
        """
        parser = ActionParser()
        statement = {"Action": f"{service}:*"}
        matched = parser.get_matched_capabilities(statement)
        
        # All capabilities for this service should be matched
        for capability in parser.CAPABILITY_ACTIONS:
            if capability.lower().startswith(f"{service.lower()}:"):
                assert capability in matched, (
                    f"Service wildcard {service}:* should match {capability}"
                )

    @given(st.sampled_from(list(ActionParser.CAPABILITY_ACTIONS.keys())))
    @settings(max_examples=100)
    def test_full_wildcard_matches_all_capabilities(self, capability_action):
        """
        Property test: A full wildcard (*) should match all capability actions.
        
        **Feature: capability-graph-upgrade, Property 4: Wildcard Action Matching**
        **Validates: Requirements 4.4**
        """
        parser = ActionParser()
        statement = {"Action": "*"}
        matched = parser.get_matched_capabilities(statement)
        
        assert capability_action in matched, (
            f"Full wildcard should match {capability_action}"
        )

    @given(st.sampled_from(list(ActionParser.CAPABILITY_ACTIONS.keys())))
    @settings(max_examples=100)
    def test_not_action_excludes_specified_capability(self, capability_action):
        """
        Property test: NotAction should exclude the specified capability but include others.
        
        **Feature: capability-graph-upgrade, Property 4: Wildcard Action Matching**
        **Validates: Requirements 4.4**
        """
        parser = ActionParser()
        statement = {"NotAction": capability_action}
        matched = parser.get_matched_capabilities(statement)
        
        # The specified capability should NOT be matched
        assert capability_action not in matched, (
            f"NotAction {capability_action} should exclude it from matches"
        )
        
        # Other capabilities should be matched (at least some)
        other_capabilities = [c for c in parser.CAPABILITY_ACTIONS if c != capability_action]
        if other_capabilities:
            assert len(matched) > 0, (
                f"NotAction should still match other capabilities"
            )

    @given(
        st.lists(st.sampled_from(list(ActionParser.CAPABILITY_ACTIONS.keys())), min_size=1, max_size=3),
        st.lists(st.sampled_from(list(ActionParser.CAPABILITY_ACTIONS.keys())), min_size=0, max_size=2),
    )
    @settings(max_examples=100)
    def test_action_and_not_action_interaction(self, actions, not_actions):
        """
        Property test: When both Action and NotAction are present, NotAction should
        exclude capabilities from the Action matches.
        
        **Feature: capability-graph-upgrade, Property 4: Wildcard Action Matching**
        **Validates: Requirements 4.4**
        """
        parser = ActionParser()
        
        # Only test when there's actual overlap to exclude
        assume(len(not_actions) > 0)
        
        statement = {"Action": actions, "NotAction": not_actions}
        matched = parser.get_matched_capabilities(statement)
        
        # Capabilities in NotAction should not be in matched (if they were in Action)
        for not_action in not_actions:
            if not_action in actions:
                assert not_action not in matched, (
                    f"NotAction {not_action} should exclude it even if in Action"
                )

    # Strategy for generating non-capability actions
    @st.composite
    def non_capability_action(draw):
        """Generate actions that don't match any capability."""
        # Use services that don't have capability actions
        non_capability_services = ["ec2", "rds", "dynamodb", "sqs", "sns", "cloudwatch"]
        service = draw(st.sampled_from(non_capability_services))
        actions = ["Describe", "List", "Get", "Put", "Create", "Delete"]
        action = draw(st.sampled_from(actions))
        suffix = draw(st.sampled_from(["Instances", "Tables", "Queues", "Topics", "Alarms", "Items"]))
        return f"{service}:{action}{suffix}"

    @given(non_capability_action())
    @settings(max_examples=100)
    def test_non_capability_actions_return_empty(self, random_action):
        """
        Property test: Actions that don't match any capability should return empty set.
        
        **Feature: capability-graph-upgrade, Property 4: Wildcard Action Matching**
        **Validates: Requirements 4.4**
        """
        parser = ActionParser()
        
        statement = {"Action": random_action}
        matched = parser.get_matched_capabilities(statement)
        
        assert len(matched) == 0, (
            f"Non-capability action {random_action} should not match any capabilities"
        )
