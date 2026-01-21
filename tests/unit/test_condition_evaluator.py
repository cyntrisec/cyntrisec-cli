"""
Property tests for ConditionEvaluator tri-state evaluation.

**Feature: capability-graph-upgrade, Property 8: Condition Evaluation Tri-State**
**Validates: Requirements 7.2, 7.3, 7.4**
"""
from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

from cyntrisec.aws.relationship_builder import ConditionEvaluator, EvaluationContext
from cyntrisec.core.schema import ConditionResult


class TestConditionEvaluatorBasic:
    """Basic unit tests for ConditionEvaluator."""

    @pytest.fixture
    def evaluator(self):
        return ConditionEvaluator()

    @pytest.fixture
    def context_with_vpce(self):
        return EvaluationContext(source_vpce="vpce-12345678")

    @pytest.fixture
    def context_with_tags(self):
        return EvaluationContext(
            principal_tags={"Environment": "Production", "Team": "Security"}
        )

    @pytest.fixture
    def empty_context(self):
        return EvaluationContext()

    def test_empty_conditions_returns_true(self, evaluator, empty_context):
        result = evaluator.evaluate({}, empty_context)
        assert result == ConditionResult.TRUE

    def test_none_conditions_returns_true(self, evaluator, empty_context):
        result = evaluator.evaluate(None, empty_context)
        assert result == ConditionResult.TRUE

    def test_source_vpce_string_equals_match(self, evaluator, context_with_vpce):
        conditions = {"StringEquals": {"aws:SourceVpce": "vpce-12345678"}}
        result = evaluator.evaluate(conditions, context_with_vpce)
        assert result == ConditionResult.TRUE

    def test_source_vpce_string_equals_no_match(self, evaluator, context_with_vpce):
        conditions = {"StringEquals": {"aws:SourceVpce": "vpce-99999999"}}
        result = evaluator.evaluate(conditions, context_with_vpce)
        assert result == ConditionResult.FALSE
