"""Unit tests for Lambda Collector."""

from __future__ import annotations

from unittest.mock import MagicMock

import boto3
from botocore.exceptions import ClientError

from cyntrisec.aws.collectors.lambda_ import LambdaCollector


def _make_collector():
    session = MagicMock(spec=boto3.Session)
    client = MagicMock()
    session.client.return_value = client
    return LambdaCollector(session, "us-east-1"), client


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "err"}}, "op")


class TestLambdaCollector:
    def test_collect_all_enriches_with_policy(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"Functions": [{"FunctionName": "fn1"}]}
        ]
        client.get_policy.return_value = {"Policy": '{"Statement": []}'}

        result = collector.collect_all()
        assert len(result["functions"]) == 1
        assert result["functions"][0]["Policy"] == {"Policy": '{"Statement": []}'}

    def test_collect_functions_pagination(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"Functions": [{"FunctionName": "fn1"}]},
            {"Functions": [{"FunctionName": "fn2"}]},
        ]

        result = collector._collect_functions()
        assert len(result) == 2

    def test_get_function_policy_happy_path(self):
        collector, client = _make_collector()
        client.get_policy.return_value = {"Policy": '{"stmt": []}'}

        result = collector._get_function_policy("fn1")
        assert result == {"Policy": '{"stmt": []}'}

    def test_get_function_policy_resource_not_found(self):
        collector, client = _make_collector()
        client.get_policy.side_effect = _client_error("ResourceNotFoundException")

        result = collector._get_function_policy("fn1")
        assert result is None

    def test_get_function_policy_other_error(self):
        collector, client = _make_collector()
        client.get_policy.side_effect = _client_error("AccessDeniedException")

        result = collector._get_function_policy("fn1")
        assert "Error" in result

    def test_collect_functions_empty(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [{}]

        result = collector._collect_functions()
        assert result == []
