"""Unit tests for RDS Collector."""

from __future__ import annotations

from unittest.mock import MagicMock

import boto3

from cyntrisec.aws.collectors.rds import RdsCollector


def _make_collector():
    session = MagicMock(spec=boto3.Session)
    client = MagicMock()
    session.client.return_value = client
    return RdsCollector(session, "us-east-1"), client


class TestRdsCollector:
    def test_collect_all_returns_both_keys(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [{"DBInstances": [], "DBClusters": []}]

        result = collector.collect_all()
        assert "instances" in result
        assert "clusters" in result

    def test_collect_instances(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"DBInstances": [{"DBInstanceIdentifier": "db-1"}]}
        ]

        result = collector._collect_instances()
        assert len(result) == 1
        assert result[0]["DBInstanceIdentifier"] == "db-1"

    def test_collect_clusters(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"DBClusters": [{"DBClusterIdentifier": "cl-1"}]}
        ]

        result = collector._collect_clusters()
        assert len(result) == 1
        assert result[0]["DBClusterIdentifier"] == "cl-1"

    def test_collect_instances_multi_page(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"DBInstances": [{"DBInstanceIdentifier": "db-1"}]},
            {"DBInstances": [{"DBInstanceIdentifier": "db-2"}]},
        ]

        result = collector._collect_instances()
        assert len(result) == 2

    def test_collect_empty(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [{}]

        result = collector._collect_instances()
        assert result == []
