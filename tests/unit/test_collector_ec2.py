"""Unit tests for EC2 Collector."""

from __future__ import annotations

from unittest.mock import MagicMock

import boto3

from cyntrisec.aws.collectors.ec2 import Ec2Collector


def _make_collector():
    """Create an Ec2Collector with mocked session."""
    session = MagicMock(spec=boto3.Session)
    client = MagicMock()
    session.client.return_value = client
    return Ec2Collector(session, "us-east-1"), client


class TestEc2Collector:
    def test_collect_all_returns_instances_key(self):
        collector, client = _make_collector()
        paginator = MagicMock()
        client.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]}
        ]

        result = collector.collect_all()
        assert "instances" in result
        assert result["instances"] == [{"InstanceId": "i-1"}]

    def test_collect_instances_multi_page(self):
        collector, client = _make_collector()
        paginator = MagicMock()
        client.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]},
            {"Reservations": [{"Instances": [{"InstanceId": "i-2"}]}]},
        ]

        result = collector.collect_all()
        assert len(result["instances"]) == 2
        assert result["instances"][0]["InstanceId"] == "i-1"
        assert result["instances"][1]["InstanceId"] == "i-2"

    def test_collect_instances_multi_reservation(self):
        collector, client = _make_collector()
        paginator = MagicMock()
        client.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "Reservations": [
                    {"Instances": [{"InstanceId": "i-1"}]},
                    {"Instances": [{"InstanceId": "i-2"}]},
                ]
            }
        ]

        result = collector.collect_all()
        assert len(result["instances"]) == 2

    def test_collect_instances_empty(self):
        collector, client = _make_collector()
        paginator = MagicMock()
        client.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Reservations": []}]

        result = collector.collect_all()
        assert result["instances"] == []

    def test_collect_instances_missing_keys(self):
        collector, client = _make_collector()
        paginator = MagicMock()
        client.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{}]

        result = collector.collect_all()
        assert result["instances"] == []
