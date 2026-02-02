"""Unit tests for Network Collector."""

from __future__ import annotations

from unittest.mock import MagicMock

import boto3
from botocore.exceptions import ClientError

from cyntrisec.aws.collectors.network import NetworkCollector


def _make_collector():
    session = MagicMock(spec=boto3.Session)
    ec2_client = MagicMock()
    elb_client = MagicMock()

    def client_factory(service, **kwargs):
        if service == "elbv2":
            return elb_client
        return ec2_client

    session.client.side_effect = client_factory
    collector = NetworkCollector(session, "us-east-1")
    return collector, ec2_client, elb_client


class TestNetworkCollectorCollectAll:
    def test_collect_all_returns_seven_keys(self):
        collector, ec2, elb = _make_collector()
        pag = MagicMock()
        pag.paginate.return_value = [{}]
        ec2.get_paginator.return_value = pag
        elb.get_paginator.return_value = pag

        result = collector.collect_all()
        expected_keys = {
            "vpcs", "subnets", "security_groups", "route_tables",
            "internet_gateways", "nat_gateways", "load_balancers",
        }
        assert set(result.keys()) == expected_keys

    def test_collect_vpcs(self):
        collector, ec2, _ = _make_collector()
        pag = MagicMock()
        ec2.get_paginator.return_value = pag
        pag.paginate.return_value = [{"Vpcs": [{"VpcId": "vpc-1"}]}]

        result = collector._collect_vpcs()
        assert len(result) == 1
        assert result[0]["VpcId"] == "vpc-1"

    def test_collect_subnets(self):
        collector, ec2, _ = _make_collector()
        pag = MagicMock()
        ec2.get_paginator.return_value = pag
        pag.paginate.return_value = [{"Subnets": [{"SubnetId": "sn-1"}]}]

        result = collector._collect_subnets()
        assert len(result) == 1

    def test_collect_security_groups(self):
        collector, ec2, _ = _make_collector()
        pag = MagicMock()
        ec2.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"SecurityGroups": [{"GroupId": "sg-1"}]}
        ]

        result = collector._collect_security_groups()
        assert len(result) == 1

    def test_collect_route_tables(self):
        collector, ec2, _ = _make_collector()
        pag = MagicMock()
        ec2.get_paginator.return_value = pag
        pag.paginate.return_value = [{"RouteTables": [{"RouteTableId": "rt-1"}]}]

        result = collector._collect_route_tables()
        assert len(result) == 1

    def test_collect_internet_gateways(self):
        collector, ec2, _ = _make_collector()
        pag = MagicMock()
        ec2.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"InternetGateways": [{"InternetGatewayId": "igw-1"}]}
        ]

        result = collector._collect_internet_gateways()
        assert len(result) == 1

    def test_collect_nat_gateways(self):
        collector, ec2, _ = _make_collector()
        pag = MagicMock()
        ec2.get_paginator.return_value = pag
        pag.paginate.return_value = [{"NatGateways": [{"NatGatewayId": "nat-1"}]}]

        result = collector._collect_nat_gateways()
        assert len(result) == 1

    def test_collect_load_balancers_happy_path(self):
        collector, _, elb = _make_collector()
        pag = MagicMock()
        elb.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"LoadBalancers": [{"LoadBalancerArn": "arn:lb1"}]}
        ]

        result = collector._collect_load_balancers()
        assert len(result) == 1

    def test_collect_load_balancers_error_returns_empty(self):
        collector, _, elb = _make_collector()
        # Override session.client to raise when creating elbv2 client
        collector._session.client.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "op"
        )

        result = collector._collect_load_balancers()
        assert result == []

    def test_collect_vpcs_multi_page(self):
        collector, ec2, _ = _make_collector()
        pag = MagicMock()
        ec2.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"Vpcs": [{"VpcId": "vpc-1"}]},
            {"Vpcs": [{"VpcId": "vpc-2"}]},
        ]

        result = collector._collect_vpcs()
        assert len(result) == 2
