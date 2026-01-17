"""Network Collector - Collect VPCs, subnets, security groups."""
from __future__ import annotations

from typing import Any, Dict, List

import boto3


class NetworkCollector:
    """Collect network resources."""

    def __init__(self, session: boto3.Session, region: str):
        self._session = session
        self._ec2 = session.client("ec2", region_name=region)
        self._region = region

    def collect_all(self) -> Dict[str, Any]:
        """Collect all network data."""
        return {
            "vpcs": self._collect_vpcs(),
            "subnets": self._collect_subnets(),
            "security_groups": self._collect_security_groups(),
            "route_tables": self._collect_route_tables(),
            "internet_gateways": self._collect_internet_gateways(),
            "nat_gateways": self._collect_nat_gateways(),
            "load_balancers": self._collect_load_balancers(),
        }

    def _collect_vpcs(self) -> List[Dict]:
        """Collect VPCs."""
        response = self._ec2.describe_vpcs()
        return response.get("Vpcs", [])

    def _collect_subnets(self) -> List[Dict]:
        """Collect subnets."""
        response = self._ec2.describe_subnets()
        return response.get("Subnets", [])

    def _collect_security_groups(self) -> List[Dict]:
        """Collect security groups."""
        sgs = []
        paginator = self._ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            sgs.extend(page.get("SecurityGroups", []))
        return sgs

    def _collect_route_tables(self) -> List[Dict]:
        """Collect route tables."""
        response = self._ec2.describe_route_tables()
        return response.get("RouteTables", [])

    def _collect_internet_gateways(self) -> List[Dict]:
        """Collect internet gateways."""
        response = self._ec2.describe_internet_gateways()
        return response.get("InternetGateways", [])

    def _collect_nat_gateways(self) -> List[Dict]:
        """Collect NAT gateways."""
        response = self._ec2.describe_nat_gateways()
        return response.get("NatGateways", [])

    def _collect_load_balancers(self) -> List[Dict]:
        """Collect ELBv2 load balancers."""
        try:
            elb = self._session.client("elbv2", region_name=self._region)
            response = elb.describe_load_balancers()
            return response.get("LoadBalancers", [])
        except Exception:
            return []
