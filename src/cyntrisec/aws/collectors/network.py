"""Network Collector - Collect VPCs, subnets, security groups."""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

log = logging.getLogger(__name__)


class NetworkCollector:
    """Collect network resources."""

    def __init__(self, session: boto3.Session, region: str):
        self._session = session
        self._ec2 = session.client("ec2", region_name=region)
        self._region = region

    def collect_all(self) -> dict[str, Any]:
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

    def _collect_vpcs(self) -> list[dict]:
        """Collect VPCs with pagination."""
        vpcs = []
        paginator = self._ec2.get_paginator("describe_vpcs")
        for page in paginator.paginate():
            vpcs.extend(page.get("Vpcs", []))
        return vpcs

    def _collect_subnets(self) -> list[dict]:
        """Collect subnets with pagination."""
        subnets = []
        paginator = self._ec2.get_paginator("describe_subnets")
        for page in paginator.paginate():
            subnets.extend(page.get("Subnets", []))
        return subnets

    def _collect_security_groups(self) -> list[dict]:
        """Collect security groups."""
        sgs = []
        paginator = self._ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            sgs.extend(page.get("SecurityGroups", []))
        return sgs

    def _collect_route_tables(self) -> list[dict]:
        """Collect route tables with pagination."""
        tables = []
        paginator = self._ec2.get_paginator("describe_route_tables")
        for page in paginator.paginate():
            tables.extend(page.get("RouteTables", []))
        return tables

    def _collect_internet_gateways(self) -> list[dict]:
        """Collect internet gateways with pagination."""
        gateways = []
        paginator = self._ec2.get_paginator("describe_internet_gateways")
        for page in paginator.paginate():
            gateways.extend(page.get("InternetGateways", []))
        return gateways

    def _collect_nat_gateways(self) -> list[dict]:
        """Collect NAT gateways with pagination."""
        gateways = []
        paginator = self._ec2.get_paginator("describe_nat_gateways")
        for page in paginator.paginate():
            gateways.extend(page.get("NatGateways", []))
        return gateways

    def _collect_load_balancers(self) -> list[dict]:
        """Collect ELBv2 load balancers with pagination."""
        try:
            elb = self._session.client("elbv2", region_name=self._region)
            lbs = []
            paginator = elb.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                lbs.extend(page.get("LoadBalancers", []))
            return lbs
        except (ClientError, BotoCoreError) as e:
            log.warning("Failed to collect load balancers in %s: %s", self._region, e)
            return []
