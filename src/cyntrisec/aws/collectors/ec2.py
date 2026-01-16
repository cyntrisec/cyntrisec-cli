"""EC2 Collector - Collect EC2 instances."""
from __future__ import annotations

from typing import Any, Dict, List

import boto3


class Ec2Collector:
    """Collect EC2 resources."""

    def __init__(self, session: boto3.Session, region: str):
        self._ec2 = session.client("ec2", region_name=region)
        self._region = region

    def collect_all(self) -> Dict[str, Any]:
        """Collect all EC2 data."""
        return {
            "instances": self._collect_instances(),
        }

    def _collect_instances(self) -> List[Dict]:
        """Collect EC2 instances."""
        instances = []
        paginator = self._ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                instances.extend(reservation.get("Instances", []))
        return instances
