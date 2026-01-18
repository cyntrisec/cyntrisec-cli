"""RDS Collector - Collect RDS instances."""

from __future__ import annotations

from typing import Any

import boto3


class RdsCollector:
    """Collect RDS resources."""

    def __init__(self, session: boto3.Session, region: str):
        self._rds = session.client("rds", region_name=region)
        self._region = region

    def collect_all(self) -> dict[str, Any]:
        """Collect all RDS data."""
        return {
            "instances": self._collect_instances(),
            "clusters": self._collect_clusters(),
        }

    def _collect_instances(self) -> list[dict]:
        """Collect RDS DB instances."""
        instances = []
        paginator = self._rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))
        return instances

    def _collect_clusters(self) -> list[dict]:
        """Collect RDS Aurora clusters."""
        clusters = []
        paginator = self._rds.get_paginator("describe_db_clusters")
        for page in paginator.paginate():
            clusters.extend(page.get("DBClusters", []))
        return clusters
