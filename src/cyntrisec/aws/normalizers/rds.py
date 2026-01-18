"""RDS Normalizer - Transform RDS data to canonical schema."""

from __future__ import annotations

import uuid
from typing import Any

from cyntrisec.core.schema import Asset, Finding, FindingSeverity, Relationship


class RdsNormalizer:
    """Normalize RDS data to canonical assets."""

    def __init__(
        self,
        snapshot_id: uuid.UUID,
        region: str,
        account_id: str,
    ):
        self._snapshot_id = snapshot_id
        self._region = region
        self._account_id = account_id

    def normalize(
        self,
        data: dict[str, Any],
    ) -> tuple[list[Asset], list[Relationship], list[Finding]]:
        """Normalize RDS data."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        for instance in data.get("instances", []):
            asset, instance_findings = self._normalize_instance(instance)
            assets.append(asset)
            findings.extend(instance_findings)

        for cluster in data.get("clusters", []):
            asset, cluster_findings = self._normalize_cluster(cluster)
            assets.append(asset)
            findings.extend(cluster_findings)

        return assets, [], findings

    def _normalize_instance(
        self,
        instance: dict[str, Any],
    ) -> tuple[Asset, list[Finding]]:
        """Normalize an RDS DB instance."""
        db_id = instance["DBInstanceIdentifier"]
        db_arn = instance["DBInstanceArn"]

        asset = Asset(
            snapshot_id=self._snapshot_id,
            asset_type="rds:db-instance",
            aws_region=self._region,
            aws_resource_id=db_arn,
            arn=db_arn,
            name=db_id,
            properties={
                "engine": instance.get("Engine"),
                "engine_version": instance.get("EngineVersion"),
                "instance_class": instance.get("DBInstanceClass"),
                "storage_encrypted": instance.get("StorageEncrypted"),
                "publicly_accessible": instance.get("PubliclyAccessible"),
                "multi_az": instance.get("MultiAZ"),
                "vpc_security_groups": [
                    sg["VpcSecurityGroupId"] for sg in instance.get("VpcSecurityGroups", [])
                ],
            },
            is_internet_facing=instance.get("PubliclyAccessible", False),
            is_sensitive_target=True,  # Databases are sensitive
        )

        findings: list[Finding] = []

        # Check for public accessibility
        if instance.get("PubliclyAccessible"):
            findings.append(
                Finding(
                    snapshot_id=self._snapshot_id,
                    asset_id=asset.id,
                    finding_type="rds-publicly-accessible",
                    severity=FindingSeverity.critical,
                    title=f"RDS instance {db_id} is publicly accessible",
                    description="Database is configured to be publicly accessible from the internet",
                    remediation="Disable public accessibility and use VPC endpoints or bastion hosts",
                )
            )

        # Check for encryption
        if not instance.get("StorageEncrypted"):
            findings.append(
                Finding(
                    snapshot_id=self._snapshot_id,
                    asset_id=asset.id,
                    finding_type="rds-not-encrypted",
                    severity=FindingSeverity.high,
                    title=f"RDS instance {db_id} is not encrypted",
                    description="Database storage is not encrypted at rest",
                    remediation="Enable storage encryption (requires database recreation)",
                )
            )

        return asset, findings

    def _normalize_cluster(
        self,
        cluster: dict[str, Any],
    ) -> tuple[Asset, list[Finding]]:
        """Normalize an RDS Aurora cluster."""
        cluster_id = cluster["DBClusterIdentifier"]
        cluster_arn = cluster["DBClusterArn"]

        asset = Asset(
            snapshot_id=self._snapshot_id,
            asset_type="rds:db-cluster",
            aws_region=self._region,
            aws_resource_id=cluster_arn,
            arn=cluster_arn,
            name=cluster_id,
            properties={
                "engine": cluster.get("Engine"),
                "engine_version": cluster.get("EngineVersion"),
                "storage_encrypted": cluster.get("StorageEncrypted"),
                "multi_az": cluster.get("MultiAZ"),
            },
            is_sensitive_target=True,
        )

        return asset, []
