"""EC2 Normalizer - Transform EC2 data to canonical schema."""

from __future__ import annotations

import uuid
from typing import Any

from cyntrisec.core.schema import Asset, Finding, FindingSeverity, Relationship


class Ec2Normalizer:
    """Normalize EC2 data to canonical assets, relationships, and findings."""

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
        """Normalize EC2 data."""
        assets: list[Asset] = []
        relationships: list[Relationship] = []
        findings: list[Finding] = []

        for instance in data.get("instances", []):
            asset, rels, findings_list = self._normalize_instance(instance)
            assets.append(asset)
            relationships.extend(rels)
            findings.extend(findings_list)

        return assets, relationships, findings

    def _normalize_instance(
        self,
        instance: dict[str, Any],
    ) -> tuple[Asset, list[Relationship], list[Finding]]:
        """Normalize a single EC2 instance."""
        instance_id = instance["InstanceId"]
        instance_type = instance.get("InstanceType", "unknown")
        state = instance.get("State", {}).get("Name", "unknown")

        # Get name from tags
        name = instance_id
        tags = {}
        for tag in instance.get("Tags", []):
            tags[tag["Key"]] = tag["Value"]
            if tag["Key"] == "Name":
                name = tag["Value"]

        # Determine if internet-facing
        public_ip = instance.get("PublicIpAddress")
        is_internet_facing = bool(public_ip)

        asset = Asset(
            snapshot_id=self._snapshot_id,
            asset_type="ec2:instance",
            aws_region=self._region,
            aws_resource_id=instance_id,
            arn=f"arn:aws:ec2:{self._region}:{self._account_id}:instance/{instance_id}",
            name=name,
            properties={
                "instance_type": instance_type,
                "state": state,
                "vpc_id": instance.get("VpcId"),
                "subnet_id": instance.get("SubnetId"),
                "public_ip": public_ip,
                "private_ip": instance.get("PrivateIpAddress"),
                "security_groups": [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
                "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn"),
            },
            tags=tags,
            is_internet_facing=is_internet_facing,
        )

        findings: list[Finding] = []

        # Check for public IP
        if public_ip:
            findings.append(
                Finding(
                    snapshot_id=self._snapshot_id,
                    asset_id=asset.id,
                    finding_type="ec2-public-ip",
                    severity=FindingSeverity.info,
                    title=f"EC2 instance {instance_id} has public IP",
                    description=f"Instance has public IP address {public_ip}",
                    evidence={"public_ip": public_ip},
                )
            )

        # Check for missing IMDSv2
        metadata_options = instance.get("MetadataOptions", {})
        if metadata_options.get("HttpTokens") != "required":
            findings.append(
                Finding(
                    snapshot_id=self._snapshot_id,
                    asset_id=asset.id,
                    finding_type="ec2-imdsv1-enabled",
                    severity=FindingSeverity.medium,
                    title=f"EC2 instance {instance_id} allows IMDSv1",
                    description="Instance Metadata Service v1 is enabled, which is vulnerable to SSRF attacks",
                    remediation="Require IMDSv2 by setting HttpTokens to 'required'",
                    evidence={"metadata_options": metadata_options},
                )
            )

        return asset, [], findings
