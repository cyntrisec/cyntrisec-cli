"""Network Normalizer - Transform network data to canonical schema."""

from __future__ import annotations

import uuid
from typing import Any

from cyntrisec.core.schema import Asset, Finding, FindingSeverity, Relationship


class NetworkNormalizer:
    """Normalize network data to canonical assets and relationships."""

    def __init__(
        self,
        snapshot_id: uuid.UUID,
        region: str,
        account_id: str,
    ):
        self._snapshot_id = snapshot_id
        self._region = region
        self._account_id = account_id
        self._asset_map: dict[str, Asset] = {}

    def normalize(
        self,
        data: dict[str, Any],
    ) -> tuple[list[Asset], list[Relationship], list[Finding]]:
        """Normalize network data."""
        assets: list[Asset] = []
        relationships: list[Relationship] = []
        findings: list[Finding] = []

        # VPCs
        for vpc in data.get("vpcs", []):
            asset = self._normalize_vpc(vpc)
            assets.append(asset)
            self._asset_map[vpc["VpcId"]] = asset

        # Subnets
        for subnet in data.get("subnets", []):
            asset = self._normalize_subnet(subnet)
            assets.append(asset)
            self._asset_map[subnet["SubnetId"]] = asset

            # Create VPC -> Subnet relationship
            vpc_id = subnet.get("VpcId")
            if vpc_id and vpc_id in self._asset_map:
                relationships.append(
                    Relationship(
                        snapshot_id=self._snapshot_id,
                        source_asset_id=self._asset_map[vpc_id].id,
                        target_asset_id=asset.id,
                        relationship_type="CONTAINS",
                    )
                )

        # Security Groups
        for sg in data.get("security_groups", []):
            asset, sg_findings = self._normalize_security_group(sg)
            assets.append(asset)
            self._asset_map[sg["GroupId"]] = asset
            findings.extend(sg_findings)

        # Load Balancers
        for lb in data.get("load_balancers", []):
            asset = self._normalize_load_balancer(lb)
            assets.append(asset)

        return assets, relationships, findings

    def _normalize_vpc(self, vpc: dict[str, Any]) -> Asset:
        """Normalize a VPC."""
        vpc_id = vpc["VpcId"]

        name = vpc_id
        for tag in vpc.get("Tags", []):
            if tag["Key"] == "Name":
                name = tag["Value"]
                break

        return Asset(
            snapshot_id=self._snapshot_id,
            asset_type="ec2:vpc",
            aws_region=self._region,
            aws_resource_id=vpc_id,
            arn=f"arn:aws:ec2:{self._region}:{self._account_id}:vpc/{vpc_id}",
            name=name,
            properties={
                "cidr_block": vpc.get("CidrBlock"),
                "is_default": vpc.get("IsDefault", False),
                "state": vpc.get("State"),
            },
        )

    def _normalize_subnet(self, subnet: dict[str, Any]) -> Asset:
        """Normalize a subnet."""
        subnet_id = subnet["SubnetId"]

        name = subnet_id
        for tag in subnet.get("Tags", []):
            if tag["Key"] == "Name":
                name = tag["Value"]
                break

        # Determine if public (has auto-assign public IP)
        is_public = subnet.get("MapPublicIpOnLaunch", False)

        return Asset(
            snapshot_id=self._snapshot_id,
            asset_type="ec2:subnet",
            aws_region=self._region,
            aws_resource_id=subnet_id,
            arn=f"arn:aws:ec2:{self._region}:{self._account_id}:subnet/{subnet_id}",
            name=name,
            properties={
                "vpc_id": subnet.get("VpcId"),
                "cidr_block": subnet.get("CidrBlock"),
                "availability_zone": subnet.get("AvailabilityZone"),
                "map_public_ip_on_launch": is_public,
            },
            is_internet_facing=is_public,
        )

    def _normalize_security_group(
        self,
        sg: dict[str, Any],
    ) -> tuple[Asset, list[Finding]]:
        """Normalize a security group."""
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)

        asset = Asset(
            snapshot_id=self._snapshot_id,
            asset_type="ec2:security-group",
            aws_region=self._region,
            aws_resource_id=sg_id,
            arn=f"arn:aws:ec2:{self._region}:{self._account_id}:security-group/{sg_id}",
            name=sg_name,
            properties={
                "vpc_id": sg.get("VpcId"),
                "description": sg.get("Description"),
                "ingress_rules": sg.get("IpPermissions", []),
                "egress_rules": sg.get("IpPermissionsEgress", []),
            },
        )

        findings: list[Finding] = []

        # Check for overly permissive ingress rules
        for rule in sg.get("IpPermissions", []):
            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    from_port = rule.get("FromPort", "all")
                    to_port = rule.get("ToPort", "all")
                    protocol = rule.get("IpProtocol", "all")
                    severity = self._severity_for_open_rule(from_port, to_port, protocol)

                    findings.append(
                        Finding(
                            snapshot_id=self._snapshot_id,
                            asset_id=asset.id,
                            finding_type="security-group-open-to-world",
                            severity=severity,
                            title=f"Security group {sg_name} allows inbound from 0.0.0.0/0",
                            description=f"Ingress rule allows traffic from anywhere on port {from_port}-{to_port}",
                            remediation="Restrict the source IP range to known addresses",
                            evidence={"rule": rule, "cidr": cidr},
                        )
                    )
            for ip_range in rule.get("Ipv6Ranges", []):
                cidr = ip_range.get("CidrIpv6", "")
                if cidr == "::/0":
                    from_port = rule.get("FromPort", "all")
                    to_port = rule.get("ToPort", "all")
                    protocol = rule.get("IpProtocol", "all")
                    severity = self._severity_for_open_rule(from_port, to_port, protocol)

                    findings.append(
                        Finding(
                            snapshot_id=self._snapshot_id,
                            asset_id=asset.id,
                            finding_type="security-group-open-to-world",
                            severity=severity,
                            title=f"Security group {sg_name} allows inbound from ::/0",
                            description=f"Ingress rule allows traffic from anywhere on port {from_port}-{to_port}",
                            remediation="Restrict the source IP range to known addresses",
                            evidence={"rule": rule, "cidr": cidr},
                        )
                    )

        return asset, findings

    @staticmethod
    def _severity_for_open_rule(from_port, to_port, protocol) -> FindingSeverity:
        """Determine severity for an open ingress rule."""
        if from_port in [22, 3389] or to_port in [22, 3389]:
            return FindingSeverity.critical
        if protocol == "-1":
            return FindingSeverity.critical
        return FindingSeverity.high

    def _normalize_load_balancer(self, lb: dict[str, Any]) -> Asset:
        """Normalize a load balancer."""
        lb_arn = lb["LoadBalancerArn"]
        lb_name = lb.get("LoadBalancerName", lb_arn.split("/")[-1])
        scheme = lb.get("Scheme", "internal")

        return Asset(
            snapshot_id=self._snapshot_id,
            asset_type="elbv2:load-balancer",
            aws_region=self._region,
            aws_resource_id=lb_arn,
            arn=lb_arn,
            name=lb_name,
            properties={
                "type": lb.get("Type"),
                "scheme": scheme,
                "dns_name": lb.get("DNSName"),
                "vpc_id": lb.get("VpcId"),
                "security_groups": lb.get("SecurityGroups", []),
            },
            is_internet_facing=(scheme == "internet-facing"),
        )
