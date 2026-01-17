"""
Relationship Builder - Create relationships between assets from different normalizers.

This module runs after all normalizers have completed to wire up cross-service connections:
- Security Group → EC2 Instance (PROTECTS)
- Subnet → EC2 Instance (CONTAINS)
- IAM Role → EC2 Instance (ATTACHED_TO via instance profile)
- Security Group (open to world) → EC2 Instance = Internet entry path
"""
from __future__ import annotations

import uuid
from typing import Dict, List, Set

from cyntrisec.core.schema import Asset, Relationship


class RelationshipBuilder:
    """
    Build relationships between assets from different sources.
    
    This is a post-processing step that runs after all normalizers complete.
    It creates edges that require knowledge of both source and target assets.
    """

    def __init__(self, snapshot_id: uuid.UUID):
        self._snapshot_id = snapshot_id

    def build(
        self,
        assets: List[Asset],
    ) -> List[Relationship]:
        """
        Build all cross-service relationships.
        
        Args:
            assets: All assets from all normalizers
            
        Returns:
            List of new relationships to add
        """
        relationships: List[Relationship] = []
        
        # Index assets by type and resource ID for fast lookup
        by_type: Dict[str, List[Asset]] = {}
        by_resource_id: Dict[str, Asset] = {}
        sg_by_id: Dict[str, Asset] = {}
        subnet_by_id: Dict[str, Asset] = {}
        instance_by_profile_arn: Dict[str, Asset] = {}
        
        for asset in assets:
            by_type.setdefault(asset.asset_type, []).append(asset)
            by_resource_id[asset.aws_resource_id] = asset
            
            if asset.asset_type == "ec2:security-group":
                sg_by_id[asset.aws_resource_id] = asset
            elif asset.asset_type == "ec2:subnet":
                subnet_by_id[asset.aws_resource_id] = asset
        
        # Process EC2 instances
        for instance in by_type.get("ec2:instance", []):
            props = instance.properties
            
            # Security Group → Instance
            for sg_id in props.get("security_groups", []):
                if sg_id in sg_by_id:
                    sg_asset = sg_by_id[sg_id]
                    
                    # Check if SG is open to world (entry point for attack path)
                    is_open_to_world = self._is_sg_open_to_world(sg_asset)
                    
                    relationships.append(Relationship(
                        snapshot_id=self._snapshot_id,
                        source_asset_id=sg_asset.id,
                        target_asset_id=instance.id,
                        relationship_type="ALLOWS_TRAFFIC_TO",
                        properties={
                            "open_to_world": is_open_to_world,
                        },
                    ))
            
            # Subnet → Instance
            subnet_id = props.get("subnet_id")
            if subnet_id and subnet_id in subnet_by_id:
                relationships.append(Relationship(
                    snapshot_id=self._snapshot_id,
                    source_asset_id=subnet_by_id[subnet_id].id,
                    target_asset_id=instance.id,
                    relationship_type="CONTAINS",
                ))
            
            # IAM Instance Profile → Instance
            # Direction: Instance → Role (instance CAN_ASSUME the role)
            profile_arn = props.get("iam_instance_profile")
            if profile_arn:
                # Instance profile ARN: arn:aws:iam::ACCOUNT:instance-profile/NAME
                profile_name = profile_arn.split("/")[-1] if "/" in profile_arn else None
                for role in by_type.get("iam:role", []):
                    if profile_name and profile_name in role.name:
                        # Instance CAN_ASSUME the role via instance profile
                        relationships.append(Relationship(
                            snapshot_id=self._snapshot_id,
                            source_asset_id=instance.id,  # FROM instance
                            target_asset_id=role.id,      # TO role
                            relationship_type="CAN_ASSUME",
                            properties={"via": "instance_profile"},
                        ))
        
        # Process Lambda functions - they CAN_ASSUME their execution roles
        for func in by_type.get("lambda:function", []):
            role_arn = func.properties.get("role")
            if role_arn:
                for role in by_type.get("iam:role", []):
                    if role.arn == role_arn:
                        # Lambda CAN_ASSUME its execution role
                        relationships.append(Relationship(
                            snapshot_id=self._snapshot_id,
                            source_asset_id=func.id,  # FROM lambda
                            target_asset_id=role.id,  # TO role
                            relationship_type="CAN_ASSUME",
                            properties={"via": "execution_role"},
                        ))
        
        # Process Load Balancers
        for lb in by_type.get("elbv2:load-balancer", []):
            props = lb.properties
            
            # LB → Security Groups it uses
            for sg_id in props.get("security_groups", []):
                if sg_id in sg_by_id:
                    relationships.append(Relationship(
                        snapshot_id=self._snapshot_id,
                        source_asset_id=lb.id,
                        target_asset_id=sg_by_id[sg_id].id,
                        relationship_type="USES",
                    ))
        
        # Create Internet → Entry Point relationships
        # For assets that are marked as internet_facing
        internet_entry_count = 0
        for asset in assets:
            if asset.is_internet_facing and asset.asset_type == "ec2:instance":
                # If instance is internet facing, the SGs protecting it form the entry path
                for sg_id in asset.properties.get("security_groups", []):
                    if sg_id in sg_by_id:
                        sg = sg_by_id[sg_id]
                        if self._is_sg_open_to_world(sg):
                            internet_entry_count += 1
        
        # Collect all IAM roles that are used by EC2 instances
        instance_roles: Set[uuid.UUID] = set()
        for instance in by_type.get("ec2:instance", []):
            profile_arn = instance.properties.get("iam_instance_profile")
            if profile_arn:
                profile_name = profile_arn.split("/")[-1] if "/" in profile_arn else None
                for role in by_type.get("iam:role", []):
                    if profile_name and profile_name in role.name:
                        instance_roles.add(role.id)
        
        # Also add Lambda execution roles
        for func in by_type.get("lambda:function", []):
            role_arn = func.properties.get("role")
            if role_arn:
                for role in by_type.get("iam:role", []):
                    if role.arn == role_arn:
                        instance_roles.add(role.id)
        
        # Create relationships from instance/lambda roles to all sensitive targets
        # This is an abstraction: "role CAN_ACCESS sensitive resource"
        # In reality this requires policy analysis, but for MVP we assume
        # any compute role COULD access sensitive S3 buckets
        sensitive_targets = [a for a in assets if a.is_sensitive_target]
        for role_id in instance_roles:
            for target in sensitive_targets:
                # Don't create self-loops
                if role_id != target.id:
                    relationships.append(Relationship(
                        snapshot_id=self._snapshot_id,
                        source_asset_id=role_id,
                        target_asset_id=target.id,
                        relationship_type="MAY_ACCESS",
                        properties={"via": "iam_policy_assumption"},
                    ))
        
        return relationships

    def _is_sg_open_to_world(self, sg_asset: Asset) -> bool:
        """Check if a security group has 0.0.0.0/0 ingress rules."""
        for rule in sg_asset.properties.get("ingress_rules", []):
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    return True
            # Also check IPv6
            for ip_range in rule.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    return True
        return False
