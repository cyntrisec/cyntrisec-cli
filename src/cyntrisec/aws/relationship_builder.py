"""
Relationship Builder - Create relationships between assets from different normalizers.

This module runs after all normalizers have completed to wire up cross-service connections:
- Security Group → EC2 Instance (ALLOWS_TRAFFIC_TO)
- Subnet → EC2 Instance (CONTAINS)
- IAM Role → EC2 Instance (CAN_ASSUME via instance profile)
- Lambda → IAM Role (CAN_ASSUME via execution role)
- Load Balancer → Security Group (USES)
- IAM Role → Sensitive Target (MAY_ACCESS)
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
        # Indexes populated during build
        self._by_type: Dict[str, List[Asset]] = {}
        self._sg_by_id: Dict[str, Asset] = {}
        self._subnet_by_id: Dict[str, Asset] = {}

    def build(self, assets: List[Asset]) -> List[Relationship]:
        """
        Build all cross-service relationships.
        
        Args:
            assets: All assets from all normalizers
            
        Returns:
            List of new relationships to add
        """
        # Build indexes
        self._index_assets(assets)
        
        # Build relationships by category
        relationships: List[Relationship] = []
        relationships.extend(self._build_ec2_relationships())
        relationships.extend(self._build_lambda_relationships())
        relationships.extend(self._build_loadbalancer_relationships())
        relationships.extend(self._build_iam_access_relationships(assets))
        
        return relationships

    def _index_assets(self, assets: List[Asset]) -> None:
        """Build lookup indexes for fast asset access."""
        self._by_type = {}
        self._sg_by_id = {}
        self._subnet_by_id = {}
        
        for asset in assets:
            self._by_type.setdefault(asset.asset_type, []).append(asset)
            
            if asset.asset_type == "ec2:security-group":
                self._sg_by_id[asset.aws_resource_id] = asset
            elif asset.asset_type == "ec2:subnet":
                self._subnet_by_id[asset.aws_resource_id] = asset

    def _build_ec2_relationships(self) -> List[Relationship]:
        """Build relationships for EC2 instances."""
        relationships: List[Relationship] = []
        
        for instance in self._by_type.get("ec2:instance", []):
            props = instance.properties
            
            # Security Group → Instance
            relationships.extend(self._sg_to_instance_rels(instance, props))
            
            # Subnet → Instance
            rel = self._subnet_to_instance_rel(instance, props)
            if rel:
                relationships.append(rel)
            
            # Instance → IAM Role (via instance profile)
            relationships.extend(self._instance_to_role_rels(instance, props))
        
        return relationships

    def _sg_to_instance_rels(self, instance: Asset, props: dict) -> List[Relationship]:
        """Create Security Group → Instance relationships."""
        relationships = []
        for sg_id in props.get("security_groups", []):
            if sg_id in self._sg_by_id:
                sg_asset = self._sg_by_id[sg_id]
                relationships.append(Relationship(
                    snapshot_id=self._snapshot_id,
                    source_asset_id=sg_asset.id,
                    target_asset_id=instance.id,
                    relationship_type="ALLOWS_TRAFFIC_TO",
                    properties={"open_to_world": self._is_sg_open_to_world(sg_asset)},
                ))
        return relationships

    def _subnet_to_instance_rel(self, instance: Asset, props: dict) -> Relationship | None:
        """Create Subnet → Instance containment relationship."""
        subnet_id = props.get("subnet_id")
        if subnet_id and subnet_id in self._subnet_by_id:
            return Relationship(
                snapshot_id=self._snapshot_id,
                source_asset_id=self._subnet_by_id[subnet_id].id,
                target_asset_id=instance.id,
                relationship_type="CONTAINS",
            )
        return None

    def _instance_to_role_rels(self, instance: Asset, props: dict) -> List[Relationship]:
        """Create Instance → IAM Role relationships via instance profile."""
        relationships = []
        profile_arn = props.get("iam_instance_profile")
        if not profile_arn:
            return relationships
        
        profile_name = profile_arn.split("/")[-1] if "/" in profile_arn else None
        if not profile_name:
            return relationships
        
        for role in self._by_type.get("iam:role", []):
            if profile_name in role.name:
                relationships.append(Relationship(
                    snapshot_id=self._snapshot_id,
                    source_asset_id=instance.id,
                    target_asset_id=role.id,
                    relationship_type="CAN_ASSUME",
                    properties={"via": "instance_profile"},
                ))
        return relationships

    def _build_lambda_relationships(self) -> List[Relationship]:
        """Build Lambda → IAM Role relationships."""
        relationships = []
        for func in self._by_type.get("lambda:function", []):
            role_arn = func.properties.get("role")
            if not role_arn:
                continue
            
            for role in self._by_type.get("iam:role", []):
                if role.arn == role_arn:
                    relationships.append(Relationship(
                        snapshot_id=self._snapshot_id,
                        source_asset_id=func.id,
                        target_asset_id=role.id,
                        relationship_type="CAN_ASSUME",
                        properties={"via": "execution_role"},
                    ))
        return relationships

    def _build_loadbalancer_relationships(self) -> List[Relationship]:
        """Build Load Balancer → Security Group relationships."""
        relationships = []
        for lb in self._by_type.get("elbv2:load-balancer", []):
            for sg_id in lb.properties.get("security_groups", []):
                if sg_id in self._sg_by_id:
                    relationships.append(Relationship(
                        snapshot_id=self._snapshot_id,
                        source_asset_id=lb.id,
                        target_asset_id=self._sg_by_id[sg_id].id,
                        relationship_type="USES",
                    ))
        return relationships

    def _build_iam_access_relationships(self, assets: List[Asset]) -> List[Relationship]:
        """Build IAM Role → Sensitive Target access relationships."""
        relationships = []
        
        # Collect roles used by compute resources
        compute_roles = self._collect_compute_roles()
        
        # Create MAY_ACCESS relationships to sensitive targets
        sensitive_targets = [a for a in assets if a.is_sensitive_target]
        for role_id in compute_roles:
            for target in sensitive_targets:
                if role_id != target.id:  # Avoid self-loops
                    relationships.append(Relationship(
                        snapshot_id=self._snapshot_id,
                        source_asset_id=role_id,
                        target_asset_id=target.id,
                        relationship_type="MAY_ACCESS",
                        properties={"via": "iam_policy_assumption"},
                    ))
        
        return relationships

    def _collect_compute_roles(self) -> Set[uuid.UUID]:
        """Collect IAM roles used by EC2 instances and Lambda functions."""
        roles: Set[uuid.UUID] = set()
        
        # EC2 instance roles
        for instance in self._by_type.get("ec2:instance", []):
            profile_arn = instance.properties.get("iam_instance_profile")
            if profile_arn:
                profile_name = profile_arn.split("/")[-1] if "/" in profile_arn else None
                if profile_name:
                    for role in self._by_type.get("iam:role", []):
                        if profile_name in role.name:
                            roles.add(role.id)
        
        # Lambda execution roles
        for func in self._by_type.get("lambda:function", []):
            role_arn = func.properties.get("role")
            if role_arn:
                for role in self._by_type.get("iam:role", []):
                    if role.arn == role_arn:
                        roles.add(role.id)
        
        return roles

    def _is_sg_open_to_world(self, sg_asset: Asset) -> bool:
        """Check if a security group has 0.0.0.0/0 or ::/0 ingress rules."""
        for rule in sg_asset.properties.get("ingress_rules", []):
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    return True
            for ip_range in rule.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    return True
        return False
