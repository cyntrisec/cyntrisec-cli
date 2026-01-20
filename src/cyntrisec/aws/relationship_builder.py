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

import fnmatch
import uuid

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
        self._by_type: dict[str, list[Asset]] = {}
        self._sg_by_id: dict[str, Asset] = {}
        self._subnet_by_id: dict[str, Asset] = {}

    def build(self, assets: list[Asset]) -> list[Relationship]:
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
        relationships: list[Relationship] = []
        relationships.extend(self._build_ec2_relationships())
        relationships.extend(self._build_lambda_relationships())
        relationships.extend(self._build_loadbalancer_relationships())
        relationships.extend(self._build_iam_access_relationships(assets))
        relationships.extend(self._build_pass_role_relationships(assets))

        return relationships

    def _index_assets(self, assets: list[Asset]) -> None:
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

    def _build_ec2_relationships(self) -> list[Relationship]:
        """Build relationships for EC2 instances."""
        relationships: list[Relationship] = []

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

    def _sg_to_instance_rels(self, instance: Asset, props: dict) -> list[Relationship]:
        """Create Security Group → Instance relationships."""
        relationships = []
        for sg_id in props.get("security_groups", []):
            if sg_id in self._sg_by_id:
                sg_asset = self._sg_by_id[sg_id]
                relationships.append(
                    Relationship(
                        snapshot_id=self._snapshot_id,
                        source_asset_id=sg_asset.id,
                        target_asset_id=instance.id,
                        relationship_type="ALLOWS_TRAFFIC_TO",
                        properties={"open_to_world": self._is_sg_open_to_world(sg_asset)},
                    )
                )
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

    def _instance_to_role_rels(self, instance: Asset, props: dict) -> list[Relationship]:
        """Create Instance → IAM Role relationships via instance profile."""
        relationships = []
        profile_arn = props.get("iam_instance_profile")
        if not profile_arn:
            return relationships

        for profile in self._by_type.get("iam:instance-profile", []):
            if profile.arn == profile_arn or profile.aws_resource_id == profile_arn:
                role_arns = profile.properties.get("role_arns") or []
                primary_role = profile.properties.get("role_arn")
                if primary_role and primary_role not in role_arns:
                    role_arns.append(primary_role)

                for role in self._by_type.get("iam:role", []):
                    if role.arn in role_arns:
                        relationships.append(
                            Relationship(
                                snapshot_id=self._snapshot_id,
                                source_asset_id=instance.id,
                                target_asset_id=role.id,
                                relationship_type="CAN_ASSUME",
                                properties={"via": "instance_profile"},
                            )
                        )
        return relationships

    def _build_lambda_relationships(self) -> list[Relationship]:
        """Build Lambda → IAM Role relationships."""
        relationships = []
        for func in self._by_type.get("lambda:function", []):
            role_arn = func.properties.get("role")
            if not role_arn:
                continue

            for role in self._by_type.get("iam:role", []):
                if role.arn == role_arn:
                    relationships.append(
                        Relationship(
                            snapshot_id=self._snapshot_id,
                            source_asset_id=func.id,
                            target_asset_id=role.id,
                            relationship_type="CAN_ASSUME",
                            properties={"via": "execution_role"},
                        )
                    )
        return relationships

    def _build_loadbalancer_relationships(self) -> list[Relationship]:
        """Build Load Balancer → Security Group relationships."""
        relationships = []
        for lb in self._by_type.get("elbv2:load-balancer", []):
            for sg_id in lb.properties.get("security_groups", []):
                if sg_id in self._sg_by_id:
                    relationships.append(
                        Relationship(
                            snapshot_id=self._snapshot_id,
                            source_asset_id=lb.id,
                            target_asset_id=self._sg_by_id[sg_id].id,
                            relationship_type="USES",
                        )
                    )
        return relationships

    def _build_iam_access_relationships(self, assets: list[Asset]) -> list[Relationship]:
        """Build IAM Role → Sensitive Target access relationships."""
        relationships = []

        # Collect roles used by compute resources
        compute_roles = self._collect_compute_roles()

        # Create MAY_ACCESS relationships to sensitive targets
        sensitive_targets = [a for a in assets if a.is_sensitive_target]
        role_lookup = {role.id: role for role in self._by_type.get("iam:role", [])}

        for role_id in compute_roles:
            role = role_lookup.get(role_id)
            if not role:
                continue
            policy_docs = role.properties.get("policy_documents", [])
            policy_docs = role.properties.get("policy_documents", [])
            allowed, denied = self._collect_policy_resources(policy_docs)
            if not allowed:
                continue

            for target in sensitive_targets:
                target_arn = target.arn or target.aws_resource_id
                if not target_arn or role_id == target.id:
                    continue
                if self._resources_match_target(allowed, denied, target_arn):
                    relationships.append(
                        Relationship(
                            snapshot_id=self._snapshot_id,
                            source_asset_id=role_id,
                            target_asset_id=target.id,
                            relationship_type="MAY_ACCESS",
                            properties={"via": "iam_policy"},
                        )
                    )

        return relationships

    def _collect_policy_resources(self, policy_docs: list[dict]) -> tuple[list[str], list[str]]:
        """Extract allowed and denied resources from policy documents."""
        allowed: list[str] = []
        denied: list[str] = []
        for policy in policy_docs:
            for statement in self._iter_policy_statements(policy):
                effect = statement.get("Effect", "Allow")
                resources = self._normalize_resources(statement.get("Resource"))
                
                if effect == "Allow":
                    allowed.extend(resources)
                elif effect == "Deny":
                    denied.extend(resources)
                    
        return allowed, denied

    @staticmethod
    def _iter_policy_statements(policy: dict) -> list[dict]:
        """Return policy statements as a list."""
        statements = policy.get("Statement", [])
        if isinstance(statements, list):
            return statements
        if isinstance(statements, dict):
            return [statements]
        return []

    @staticmethod
    def _normalize_resources(resource_value) -> list[str]:
        """Normalize Resource field into a list of strings."""
        if not resource_value:
            return []
        if isinstance(resource_value, list):
            return [r for r in resource_value if isinstance(r, str)]
        if isinstance(resource_value, str):
            return [resource_value]
        return []

    @staticmethod
    def _resources_match_target(allowed: list[str], denied: list[str], target_arn: str) -> bool:
        """Return True when matches allowed and NOT denied."""
        # Check explicit deny first
        for resource in denied:
            if resource == "*" or fnmatch.fnmatchcase(target_arn, resource):
                return False

        # Check allow
        for resource in allowed:
            if resource == "*" or fnmatch.fnmatchcase(target_arn, resource):
                return True
        return False

    def _collect_compute_roles(self) -> set[uuid.UUID]:
        """Collect IAM roles used by EC2 instances and Lambda functions."""
        roles: set[uuid.UUID] = set()

        # EC2 instance roles
        for instance in self._by_type.get("ec2:instance", []):
            profile_arn = instance.properties.get("iam_instance_profile")
            if profile_arn:
                for profile in self._by_type.get("iam:instance-profile", []):
                    if profile.arn == profile_arn or profile.aws_resource_id == profile_arn:
                        role_arns = profile.properties.get("role_arns") or []
                        primary_role = profile.properties.get("role_arn")
                        if primary_role and primary_role not in role_arns:
                            role_arns.append(primary_role)
                        for role in self._by_type.get("iam:role", []):
                            if role.arn in role_arns:
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

    def _build_pass_role_relationships(self, assets: list[Asset]) -> list[Relationship]:
        """Build IAM Role -> Role relationships via PassRole (Privilege Escalation)."""
        relationships = []
        roles = [a for a in assets if a.asset_type == "iam:role"]
        
        for source_role in roles:
            policy_docs = source_role.properties.get("policy_documents", [])
            
            allowed_resources = []
            for policy in policy_docs:
                for statement in self._iter_policy_statements(policy):
                    if statement.get("Effect") != "Allow":
                        continue
                        
                    actions = statement.get("Action", [])
                    if isinstance(actions, str): actions = [actions]
                    
                    if any(fnmatch.fnmatchcase("iam:PassRole", a) for a in actions):
                         allowed_resources.extend(self._normalize_resources(statement.get("Resource")))

            if not allowed_resources:
                continue
                
            for target_role in roles:
                if source_role.id == target_role.id:
                    continue
                    
                target_arn = target_role.arn or target_role.aws_resource_id
                if not target_arn: continue
                
                # Check if source can pass target
                can_pass = False
                for res in allowed_resources:
                    if res == "*" or fnmatch.fnmatchcase(target_arn, res):
                        can_pass = True
                        break
                
                if can_pass:
                    relationships.append(
                        Relationship(
                            snapshot_id=self._snapshot_id,
                            source_asset_id=source_role.id,
                            target_asset_id=target_role.id,
                            relationship_type="CAN_PASS_TO",
                            properties={"via": "iam_pass_role"},
                        )
                    )
        return relationships
