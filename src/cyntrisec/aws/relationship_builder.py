"""
Relationship Builder - Create relationships between assets from different normalizers.

This module runs after all normalizers have completed to wire up cross-service connections:
- Security Group → EC2 Instance (ALLOWS_TRAFFIC_TO)
- Subnet → EC2 Instance (CONTAINS)
- EC2 Instance → IAM Role (CAN_ASSUME via instance profile)
- Lambda → IAM Role (CAN_ASSUME via execution role)
- IAM Role → IAM Role (CAN_ASSUME via sts:AssumeRole permission + trust policy)
- Load Balancer → Security Group (USES)
- IAM Role → Sensitive Target (MAY_READ_SECRET, MAY_READ_PARAMETER, MAY_DECRYPT, etc.)
- IAM Role → IAM Role (CAN_PASS_TO via iam:PassRole permission)
"""

from __future__ import annotations

import fnmatch
import ipaddress
import uuid
from dataclasses import dataclass, field
from typing import Any

from cyntrisec.core.schema import (
    INTERNET_ASSET_ID,
    Asset,
    ConditionResult,
    EdgeEvidence,
    EdgeKind,
    Relationship,
)


@dataclass
class EvaluationContext:
    """Context for evaluating IAM policy conditions.

    Contains information about the source principal and network context
    that can be used to evaluate IAM conditions.
    """

    # VPC endpoint ID if the request comes through a VPC endpoint
    source_vpce: str | None = None

    # VPC ID of the source
    source_vpc_id: str | None = None

    # Principal tags (key -> value)
    principal_tags: dict[str, str] = field(default_factory=dict)

    # Source IP address or CIDR
    source_ip: str | None = None

    # AWS account ID
    account_id: str | None = None


class ConditionEvaluator:
    """
    Evaluates IAM policy conditions with tri-state results.

    This class evaluates IAM policy Condition clauses and returns a tri-state result:
    - TRUE: Condition is satisfied
    - FALSE: Condition is not satisfied
    - UNKNOWN: Cannot evaluate locally (unsupported condition or missing context)

    Supported conditions:
    - aws:SourceVpce: Checks if request comes from specified VPC endpoint
    - aws:PrincipalTag: Checks if principal has matching tag

    All other conditions return UNKNOWN.
    """

    # Set of condition keys we can evaluate
    SUPPORTED_CONDITIONS: set[str] = {
        "aws:SourceVpce",
        "aws:sourcevpce",  # Case variations
        "aws:PrincipalTag",
        "aws:principaltag",
    }

    def evaluate(
        self,
        conditions: dict[str, Any],
        context: EvaluationContext,
    ) -> ConditionResult:
        """
        Evaluate IAM policy conditions against the provided context.

        Args:
            conditions: The Condition block from an IAM policy statement
            context: The evaluation context with source information

        Returns:
            ConditionResult.TRUE if all conditions are satisfied
            ConditionResult.FALSE if any condition is not satisfied
            ConditionResult.UNKNOWN if any condition cannot be evaluated
        """
        if not conditions:
            return ConditionResult.TRUE

        has_unknown = False

        for operator, condition_block in conditions.items():
            if not isinstance(condition_block, dict):
                has_unknown = True
                continue

            for condition_key, condition_value in condition_block.items():
                result = self._evaluate_single_condition(
                    operator, condition_key, condition_value, context
                )

                if result == ConditionResult.FALSE:
                    return ConditionResult.FALSE
                elif result == ConditionResult.UNKNOWN:
                    has_unknown = True

        return ConditionResult.UNKNOWN if has_unknown else ConditionResult.TRUE

    def _evaluate_single_condition(
        self,
        operator: str,
        condition_key: str,
        condition_value: Any,
        context: EvaluationContext,
    ) -> ConditionResult:
        """Evaluate a single condition."""
        # Normalize condition key for comparison
        key_lower = condition_key.lower()

        # Handle aws:SourceVpce
        if key_lower == "aws:sourcevpce":
            return self.evaluate_source_vpce(operator, condition_value, context)

        # Handle aws:PrincipalTag/*
        if key_lower.startswith("aws:principaltag/"):
            tag_key = condition_key.split("/", 1)[1] if "/" in condition_key else ""
            return self.evaluate_principal_tag(operator, tag_key, condition_value, context)

        # Unsupported condition - return UNKNOWN
        return ConditionResult.UNKNOWN

    def evaluate_source_vpce(
        self,
        operator: str,
        condition_value: Any,
        context: EvaluationContext,
    ) -> ConditionResult:
        """
        Evaluate aws:SourceVpce condition.

        Checks if the source VPC endpoint matches the expected value(s).

        Args:
            operator: The condition operator (StringEquals, StringLike, etc.)
            condition_value: The expected VPC endpoint ID(s)
            context: The evaluation context

        Returns:
            ConditionResult indicating if the condition is satisfied
        """
        if context.source_vpce is None:
            return ConditionResult.UNKNOWN

        # Normalize condition value to list
        expected_values = self._normalize_condition_value(condition_value)

        # Handle different operators
        operator_lower = operator.lower()

        if operator_lower in ("stringequals", "stringequalsifexists"):
            # Exact match
            if context.source_vpce in expected_values:
                return ConditionResult.TRUE
            return ConditionResult.FALSE

        elif operator_lower in ("stringnotequals", "stringnotequalsifexists"):
            # Not equal
            if context.source_vpce not in expected_values:
                return ConditionResult.TRUE
            return ConditionResult.FALSE

        elif operator_lower in ("stringlike", "stringlikeifexists"):
            # Wildcard match
            for pattern in expected_values:
                if fnmatch.fnmatch(context.source_vpce, pattern):
                    return ConditionResult.TRUE
            return ConditionResult.FALSE

        elif operator_lower in ("stringnotlike", "stringnotlikeifexists"):
            # Not like (wildcard)
            for pattern in expected_values:
                if fnmatch.fnmatch(context.source_vpce, pattern):
                    return ConditionResult.FALSE
            return ConditionResult.TRUE

        # Unsupported operator
        return ConditionResult.UNKNOWN

    def evaluate_principal_tag(
        self,
        operator: str,
        tag_key: str,
        condition_value: Any,
        context: EvaluationContext,
    ) -> ConditionResult:
        """
        Evaluate aws:PrincipalTag condition.

        Checks if the principal has a tag with the specified key and value.

        Args:
            operator: The condition operator (StringEquals, StringLike, etc.)
            tag_key: The tag key to check
            condition_value: The expected tag value(s)
            context: The evaluation context

        Returns:
            ConditionResult indicating if the condition is satisfied
        """
        if not context.principal_tags:
            return ConditionResult.UNKNOWN

        # Get the actual tag value from context
        actual_value = context.principal_tags.get(tag_key)

        if actual_value is None:
            # Tag doesn't exist - for IfExists operators, this is TRUE
            operator_lower = operator.lower()
            if "ifexists" in operator_lower:
                return ConditionResult.TRUE
            return ConditionResult.FALSE

        # Normalize condition value to list
        expected_values = self._normalize_condition_value(condition_value)

        # Handle different operators
        operator_lower = operator.lower()

        if operator_lower in ("stringequals", "stringequalsifexists"):
            if actual_value in expected_values:
                return ConditionResult.TRUE
            return ConditionResult.FALSE

        elif operator_lower in ("stringnotequals", "stringnotequalsifexists"):
            if actual_value not in expected_values:
                return ConditionResult.TRUE
            return ConditionResult.FALSE

        elif operator_lower in ("stringlike", "stringlikeifexists"):
            for pattern in expected_values:
                if fnmatch.fnmatch(actual_value, pattern):
                    return ConditionResult.TRUE
            return ConditionResult.FALSE

        elif operator_lower in ("stringnotlike", "stringnotlikeifexists"):
            for pattern in expected_values:
                if fnmatch.fnmatch(actual_value, pattern):
                    return ConditionResult.FALSE
            return ConditionResult.TRUE

        # Unsupported operator
        return ConditionResult.UNKNOWN

    def _normalize_condition_value(self, value: Any) -> list[str]:
        """Normalize condition value to a list of strings."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        return [str(value)]

    def check_explicit_deny_presence(
        self,
        role: Asset,
        target_arn: str,
        action: str,
    ) -> tuple[bool, str]:
        """
        Check if explicit deny might apply to this access.

        Detects the presence of:
        - Identity policy Deny statements
        - Permission boundaries
        - SCP presence (if org data available)
        - Resource policy Deny statements

        When explicit deny is detected but cannot be fully evaluated,
        confidence should be lowered to MED or LOW.

        Args:
            role: The IAM role asset to check
            target_arn: The target resource ARN
            action: The IAM action being checked

        Returns:
            Tuple of (has_potential_deny, reason) where:
            - has_potential_deny: True if explicit deny might apply
            - reason: Specific explanation of what couldn't be fully evaluated
        """
        reasons: list[str] = []

        # Check identity policy denies
        policy_docs = role.properties.get("policy_documents", [])
        for policy in policy_docs:
            if self._has_deny_statement(policy, target_arn, action):
                reasons.append("identity policy Deny statement present")
                break

        # Check permission boundary presence
        permission_boundary = role.properties.get("permission_boundary")
        if permission_boundary:
            reasons.append("permission boundary attached")

        # Check SCP presence (if we have org data)
        scp_present = role.properties.get("scp_present")
        if scp_present:
            reasons.append("SCP may apply")

        # Check for inline policy denies
        inline_policies = role.properties.get("inline_policies", [])
        for policy in inline_policies:
            if self._has_deny_statement(policy, target_arn, action):
                reasons.append("inline policy Deny statement present")
                break

        # Check attached managed policy denies
        attached_policies = role.properties.get("attached_policy_documents", [])
        for policy in attached_policies:
            if self._has_deny_statement(policy, target_arn, action):
                reasons.append("attached managed policy Deny statement present")
                break

        if reasons:
            return True, "possible explicit deny not fully evaluated: " + ", ".join(reasons)
        return False, ""

    def _has_deny_statement(
        self,
        policy: dict[str, Any],
        target_arn: str,
        action: str,
    ) -> bool:
        """
        Check if a policy document contains a Deny statement that might apply.

        Args:
            policy: The policy document
            target_arn: The target resource ARN
            action: The IAM action being checked

        Returns:
            True if a potentially applicable Deny statement exists
        """
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if not isinstance(statement, dict):
                continue

            effect = statement.get("Effect", "Allow")
            if effect != "Deny":
                continue

            # Check if action matches
            stmt_actions = statement.get("Action", [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]

            action_matches = False
            for stmt_action in stmt_actions:
                if stmt_action == "*" or fnmatch.fnmatch(action.lower(), stmt_action.lower()):
                    action_matches = True
                    break

            if not action_matches:
                continue

            # Check if resource matches
            stmt_resources = statement.get("Resource", [])
            if isinstance(stmt_resources, str):
                stmt_resources = [stmt_resources]

            for stmt_resource in stmt_resources:
                if stmt_resource == "*" or fnmatch.fnmatch(target_arn, stmt_resource):
                    return True

        return False


class ActionParser:
    """
    Parses IAM actions using fnmatch against known capability set.

    This class matches IAM policy Action/NotAction patterns against a predefined
    set of capability-granting actions. It does NOT enumerate or expand wildcards
    to a full action list; instead it matches patterns directly using fnmatch.

    The matching logic:
    - For Action: a capability is matched if any Action pattern matches it
    - For NotAction: a capability is allowed unless it matches a NotAction pattern
    """

    # Capability-granting actions mapped to edge types
    # These are the specific IAM actions that grant meaningful capabilities
    CAPABILITY_ACTIONS: dict[str, str] = {
        "secretsmanager:GetSecretValue": "MAY_READ_SECRET",
        "ssm:GetParameter": "MAY_READ_PARAMETER",
        "ssm:GetParameters": "MAY_READ_PARAMETER",
        "ssm:GetParametersByPath": "MAY_READ_PARAMETER",
        "kms:Decrypt": "MAY_DECRYPT",
        "s3:GetObject": "MAY_READ_S3_OBJECT",
        "lambda:CreateFunction": "MAY_CREATE_LAMBDA",
        "lambda:UpdateFunctionConfiguration": "MAY_CREATE_LAMBDA",
        "iam:PassRole": "CAN_PASS_TO",
    }

    def get_matched_capabilities(self, statement: dict[str, Any]) -> set[str]:
        """
        Get capability actions matched by this IAM policy statement.

        Uses fnmatch to check if statement's Action patterns match
        any capability action. Does NOT enumerate all AWS actions.

        Args:
            statement: An IAM policy statement dict with Action/NotAction fields

        Returns:
            Set of matched capability action strings (e.g., "secretsmanager:GetSecretValue")
        """
        actions = self._normalize_actions(statement.get("Action", []))
        not_actions = self._normalize_actions(statement.get("NotAction", []))

        matched: set[str] = set()

        # Case 1: Statement has Action field
        if actions:
            for capability_action in self.CAPABILITY_ACTIONS:
                # Check if any Action pattern matches this capability
                if self._any_pattern_matches(actions, capability_action):
                    # Check it's not excluded by NotAction (if both are present)
                    if not not_actions or not self._any_pattern_matches(
                        not_actions, capability_action
                    ):
                        matched.add(capability_action)

        # Case 2: Statement has only NotAction field (no Action)
        # For NotAction: capability is allowed unless it matches NotAction pattern
        elif not_actions:
            for capability_action in self.CAPABILITY_ACTIONS:
                if not self._any_pattern_matches(not_actions, capability_action):
                    matched.add(capability_action)

        return matched

    def get_edge_type_for_action(self, action: str) -> str | None:
        """
        Get the edge type for a specific capability action.

        Args:
            action: The IAM action string (e.g., "secretsmanager:GetSecretValue")

        Returns:
            The edge type string (e.g., "MAY_READ_SECRET") or None if not a capability action
        """
        return self.CAPABILITY_ACTIONS.get(action)

    def _any_pattern_matches(self, patterns: list[str], action: str) -> bool:
        """
        Check if any pattern matches the action using fnmatch.

        This supports wildcards in patterns:
        - "s3:*" matches "s3:GetObject"
        - "s3:Get*" matches "s3:GetObject" and "s3:GetBucketPolicy"
        - "*" matches any action

        Args:
            patterns: List of IAM action patterns (may contain wildcards)
            action: The specific action to check

        Returns:
            True if any pattern matches the action
        """
        for pattern in patterns:
            # Handle case-insensitive matching for IAM actions
            # IAM actions are case-insensitive, but we normalize to lowercase for matching
            pattern_lower = pattern.lower()
            action_lower = action.lower()

            if fnmatch.fnmatch(action_lower, pattern_lower):
                return True
        return False

    def _normalize_actions(self, actions: Any) -> list[str]:
        """
        Normalize Action/NotAction field to list of strings.

        IAM policies can have Action/NotAction as either a string or list.

        Args:
            actions: The Action or NotAction field value

        Returns:
            List of action strings
        """
        if not actions:
            return []
        if isinstance(actions, str):
            return [actions]
        if isinstance(actions, list):
            return [a for a in actions if isinstance(a, str)]
        return []


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
        self._assets_by_sg: dict[str, list[Asset]] = {}

    def build(self, assets: list[Asset]) -> list[Relationship]:
        """
        Build all cross-service relationships.

        Args:
            assets: All assets from all normalizers

        Returns:
            List of new relationships to add
        """
        # Ensure pseudo-assets exist
        self._ensure_internet_asset(assets)
        self._ensure_lambda_service_asset(assets)

        # Build indexes
        self._index_assets(assets)

        # Build relationships by category
        relationships: list[Relationship] = []
        relationships.extend(self._build_ec2_relationships())
        relationships.extend(self._build_lambda_relationships())
        relationships.extend(self._build_loadbalancer_relationships())
        relationships.extend(self._build_iam_access_relationships(assets))
        relationships.extend(self._build_pass_role_relationships(assets))
        relationships.extend(self._build_lambda_creation_relationships(assets))
        relationships.extend(self._build_role_to_role_assume_relationships(assets))
        relationships.extend(self._build_network_reachability_relationships())
        relationships.extend(self._build_identity_relationships())

        return relationships

    def _index_assets(self, assets: list[Asset]) -> None:
        """Build lookup indexes for fast asset access."""
        self._by_type = {}
        self._sg_by_id = {}
        self._subnet_by_id = {}
        self._assets_by_sg = {}

        for asset in assets:
            self._by_type.setdefault(asset.asset_type, []).append(asset)

            if asset.asset_type == "ec2:security-group":
                self._sg_by_id[asset.aws_resource_id] = asset
            elif asset.asset_type == "ec2:subnet":
                self._subnet_by_id[asset.aws_resource_id] = asset

            # Index by security group
            sg_ids = asset.properties.get("security_groups", [])
            for sg_id in sg_ids:
                self._assets_by_sg.setdefault(sg_id, []).append(asset)

    def _ensure_internet_asset(self, assets: list[Asset]) -> None:
        """Ensure the Internet pseudo-asset exists."""
        for asset in assets:
            if asset.id == INTERNET_ASSET_ID:
                return

        internet = Asset(
            id=INTERNET_ASSET_ID,
            snapshot_id=self._snapshot_id,
            asset_type="pseudo:internet",
            aws_resource_id="internet",
            name="Internet",
            is_internet_facing=True,
            properties={"description": "The Internet (0.0.0.0/0)"},
        )
        assets.append(internet)

    def _ensure_lambda_service_asset(self, assets: list[Asset]) -> None:
        """Ensure the Lambda service pseudo-asset exists for MAY_CREATE_LAMBDA edges."""
        lambda_service_id = uuid.UUID("00000000-0000-0000-0000-00000000000a")
        for asset in assets:
            if asset.id == lambda_service_id:
                return

        lambda_service = Asset(
            id=lambda_service_id,
            snapshot_id=self._snapshot_id,
            asset_type="pseudo:lambda-service",
            aws_resource_id="lambda-service",
            name="Lambda Service",
            properties={"description": "AWS Lambda service (target for MAY_CREATE_LAMBDA edges)"},
        )
        assets.append(lambda_service)

    def _build_network_reachability_relationships(self) -> list[Relationship]:
        """Build CAN_REACH edges based on network accessibility."""
        relationships: list[Relationship] = []

        # Iterate over all security groups
        for sg in self._sg_by_id.values():
            targets = self._assets_by_sg.get(sg.aws_resource_id, [])
            if not targets:
                continue

            ingress_rules = sg.properties.get("ingress_rules", [])

            for rule in ingress_rules:
                # 6.1 Internet Reachability (0.0.0.0/0)
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")
                    if cidr == "0.0.0.0/0":
                        for target in targets:
                            relationships.append(
                                self._create_can_reach_edge(
                                    INTERNET_ASSET_ID, target.id, rule, source_label="world"
                                )
                            )
                    # 6.3 CIDR Containment
                    elif cidr:
                        try:
                            rule_net = ipaddress.ip_network(cidr)
                            # Check against all known subnets
                            for subnet in self._subnet_by_id.values():
                                subnet_cidr = subnet.properties.get("cidr_block")
                                if subnet_cidr:
                                    subnet_net = ipaddress.ip_network(subnet_cidr)
                                    if rule_net.supernet_of(subnet_net):  # type: ignore[arg-type]
                                        for target in targets:
                                            relationships.append(
                                                self._create_can_reach_edge(
                                                    subnet.id,
                                                    target.id,
                                                    rule,
                                                    source_label=subnet.name,
                                                    confidence=0.5,
                                                )
                                            )
                        except ValueError:
                            continue

                # IPv6 Internet Reachability
                for ipv6_range in rule.get("Ipv6Ranges", []):
                    if ipv6_range.get("CidrIpv6") == "::/0":
                        for target in targets:
                            relationships.append(
                                self._create_can_reach_edge(
                                    INTERNET_ASSET_ID, target.id, rule, source_label="world"
                                )
                            )

                # 6.2 Lateral SG-to-SG Reachability
                for group_pair in rule.get("UserIdGroupPairs", []):
                    source_group_id = group_pair.get("GroupId")
                    if source_group_id and source_group_id in self._sg_by_id:
                        source_sg = self._sg_by_id[source_group_id]
                        for target in targets:
                            relationships.append(
                                self._create_can_reach_edge(
                                    source_sg.id, target.id, rule, source_label=source_sg.name
                                )
                            )

        return relationships

    def _create_can_reach_edge(
        self,
        source_id: uuid.UUID,
        target_id: uuid.UUID,
        rule: dict,
        source_label: str,
        confidence: float = 1.0,
    ) -> Relationship:
        """Create a CAN_REACH relationship from ingress rule.

        Args:
            source_id: Source asset UUID (e.g., Internet, SG, or Subnet)
            target_id: Target asset UUID
            rule: Security group ingress rule dict
            source_label: Human-readable source label
            confidence: Confidence score (1.0=HIGH, 0.5=MED for CIDR inference)
        """
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        protocol = rule.get("IpProtocol")

        props = {
            "protocol": protocol,
            "port_range": f"{from_port}-{to_port}" if from_port is not None else "all",
            "source": source_label,
            "confidence": confidence,
        }

        return Relationship(
            snapshot_id=self._snapshot_id,
            source_asset_id=source_id,
            target_asset_id=target_id,
            relationship_type="CAN_REACH",
            edge_kind=EdgeKind.CAPABILITY,
            properties=props,
            edge_weight=1.0,
        )

    def _build_identity_relationships(self) -> list[Relationship]:
        """
        Build USE_IDENTITY edges from Compute resources to their Network Identity (SGs).
        This allows traversal from an Instance to the SG node, enabling access to CAN_REACH edges
        originating from that SG.
        """
        relationships: list[Relationship] = []

        for sg_id, sg_asset in self._sg_by_id.items():
            members = self._assets_by_sg.get(sg_id, [])
            for member in members:
                relationships.append(
                    Relationship(
                        snapshot_id=self._snapshot_id,
                        source_asset_id=member.id,
                        target_asset_id=sg_asset.id,
                        relationship_type="USE_IDENTITY",
                        edge_kind=EdgeKind.CAPABILITY,
                        properties={},
                    )
                )
        return relationships

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
                        edge_kind=EdgeKind.STRUCTURAL,
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
                edge_kind=EdgeKind.STRUCTURAL,
            )
        return None

    def _instance_to_role_rels(self, instance: Asset, props: dict) -> list[Relationship]:
        """Create Instance → IAM Role relationships via instance profile."""
        relationships: list[Relationship] = []
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
                                edge_kind=EdgeKind.CAPABILITY,
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
                            edge_kind=EdgeKind.CAPABILITY,
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
                            edge_kind=EdgeKind.STRUCTURAL,
                        )
                    )
        return relationships

    def _build_iam_access_relationships(self, assets: list[Asset]) -> list[Relationship]:
        """Build IAM Role → Sensitive Target access relationships with action-specific edges.

        Creates action-specific capability edges instead of generic MAY_ACCESS:
        - MAY_READ_SECRET for secretsmanager:GetSecretValue
        - MAY_READ_PARAMETER for ssm:GetParameter*
        - MAY_DECRYPT for kms:Decrypt
        - MAY_READ_S3_OBJECT for s3:GetObject

        Each capability edge includes evidence with policy_sid, target_arn, permission,
        and raw_statement for provenance tracking.
        """
        relationships = []
        action_parser = ActionParser()

        # Collect roles used by compute resources
        compute_roles = self._collect_compute_roles()

        # Create action-specific relationships to sensitive targets
        sensitive_targets = [a for a in assets if a.is_sensitive_target]
        role_lookup = {role.id: role for role in self._by_type.get("iam:role", [])}

        # Map target asset types to relevant capability actions
        target_type_to_actions = {
            "secretsmanager:secret": ["secretsmanager:GetSecretValue"],
            "ssm:parameter": ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"],
            "kms:key": ["kms:Decrypt"],
            "s3:bucket": ["s3:GetObject"],
        }

        for role_id in compute_roles:
            role = role_lookup.get(role_id)
            if not role:
                continue

            policy_docs = role.properties.get("policy_documents", [])
            _, denied_resources = self._collect_policy_resources(policy_docs)

            for target in sensitive_targets:
                target_arn = target.arn or target.aws_resource_id
                if not target_arn or role_id == target.id:
                    continue

                # Get relevant actions for this target type
                relevant_actions = target_type_to_actions.get(target.asset_type, [])
                if not relevant_actions:
                    continue

                # Check each policy document for matching capabilities
                for policy in policy_docs:
                    policy_arn = policy.get("PolicyArn") or policy.get("Arn")

                    for statement in self._iter_policy_statements(policy):
                        if statement.get("Effect") != "Allow":
                            continue

                        # Check if statement resources match target (considering denies)
                        resources = self._normalize_resources(statement.get("Resource"))
                        if not self._resources_match_target(
                            resources, denied_resources, target_arn
                        ):
                            continue

                        # Get matched capabilities from this statement
                        matched_capabilities = action_parser.get_matched_capabilities(statement)

                        # Create edges for relevant matched capabilities
                        for capability_action in matched_capabilities:
                            if capability_action in relevant_actions:
                                edge_type = action_parser.get_edge_type_for_action(
                                    capability_action
                                )
                                if edge_type:
                                    # Create evidence for provenance tracking
                                    evidence = EdgeEvidence(
                                        policy_sid=statement.get("Sid"),
                                        policy_arn=policy_arn,
                                        source_arn=role.arn,
                                        target_arn=target_arn,
                                        permission=capability_action,
                                        raw_statement=statement,
                                    )

                                    relationships.append(
                                        Relationship(
                                            snapshot_id=self._snapshot_id,
                                            source_asset_id=role_id,
                                            target_asset_id=target.id,
                                            relationship_type=edge_type,
                                            edge_kind=EdgeKind.CAPABILITY,
                                            evidence=evidence,
                                            properties={
                                                "via": "iam_policy",
                                                "action": capability_action,
                                            },
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
        """Build IAM Role -> Role relationships via PassRole (Privilege Escalation).

        Each CAN_PASS_TO edge includes evidence with policy_sid, target_arn, permission,
        and raw_statement for provenance tracking.
        """
        relationships = []
        roles = [a for a in assets if a.asset_type == "iam:role"]

        for source_role in roles:
            policy_docs = source_role.properties.get("policy_documents", [])

            # Collect statements that grant PassRole
            passrole_statements: list[
                tuple[dict, str | None, dict]
            ] = []  # (statement, policy_arn, policy)
            for policy in policy_docs:
                policy_arn = policy.get("PolicyArn") or policy.get("Arn")
                for statement in self._iter_policy_statements(policy):
                    if statement.get("Effect") != "Allow":
                        continue

                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    if any(fnmatch.fnmatchcase("iam:PassRole", a) for a in actions):
                        passrole_statements.append((statement, policy_arn, policy))

            if not passrole_statements:
                continue

            for target_role in roles:
                if source_role.id == target_role.id:
                    continue

                target_arn = target_role.arn or target_role.aws_resource_id
                if not target_arn:
                    continue

                # Check if source can pass target and find the granting statement
                for statement, policy_arn, policy in passrole_statements:
                    resources = self._normalize_resources(statement.get("Resource"))
                    can_pass = False
                    for res in resources:
                        if res == "*" or fnmatch.fnmatchcase(target_arn, res):
                            can_pass = True
                            break

                    if can_pass:
                        # Create evidence for provenance tracking
                        evidence = EdgeEvidence(
                            policy_sid=statement.get("Sid"),
                            policy_arn=policy_arn,
                            source_arn=source_role.arn,
                            target_arn=target_arn,
                            permission="iam:PassRole",
                            raw_statement=statement,
                        )

                        relationships.append(
                            Relationship(
                                snapshot_id=self._snapshot_id,
                                source_asset_id=source_role.id,
                                target_asset_id=target_role.id,
                                relationship_type="CAN_PASS_TO",
                                edge_kind=EdgeKind.CAPABILITY,
                                evidence=evidence,
                                properties={"via": "iam_pass_role"},
                            )
                        )
                        break  # Only create one edge per source-target pair
        return relationships

    def _build_lambda_creation_relationships(self, assets: list[Asset]) -> list[Relationship]:
        """Build IAM Role -> Lambda Service relationships for lambda creation capabilities.

        Creates MAY_CREATE_LAMBDA edges when a role has:
        - lambda:CreateFunction permission
        - lambda:UpdateFunctionConfiguration permission

        These edges are used to validate the PassRole motif for privilege escalation.
        The target is a synthetic "lambda-service" asset representing the Lambda service.

        Each MAY_CREATE_LAMBDA edge includes evidence with policy_sid, permission,
        and raw_statement for provenance tracking.
        """
        relationships = []
        action_parser = ActionParser()

        # Lambda creation actions that grant MAY_CREATE_LAMBDA capability
        lambda_creation_actions = ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"]

        roles = [a for a in assets if a.asset_type == "iam:role"]

        # Find or create a synthetic Lambda service asset for targeting
        # We'll use a well-known UUID for the Lambda service
        lambda_service_id = uuid.UUID("00000000-0000-0000-0000-00000000000a")

        for role in roles:
            policy_docs = role.properties.get("policy_documents", [])

            for policy in policy_docs:
                policy_arn = policy.get("PolicyArn") or policy.get("Arn")

                for statement in self._iter_policy_statements(policy):
                    if statement.get("Effect") != "Allow":
                        continue

                    # Get matched capabilities from this statement
                    matched_capabilities = action_parser.get_matched_capabilities(statement)

                    # Check if any lambda creation action is matched
                    for capability_action in matched_capabilities:
                        if capability_action in lambda_creation_actions:
                            # Create evidence for provenance tracking
                            evidence = EdgeEvidence(
                                policy_sid=statement.get("Sid"),
                                policy_arn=policy_arn,
                                source_arn=role.arn,
                                target_arn="arn:aws:lambda:::service",
                                permission=capability_action,
                                raw_statement=statement,
                            )

                            relationships.append(
                                Relationship(
                                    snapshot_id=self._snapshot_id,
                                    source_asset_id=role.id,
                                    target_asset_id=lambda_service_id,
                                    relationship_type="MAY_CREATE_LAMBDA",
                                    edge_kind=EdgeKind.CAPABILITY,
                                    evidence=evidence,
                                    properties={
                                        "via": "iam_policy",
                                        "action": capability_action,
                                    },
                                )
                            )
                            # Only create one edge per role (even if multiple actions match)
                            break
                    else:
                        continue
                    break  # Break out of statement loop if we created an edge
                else:
                    continue
                break  # Break out of policy loop if we created an edge

        return relationships

    def _build_role_to_role_assume_relationships(self, assets: list[Asset]) -> list[Relationship]:
        """Build IAM Role -> Role CAN_ASSUME relationships via sts:AssumeRole.

        Creates CAN_ASSUME edges when:
        1. Source role has sts:AssumeRole permission on target role's ARN (identity policy)
        2. Target role's trust policy allows the source role to assume it

        Each CAN_ASSUME edge includes evidence with policy_sid, target_arn, permission,
        and raw_statement for provenance tracking.
        """
        relationships = []
        roles = [a for a in assets if a.asset_type == "iam:role"]

        # Build lookup for roles by ARN for efficient trust policy checking
        roles_by_arn: dict[str, Asset] = {}
        for role in roles:
            if role.arn:
                roles_by_arn[role.arn] = role

        for source_role in roles:
            policy_docs = source_role.properties.get("policy_documents", [])

            # Collect statements that grant sts:AssumeRole
            assume_statements: list[tuple[dict, str | None, dict]] = []
            for policy in policy_docs:
                policy_arn = policy.get("PolicyArn") or policy.get("Arn")
                for statement in self._iter_policy_statements(policy):
                    if statement.get("Effect") != "Allow":
                        continue

                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    # Check for sts:AssumeRole permission (case-insensitive, wildcard support)
                    has_assume = any(
                        fnmatch.fnmatch("sts:assumerole", a.lower())
                        or fnmatch.fnmatch("sts:*", a.lower())
                        or a == "*"
                        for a in actions
                    )
                    if has_assume:
                        assume_statements.append((statement, policy_arn, policy))

            if not assume_statements:
                continue

            for target_role in roles:
                if source_role.id == target_role.id:
                    continue

                target_arn = target_role.arn or target_role.aws_resource_id
                if not target_arn:
                    continue

                # Check if source can assume target via identity policy
                for statement, policy_arn, policy in assume_statements:
                    resources = self._normalize_resources(statement.get("Resource"))
                    can_assume_identity = False
                    for res in resources:
                        if res == "*" or fnmatch.fnmatch(target_arn, res):
                            can_assume_identity = True
                            break

                    if not can_assume_identity:
                        continue

                    # Check target's trust policy allows source
                    if not self._trust_policy_allows(target_role, source_role):
                        continue

                    # Both identity and trust policies allow - create edge
                    evidence = EdgeEvidence(
                        policy_sid=statement.get("Sid"),
                        policy_arn=policy_arn,
                        source_arn=source_role.arn,
                        target_arn=target_arn,
                        permission="sts:AssumeRole",
                        raw_statement=statement,
                    )

                    relationships.append(
                        Relationship(
                            snapshot_id=self._snapshot_id,
                            source_asset_id=source_role.id,
                            target_asset_id=target_role.id,
                            relationship_type="CAN_ASSUME",
                            edge_kind=EdgeKind.CAPABILITY,
                            evidence=evidence,
                            properties={"via": "sts_assume_role"},
                        )
                    )
                    break  # Only create one edge per source-target pair

        return relationships

    def _trust_policy_allows(self, target_role: Asset, source_role: Asset) -> bool:
        """Check if target role's trust policy allows source role to assume it.

        Args:
            target_role: The role being assumed
            source_role: The role attempting to assume

        Returns:
            True if the trust policy explicitly allows the source role
        """
        trust_policy = target_role.properties.get("trust_policy")
        if not trust_policy:
            return False

        source_arn = source_role.arn
        if not source_arn:
            return False

        # Extract account ID from source ARN for account-level trust checks
        # ARN format: arn:aws:iam::ACCOUNT_ID:role/RoleName
        source_account = None
        if source_arn.startswith("arn:aws:iam::"):
            parts = source_arn.split(":")
            if len(parts) >= 5:
                source_account = parts[4]

        for statement in trust_policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            # Check Action allows sts:AssumeRole
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            allows_assume = any(a == "sts:AssumeRole" or a == "sts:*" or a == "*" for a in actions)
            if not allows_assume:
                continue

            principal = statement.get("Principal", {})

            # Handle wildcard principal (trusts anyone)
            if principal == "*":
                return True

            # Handle AWS principal
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            for aws_principal in aws_principals:
                # Wildcard - trusts any AWS principal
                if aws_principal == "*":
                    return True

                # Exact role ARN match
                if aws_principal == source_arn:
                    return True

                # Account root match (arn:aws:iam::ACCOUNT_ID:root)
                if source_account and aws_principal == f"arn:aws:iam::{source_account}:root":
                    return True

                # Account ID match (just the account number)
                if source_account and aws_principal == source_account:
                    return True

                # Wildcard pattern match on role ARN
                if fnmatch.fnmatch(source_arn, aws_principal):
                    return True

        return False
