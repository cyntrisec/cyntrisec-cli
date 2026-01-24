"""
IAM Policy Simulator - Test whether a principal can perform an action.

Uses AWS IAM Policy Simulator API to evaluate permissions and determine
whether a given action would be allowed or denied.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

log = logging.getLogger(__name__)


class SimulationDecision(str, Enum):
    """Result of a policy simulation."""

    allowed = "allowed"
    implicit_deny = "implicitDeny"
    explicit_deny = "explicitDeny"


@dataclass
class SimulationResult:
    """
    Result of simulating an IAM action.

    Attributes:
        action: The action tested (e.g., 's3:GetObject')
        resource: The resource tested (e.g., 'arn:aws:s3:::bucket/*')
        decision: Whether allowed, implicitly denied, or explicitly denied
        decision_details: Additional info about which policy affected decision
        matched_statements: Policy statements that matched
    """

    action: str | None
    resource: str
    decision: SimulationDecision
    decision_details: dict[str, Any] = field(default_factory=dict)
    matched_statements: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_allowed(self) -> bool:
        return self.decision == SimulationDecision.allowed

    @property
    def is_denied(self) -> bool:
        return self.decision in (SimulationDecision.implicit_deny, SimulationDecision.explicit_deny)


@dataclass
class CanAccessResult:
    """
    Result of a "can X access Y?" query.

    Attributes:
        principal_arn: The IAM principal tested
        target_resource: The resource being accessed
        action: The specific action tested
        can_access: Whether access is allowed
        simulations: All simulation results
        proof: Evidence chain for the result
    """

    principal_arn: str
    target_resource: str
    action: str | None
    can_access: bool
    simulations: list[SimulationResult] = field(default_factory=list)
    proof: dict[str, Any] = field(default_factory=dict)


class PolicySimulator:
    """
    Simulate IAM policy evaluation using AWS Policy Simulator API.

    This provides ground truth for "can X access Y?" questions by
    using the same policy evaluation logic as AWS.
    """

    def __init__(self, session):
        """
        Initialize with a boto3 Session.

        Args:
            session: boto3.Session with IAM permissions
        """
        self._session = session
        self._iam = session.client("iam")

    def simulate_principal_policy(
        self,
        principal_arn: str,
        actions: list[str],
        resources: list[str],
        *,
        context_entries: list[dict[str, Any]] | None = None,
    ) -> list[SimulationResult]:
        """
        Simulate whether a principal can perform actions on resources.

        Args:
            principal_arn: ARN of user/role to test
            actions: List of actions to test (e.g., ['s3:GetObject'])
            resources: List of resource ARNs to test against
            context_entries: Optional context values for conditions

        Returns:
            List of SimulationResult for each action/resource combination
        """
        results = []

        try:
            params: dict[str, Any] = {
                "PolicySourceArn": principal_arn,
                "ActionNames": actions,
                "ResourceArns": resources,
            }

            if context_entries:
                params["ContextEntries"] = context_entries

            paginator = self._iam.get_paginator("simulate_principal_policy")

            for page in paginator.paginate(**params):
                for eval_result in page.get("EvaluationResults", []):
                    decision_str = eval_result.get("EvalDecision", "implicitDeny")

                    # Map AWS decision to our enum
                    if decision_str == "allowed":
                        decision = SimulationDecision.allowed
                    elif decision_str == "explicitDeny":
                        decision = SimulationDecision.explicit_deny
                    else:
                        decision = SimulationDecision.implicit_deny

                    result = SimulationResult(
                        action=eval_result.get("EvalActionName", ""),
                        resource=eval_result.get("EvalResourceName", "*"),
                        decision=decision,
                        decision_details=eval_result.get("EvalDecisionDetails", {}),
                        matched_statements=eval_result.get("MatchedStatements", []),
                    )
                    results.append(result)

        except Exception as e:
            log.warning("Policy simulation failed for %s: %s", principal_arn, e)
            # Return implicit deny for all requested simulations
            for action in actions:
                for resource in resources:
                    results.append(
                        SimulationResult(
                            action=action,
                            resource=resource,
                            decision=SimulationDecision.implicit_deny,
                            decision_details={"error": str(e)},
                        )
                    )

        return results

    def can_access(
        self,
        principal_arn: str,
        target_resource: str,
        *,
        action: str | None = None,
    ) -> CanAccessResult:
        """
        Check if a principal can access a resource.

        This is the high-level "can X access Y?" query that users run.

        Args:
            principal_arn: ARN of role/user
            target_resource: Resource ARN or bucket name/etc.
            action: Specific action to test (auto-detected if not provided)

        Returns:
            CanAccessResult with full proof chain
        """
        # Normalize resource to ARN if needed
        resource_arn = self._normalize_resource(target_resource)

        # Determine actions to test based on resource type
        if action:
            actions_to_test = [action]
        else:
            actions_to_test = self._infer_actions(resource_arn)

        # Run simulation
        resources_to_test = self._resources_for_actions(resource_arn, actions_to_test)
        simulations = self.simulate_principal_policy(
            principal_arn=principal_arn,
            actions=actions_to_test,
            resources=resources_to_test,
        )

        # Determine overall result - allowed if ANY action is allowed
        can_access = any(s.is_allowed for s in simulations)

        # Build proof
        proof = {
            "principal": principal_arn,
            "resource": resource_arn,
            "resources_tested": resources_to_test,
            "actions_tested": actions_to_test,
            "simulations": [
                {
                    "action": s.action,
                    "decision": s.decision.value,
                    "matched_statements": len(s.matched_statements),
                }
                for s in simulations
            ],
        }

        return CanAccessResult(
            principal_arn=principal_arn,
            target_resource=target_resource,
            action=action or actions_to_test[0],
            can_access=can_access,
            simulations=simulations,
            proof=proof,
        )

    def _normalize_resource(self, resource: str) -> str:
        """Convert resource identifier to ARN."""
        if resource.startswith("arn:"):
            return resource

        # S3 bucket
        if resource.startswith("s3://"):
            bucket = resource[5:].split("/")[0]
            path = "/".join(resource[5:].split("/")[1:]) if "/" in resource[5:] else "*"
            return f"arn:aws:s3:::{bucket}/{path}"

        # Assume it's an S3 bucket name
        if "." in resource or resource.islower():
            return f"arn:aws:s3:::{resource}/*"

        return resource

    def _infer_actions(self, resource_arn: str) -> list[str]:
        """Infer actions to test based on resource type."""
        if ":s3:::" in resource_arn:
            return ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]

        if ":iam::" in resource_arn and ":role/" in resource_arn:
            return ["sts:AssumeRole"]

        if ":secretsmanager:" in resource_arn:
            return ["secretsmanager:GetSecretValue"]

        if ":ssm:" in resource_arn:
            return ["ssm:GetParameter"]

        if ":rds:" in resource_arn:
            return ["rds:DescribeDBInstances"]

        if ":dynamodb:" in resource_arn:
            return ["dynamodb:GetItem", "dynamodb:Scan"]

        if ":lambda:" in resource_arn:
            return ["lambda:InvokeFunction"]

        if ":ec2:" in resource_arn:
            return ["ec2:DescribeInstances"]

        # Default: test read access
        return ["*:Get*", "*:Describe*", "*:List*"]

    def _resources_for_actions(self, resource_arn: str, actions: list[str]) -> list[str]:
        """Build resource ARNs appropriate for the given actions."""
        if ":s3:::" not in resource_arn:
            return [resource_arn]

        bucket_arn, object_arn = self._s3_variants(resource_arn)
        resources: list[str] = []
        if any(a.lower() == "s3:listbucket" for a in actions):
            resources.append(bucket_arn)
        if any(a.lower().startswith("s3:") and a.lower() != "s3:listbucket" for a in actions):
            resources.append(object_arn)
        if not resources:
            resources = [object_arn]
        return resources

    def _s3_variants(self, resource_arn: str) -> tuple[str, str]:
        """Return bucket ARN and object ARN variants for S3 resources."""
        prefix = "arn:aws:s3:::"
        if not resource_arn.startswith(prefix):
            return resource_arn, resource_arn

        suffix = resource_arn[len(prefix) :]
        if "/" in suffix:
            bucket = suffix.split("/", 1)[0]
            bucket_arn = f"{prefix}{bucket}"
            object_arn = resource_arn
        else:
            bucket_arn = resource_arn
            object_arn = f"{resource_arn}/*"
        return bucket_arn, object_arn


class OfflineSimulator:
    """
    Offline policy evaluation without AWS API calls.

    Uses scan data to make educated guesses about access.
    Less accurate than PolicySimulator but works offline.
    """

    def __init__(self, assets: list[Any], relationships: list[Any]):
        """
        Initialize with scan data.

        Args:
            assets: Assets from scan
            relationships: Relationships from scan
        """
        self._assets = {a.arn: a for a in assets if a.arn}
        self._assets_by_name = {a.name: a for a in assets}
        self._relationships = relationships

    def can_access(
        self,
        principal_arn: str,
        target_resource: str,
        *,
        action: str | None = None,
    ) -> CanAccessResult:
        """
        Check if principal can access resource using scan data.

        This uses the MAY_ACCESS relationships from the graph.
        """
        # Find assets
        principal = self._assets.get(principal_arn) or self._assets_by_name.get(
            principal_arn.split("/")[-1]
        )
        target = self._assets.get(target_resource) or self._assets_by_name.get(target_resource)

        can_access = False
        proof = {}

        if principal and target:
            # Check for direct relationship
            for rel in self._relationships:
                if (
                    rel.source_asset_id == principal.id
                    and rel.target_asset_id == target.id
                    and rel.relationship_type in ("MAY_ACCESS", "CAN_ASSUME", "ALLOWS")
                ):
                    can_access = True
                    proof = {
                        "relationship_type": rel.relationship_type,
                        "properties": rel.properties,
                    }
                    break

        return CanAccessResult(
            principal_arn=principal_arn,
            target_resource=target_resource,
            action=action,
            can_access=can_access,
            simulations=[],
            proof=proof,
        )
