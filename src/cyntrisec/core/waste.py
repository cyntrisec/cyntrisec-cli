"""
Waste Analyzer - Identify unused IAM capabilities for blast radius reduction.

Analyzes the gap between "permissions granted" and "permissions used"
to find waste that increases attack surface without providing value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from cyntrisec.core.schema import Asset


@dataclass
class UnusedCapability:
    """
    An unused permission that contributes to blast radius.

    Attributes:
        role_arn: The IAM role with this capability
        role_name: Human-readable role name
        service: AWS service namespace (e.g., 's3', 'iam')
        service_name: Full service name (e.g., 'Amazon S3')
        days_unused: Number of days since last use (None = never used)
        risk_level: 'critical', 'high', 'medium', 'low'
        recommendation: What to do about it
    """

    role_arn: str
    role_name: str
    service: str
    service_name: str
    days_unused: int | None = None  # None means never used
    risk_level: str = "medium"
    recommendation: str = ""

    @property
    def never_used(self) -> bool:
        return self.days_unused is None


@dataclass
class WasteReport:
    """
    Summary of unused capabilities in an AWS account.

    Attributes:
        role_reports: Waste analysis per role
        total_unused: Total count of unused service permissions
        blast_radius_reduction: Estimated % reduction if cleaned up
    """

    role_reports: list[RoleWasteReport] = field(default_factory=list)
    total_unused: int = 0
    total_permissions: int = 0
    analyzed_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def blast_radius_reduction(self) -> float:
        """Percentage of permissions that are unused."""
        if self.total_permissions == 0:
            return 0.0
        return self.total_unused / self.total_permissions


@dataclass
class RoleWasteReport:
    """Waste analysis for a single IAM role."""

    role_arn: str
    role_name: str
    unused_capabilities: list[UnusedCapability] = field(default_factory=list)
    total_services: int = 0
    unused_services: int = 0

    @property
    def blast_radius_reduction(self) -> float:
        """Percentage reduction if unused capabilities removed."""
        if self.total_services == 0:
            return 0.0
        return self.unused_services / self.total_services


# High-risk services that should be flagged if unused
HIGH_RISK_SERVICES = {
    "iam": "critical",  # Identity management
    "sts": "high",  # Token service
    "kms": "high",  # Encryption keys
    "secretsmanager": "high",  # Secrets
    "ssm": "high",  # Systems Manager
    "ec2": "medium",  # Compute
    "s3": "medium",  # Storage
    "lambda": "medium",  # Functions
    "rds": "medium",  # Databases
    "dynamodb": "medium",  # NoSQL
}


class WasteAnalyzer:
    """
    Analyze IAM permissions for unused capabilities.

    Compares granted permissions against actual usage to find
    opportunities for blast radius reduction.
    """

    def __init__(self, days_threshold: int = 90):
        """
        Initialize analyzer.

        Args:
            days_threshold: Consider unused if not accessed in this many days
        """
        self.days_threshold = days_threshold
        self._cutoff = datetime.utcnow() - timedelta(days=days_threshold)

    def _is_aws_managed_role(self, role: Asset) -> bool:
        """Check if role is AWS-managed and should be excluded from waste analysis."""
        name = role.name or ""
        arn = role.arn or role.aws_resource_id or ""

        # AWS service-linked roles
        if name.startswith("AWSServiceRole"):
            return True
        if name.startswith("AWSReservedSSO_"):
            return True
        if "/aws-service-role/" in arn:
            return True

        return False

    def analyze_from_usage_reports(
        self,
        usage_reports: list[any],  # List[RoleUsageReport]
    ) -> WasteReport:
        """
        Analyze usage reports to find waste.

        Args:
            usage_reports: List of RoleUsageReport from UsageCollector

        Returns:
            WasteReport with all unused capabilities
        """
        report = WasteReport()

        for usage in usage_reports:
            role_waste = self._analyze_role(usage)
            report.role_reports.append(role_waste)
            report.total_unused += role_waste.unused_services
            report.total_permissions += role_waste.total_services

        return report

    def _analyze_role(self, usage) -> RoleWasteReport:
        """Analyze a single role's usage."""
        role_waste = RoleWasteReport(
            role_arn=usage.role_arn,
            role_name=usage.role_name,
            total_services=len(usage.services),
        )

        for svc in usage.services:
            # Check if unused (never accessed or not accessed within threshold)
            is_unused = False
            days_unused = None

            if svc.last_authenticated is None:
                is_unused = True
                days_unused = None  # Never used
            else:
                # Handle timezone-aware datetimes
                last_auth = svc.last_authenticated
                if hasattr(last_auth, "replace"):
                    last_auth = last_auth.replace(tzinfo=None)

                if last_auth < self._cutoff:
                    is_unused = True
                    days_unused = (datetime.utcnow() - last_auth).days

            if is_unused:
                role_waste.unused_services += 1

                # Determine risk level
                namespace = svc.service_namespace.lower()
                risk_level = HIGH_RISK_SERVICES.get(namespace, "low")

                # Build recommendation
                if days_unused is None:
                    recommendation = f"Remove {svc.service_name} access - never used"
                else:
                    recommendation = (
                        f"Remove {svc.service_name} access - unused for {days_unused} days"
                    )

                role_waste.unused_capabilities.append(
                    UnusedCapability(
                        role_arn=usage.role_arn,
                        role_name=usage.role_name,
                        service=namespace,
                        service_name=svc.service_name,
                        days_unused=days_unused,
                        risk_level=risk_level,
                        recommendation=recommendation,
                    )
                )

        # Sort by risk level
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        role_waste.unused_capabilities.sort(
            key=lambda x: (risk_order.get(x.risk_level, 4), x.service)
        )

        return role_waste

    def analyze_from_assets(
        self,
        assets: list[Asset],
        usage_reports: list[any] | None = None,
    ) -> WasteReport:
        """
        Analyze assets for potential waste.

        This is a simpler analysis that doesn't require live AWS access.
        It looks at attack paths and identifies roles that only appear
        in attack paths (pure attack surface, no legitimate use).

        Args:
            assets: Assets from a scan
            usage_reports: Optional live usage data

        Returns:
            WasteReport
        """
        if usage_reports:
            return self.analyze_from_usage_reports(usage_reports)

        # Fallback: offline analysis based on attached policies
        report = WasteReport()

        # Find IAM roles, excluding AWS-managed service roles
        roles = [
            a for a in assets if a.asset_type == "iam:role" and not self._is_aws_managed_role(a)
        ]

        for role in roles:
            role_waste = RoleWasteReport(
                role_arn=role.arn or role.aws_resource_id,
                role_name=role.name,
            )

            policy_docs = role.properties.get("policy_documents", [])
            services_granted = self._extract_services_from_policies(policy_docs)
            role_waste.total_services = len(services_granted)

            if services_granted:
                role_waste.unused_capabilities.append(
                    UnusedCapability(
                        role_arn=role.arn or role.aws_resource_id,
                        role_name=role.name,
                        service="unknown",
                        service_name="Usage data unavailable",
                        days_unused=None,
                        risk_level="info",
                        recommendation="Use --live for accurate usage analysis",
                    )
                )

            if role_waste.unused_capabilities:
                report.role_reports.append(role_waste)
                report.total_unused += role_waste.unused_services
                report.total_permissions += role_waste.total_services

        return report

    def _extract_services_from_policies(self, policy_docs: list[dict]) -> list[str]:
        """Extract service namespaces from policy documents."""
        services: set[str] = set()
        wildcard = False
        for policy in policy_docs or []:
            statements = policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue
                actions = statement.get("Action")
                if not actions:
                    continue
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    if not isinstance(action, str):
                        continue
                    if action == "*":
                        wildcard = True
                        continue
                    if ":" in action:
                        service = action.split(":", 1)[0]
                        if service and service != "*":
                            services.add(service.lower())
                    elif action:
                        services.add(action.lower())
        if wildcard and not services:
            services.update(HIGH_RISK_SERVICES.keys())
        return sorted(services)
