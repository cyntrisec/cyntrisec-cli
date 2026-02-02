"""
Compliance Mapping - Map findings to compliance frameworks.

Supports:
- CIS AWS Foundations Benchmark v1.5
- SOC 2 Type II controls

Each finding type is mapped to relevant compliance controls,
allowing users to understand their compliance posture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from cyntrisec.core.schema import Asset, Finding


class Framework(str, Enum):
    """Supported compliance frameworks."""

    CIS_AWS = "CIS-AWS"
    SOC2 = "SOC2"


@dataclass
class Control:
    """A compliance control."""

    id: str
    framework: Framework
    title: str
    description: str
    severity: str = "medium"

    @property
    def full_id(self) -> str:
        return f"{self.framework.value}:{self.id}"


@dataclass
class ControlMapping:
    """Mapping between a finding type and compliance controls."""

    finding_type: str
    controls: list[Control] = field(default_factory=list)


@dataclass
class ComplianceResult:
    """Result of compliance check for a single control."""

    control: Control
    status: str  # "pass", "fail", "unknown"
    findings: list[Finding] = field(default_factory=list)
    assets_affected: int = 0

    @property
    def is_passing(self) -> bool:
        return self.status == "pass"


@dataclass
class ComplianceReport:
    """Full compliance report for a framework."""

    framework: Framework
    results: list[ComplianceResult] = field(default_factory=list)
    data_gaps: dict[str, dict] = field(default_factory=dict)

    @property
    def passing(self) -> int:
        return sum(1 for r in self.results if r.status == "pass")

    @property
    def failing(self) -> int:
        return sum(1 for r in self.results if r.status == "fail")

    @property
    def unknown(self) -> int:
        return sum(1 for r in self.results if r.status not in {"pass", "fail"})

    @property
    def compliance_score(self) -> float:
        """Percentage of controls passing (out of all controls including unknown)."""
        total = len(self.results)
        return self.passing / total if total > 0 else 0.0

    @property
    def evaluated_score(self) -> float:
        """Percentage of controls passing (out of evaluated controls only)."""
        total = self.passing + self.failing
        return self.passing / total if total > 0 else 0.0


CONTROL_ASSET_REQUIREMENTS: dict[str, list[str]] = {
    # IAM
    "CIS-AWS:1.4": ["iam:user"],
    "CIS-AWS:1.5": ["iam:user"],
    "CIS-AWS:1.10": ["iam:user"],
    "CIS-AWS:1.12": ["iam:user"],
    "CIS-AWS:1.16": ["iam:user"],
    "CIS-AWS:1.17": ["iam:role"],
    # S3
    "CIS-AWS:2.1.1": ["s3:bucket"],
    "CIS-AWS:2.1.2": ["s3:bucket"],
    "CIS-AWS:2.1.5": ["s3:bucket"],
    # EC2/VPC
    "CIS-AWS:5.1": ["ec2:security-group"],
    "CIS-AWS:5.2": ["ec2:security-group"],
    "CIS-AWS:5.3": ["ec2:vpc"],
    "CIS-AWS:5.4": ["ec2:instance"],
    # SOC2
    "SOC2:CC6.1": ["iam:user", "iam:role"],
    "SOC2:CC6.2": ["iam:user"],
    "SOC2:CC6.3": ["iam:role"],
    "SOC2:CC6.6": ["s3:bucket"],
    "SOC2:CC7.1": ["ec2:security-group", "s3:bucket"],
    "SOC2:CC7.2": ["iam:role"],
    "SOC2:CC6.7": ["s3:bucket"],
}


# CIS AWS Foundations Benchmark v1.5 Controls
CIS_CONTROLS = [
    # IAM
    Control(
        "1.4",
        Framework.CIS_AWS,
        "Ensure no root account access key exists",
        "The root account should not have access keys configured",
        "critical",
    ),
    Control(
        "1.5",
        Framework.CIS_AWS,
        "Ensure MFA is enabled for root account",
        "The root account should have MFA enabled",
        "critical",
    ),
    Control(
        "1.10",
        Framework.CIS_AWS,
        "Ensure MFA is enabled for all IAM users with console password",
        "All IAM users with console access should have MFA enabled",
        "high",
    ),
    Control(
        "1.12",
        Framework.CIS_AWS,
        "Ensure credentials unused for 90 days are disabled",
        "IAM credentials not used in 90 days should be disabled",
        "medium",
    ),
    Control(
        "1.16",
        Framework.CIS_AWS,
        "Ensure IAM policies not attached directly to users",
        "IAM policies should be attached to groups/roles, not users",
        "medium",
    ),
    Control(
        "1.17",
        Framework.CIS_AWS,
        "Ensure wildcard (*) not used in IAM policies",
        "IAM policies should not use wildcards for resources",
        "high",
    ),
    # S3
    Control(
        "2.1.1",
        Framework.CIS_AWS,
        "Ensure S3 bucket Block Public Access is enabled",
        "All S3 buckets should have Block Public Access enabled",
        "high",
    ),
    Control(
        "2.1.2",
        Framework.CIS_AWS,
        "Ensure S3 bucket Block Public Access at account level",
        "Account-level S3 Block Public Access should be enabled",
        "high",
    ),
    Control(
        "2.1.5",
        Framework.CIS_AWS,
        "Ensure S3 bucket access logging is enabled",
        "S3 buckets should have access logging enabled",
        "medium",
    ),
    # EC2/VPC
    Control(
        "5.1",
        Framework.CIS_AWS,
        "Ensure no open Security Groups to 0.0.0.0/0",
        "Security groups should not allow 0.0.0.0/0 ingress",
        "high",
    ),
    Control(
        "5.2",
        Framework.CIS_AWS,
        "Ensure default security group restricts all traffic",
        "VPC default security groups should not allow any traffic",
        "medium",
    ),
    Control(
        "5.3",
        Framework.CIS_AWS,
        "Ensure VPC flow logging is enabled",
        "All VPCs should have flow logging enabled",
        "medium",
    ),
    Control(
        "5.4",
        Framework.CIS_AWS,
        "Ensure EC2 instances use IMDSv2",
        "EC2 instances should use Instance Metadata Service v2",
        "medium",
    ),
]

# SOC 2 Type II Controls
SOC2_CONTROLS = [
    Control(
        "CC6.1",
        Framework.SOC2,
        "Logical and Physical Access Controls",
        "Access to system components is controlled by access policies",
        "high",
    ),
    Control(
        "CC6.2",
        Framework.SOC2,
        "Prior to Access",
        "Users are authenticated before access is granted",
        "high",
    ),
    Control(
        "CC6.3",
        Framework.SOC2,
        "Role-Based Access",
        "Access is based on job function and least privilege",
        "high",
    ),
    Control(
        "CC6.6",
        Framework.SOC2,
        "Encryption of Data",
        "Data at rest and in transit is encrypted",
        "high",
    ),
    Control(
        "CC6.7",
        Framework.SOC2,
        "Data Disposal",
        "Data is disposed of securely when no longer needed",
        "medium",
    ),
    Control(
        "CC7.1",
        Framework.SOC2,
        "Security Monitoring",
        "Security events are detected and responded to",
        "high",
    ),
    Control(
        "CC7.2",
        Framework.SOC2,
        "Incident Response",
        "Security incidents are managed and resolved",
        "high",
    ),
]

# Mapping from finding types to controls
FINDING_TO_CONTROLS: dict[str, list[str]] = {
    # IAM findings
    "iam_overly_permissive_trust": ["CIS-AWS:1.17", "SOC2:CC6.3"],
    "iam_wildcard_policy": ["CIS-AWS:1.17", "SOC2:CC6.3"],
    "iam_unused_credentials": ["CIS-AWS:1.12", "SOC2:CC6.1"],
    "iam_user_direct_policy": ["CIS-AWS:1.16", "SOC2:CC6.3"],
    "iam_no_mfa": ["CIS-AWS:1.10", "SOC2:CC6.2"],
    # S3 findings
    "s3_public_bucket": ["CIS-AWS:2.1.1", "CIS-AWS:2.1.2", "SOC2:CC6.1"],
    "s3-bucket-no-public-access-block": ["CIS-AWS:2.1.1", "CIS-AWS:2.1.2", "SOC2:CC6.1"],
    "s3-bucket-public-access-block": ["CIS-AWS:2.1.1", "CIS-AWS:2.1.2", "SOC2:CC6.1"],
    "s3-bucket-partial-public-access-block": ["CIS-AWS:2.1.1", "CIS-AWS:2.1.5", "SOC2:CC6.1"],
    "s3-bucket-public-acl": ["CIS-AWS:2.1.1", "SOC2:CC6.1"],
    "s3-bucket-authenticated-users-acl": ["CIS-AWS:2.1.1", "SOC2:CC6.1"],
    "s3_no_encryption": ["SOC2:CC6.6"],
    "s3_no_logging": ["CIS-AWS:2.1.5", "SOC2:CC7.1"],
    # EC2/Network findings
    "security_group_open_to_world": ["CIS-AWS:5.1", "SOC2:CC6.1"],
    "security-group-open-to-world": ["CIS-AWS:5.1", "CIS-AWS:5.2", "SOC2:CC6.1"],
    "ec2-public-ip": ["CIS-AWS:5.1", "CIS-AWS:5.2", "SOC2:CC6.1"],
    "vpc_default_sg_in_use": ["CIS-AWS:5.2", "SOC2:CC6.1"],
    "vpc_no_flow_logs": ["CIS-AWS:5.3", "SOC2:CC7.1"],
    "ec2_imdsv1": ["CIS-AWS:5.4", "SOC2:CC6.1"],
    "ec2-imdsv1-enabled": ["CIS-AWS:5.4", "SOC2:CC6.1"],
    "iam-role-trust-any-principal": ["CIS-AWS:1.17", "SOC2:CC6.3"],
}


class ComplianceChecker:
    """
    Check compliance against frameworks based on scan findings.
    """

    def __init__(self):
        self._controls_by_id: dict[str, Control] = {}
        for ctrl in CIS_CONTROLS + SOC2_CONTROLS:
            self._controls_by_id[ctrl.full_id] = ctrl

    def check(
        self,
        findings: list[Finding],
        assets: list[Asset],
        *,
        framework: Framework | None = None,
        collection_errors: list[dict] | None = None,
    ) -> ComplianceReport:
        """
        Check compliance based on findings.

        Args:
            findings: Security findings from scan
            assets: Assets from scan
            framework: Specific framework (default: CIS_AWS)

        Returns:
            ComplianceReport with pass/fail status per control
        """
        framework = framework or Framework.CIS_AWS
        controls = CIS_CONTROLS if framework == Framework.CIS_AWS else SOC2_CONTROLS

        # Build mapping: control_id -> findings that violate it
        violations: dict[str, list[Finding]] = {}
        for finding in findings:
            control_ids = FINDING_TO_CONTROLS.get(finding.finding_type, [])
            for ctrl_id in control_ids:
                if ctrl_id not in violations:
                    violations[ctrl_id] = []
                violations[ctrl_id].append(finding)

        asset_types = {a.asset_type for a in assets}
        error_services: set[str] = {
            str(err.get("service")) for err in (collection_errors or []) if err.get("service")
        }

        # Build results
        results = []
        data_gaps: dict[str, dict] = {}
        for ctrl in controls:
            violating_findings = violations.get(ctrl.full_id, [])
            required_assets = CONTROL_ASSET_REQUIREMENTS.get(ctrl.full_id, [])

            if violating_findings:
                status = "fail"
            else:
                has_assets = not required_assets or any(
                    asset_type in asset_types for asset_type in required_assets
                )
                if has_assets:
                    status = "pass"
                else:
                    status = "unknown"
                    data_gaps[ctrl.full_id] = {
                        "reason": "missing_assets",
                        "required_assets": required_assets,
                    }

            if status != "fail" and required_assets and error_services:
                impacted = self._assets_impacted_by_errors(required_assets, error_services)
                if impacted:
                    status = "unknown"
                    data_gaps[ctrl.full_id] = {
                        "reason": "collection_error",
                        "required_assets": required_assets,
                        "services": sorted(impacted),
                    }

            results.append(
                ComplianceResult(
                    control=ctrl,
                    status=status,
                    findings=violating_findings,
                    assets_affected=len(set(f.asset_id for f in violating_findings)),
                )
            )

        return ComplianceReport(
            framework=framework,
            results=results,
            data_gaps=data_gaps,
        )

    @staticmethod
    def _assets_impacted_by_errors(
        required_assets: list[str],
        error_services: set[str],
    ) -> set[str]:
        """Map collection errors to affected control services."""
        impacted: set[str] = set()
        for service in error_services:
            if service == "iam" and any(a.startswith("iam:") for a in required_assets):
                impacted.add(service)
            if service == "s3" and any(a.startswith("s3:") for a in required_assets):
                impacted.add(service)
            if service in {"ec2", "network"} and any(a.startswith("ec2:") for a in required_assets):
                impacted.add(service)
            if service == "lambda" and any(a.startswith("lambda:") for a in required_assets):
                impacted.add(service)
            if service == "rds" and any(a.startswith("rds:") for a in required_assets):
                impacted.add(service)
        return impacted

    def get_control(self, control_id: str) -> Control | None:
        """Get a control by ID."""
        return self._controls_by_id.get(control_id)

    def summary(self, report: ComplianceReport) -> dict:
        """Generate summary statistics for a report."""
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        failing_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for result in report.results:
            sev = result.control.severity
            by_severity[sev] = by_severity.get(sev, 0) + 1
            if not result.is_passing:
                failing_by_severity[sev] = failing_by_severity.get(sev, 0) + 1

        return {
            "framework": report.framework.value,
            "total_controls": len(report.results),
            "passing": report.passing,
            "failing": report.failing,
            "unknown": report.unknown,
            "compliance_score": report.compliance_score,
            "evaluated_score": report.evaluated_score,
            "by_severity": by_severity,
            "failing_by_severity": failing_by_severity,
        }
