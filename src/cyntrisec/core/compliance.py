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

    @property
    def passing(self) -> int:
        return sum(1 for r in self.results if r.is_passing)

    @property
    def failing(self) -> int:
        return sum(1 for r in self.results if not r.is_passing)

    @property
    def compliance_score(self) -> float:
        """Percentage of controls passing."""
        total = len(self.results)
        return self.passing / total if total > 0 else 1.0


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
    "s3-bucket-public-access-block": ["CIS-AWS:2.1.1", "CIS-AWS:2.1.2", "SOC2:CC6.1"],
    "s3-bucket-partial-public-access-block": ["CIS-AWS:2.1.1", "CIS-AWS:2.1.5", "SOC2:CC6.1"],
    "s3_no_encryption": ["SOC2:CC6.6"],
    "s3_no_logging": ["CIS-AWS:2.1.5", "SOC2:CC7.1"],
    # EC2/Network findings
    "security_group_open_to_world": ["CIS-AWS:5.1", "SOC2:CC6.1"],
    "security-group-open-to-world": ["CIS-AWS:5.1", "CIS-AWS:5.2", "SOC2:CC6.1"],
    "ec2-public-ip": ["CIS-AWS:5.1", "CIS-AWS:5.2", "SOC2:CC6.1"],
    "vpc_default_sg_in_use": ["CIS-AWS:5.2", "SOC2:CC6.1"],
    "vpc_no_flow_logs": ["CIS-AWS:5.3", "SOC2:CC7.1"],
    "ec2_imdsv1": ["CIS-AWS:5.4", "SOC2:CC6.1"],
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

        # Build results
        results = []
        for ctrl in controls:
            violating_findings = violations.get(ctrl.full_id, [])

            if violating_findings:
                status = "fail"
            else:
                # Check if we have relevant assets to make a determination
                status = "pass"  # Assume pass if no violations found

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
        )

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
            "compliance_score": report.compliance_score,
            "by_severity": by_severity,
            "failing_by_severity": failing_by_severity,
        }
