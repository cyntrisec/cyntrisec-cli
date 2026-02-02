"""
Cost Estimator - Static pricing for common AWS resources.

Provides monthly cost estimates without requiring additional AWS permissions.
Uses conservative static pricing for "hero" resources where waste is obvious.

Sources:
- estimate: Static rules based on public AWS pricing (default)
- pricing-api: AWS Pricing API (future)
- cost-explorer: Real billing data (future, opt-in)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from cyntrisec.core.schema import Asset

# Average hours per month
HOURS_PER_MONTH = Decimal("730")

# Static pricing (US-East-1, approximate)
# These are conservative estimates for ranking purposes
STATIC_PRICING = {
    # NAT Gateway: $0.045/hr + $0.045/GB processed
    "ec2:nat-gateway": {
        "hourly": Decimal("0.045"),
        "monthly_base": Decimal("32.85"),  # 730 * 0.045
        "confidence": "high",
        "assumptions": [
            "$0.045/hr NAT Gateway base rate (us-east-1)",
            "730 hours/month",
            "Data processing fees not included",
        ],
    },
    # Elastic IP (unattached): $0.005/hr
    "ec2:elastic-ip": {
        "hourly": Decimal("0.005"),
        "monthly_base": Decimal("3.65"),  # 730 * 0.005
        "confidence": "high",
        "assumptions": [
            "$0.005/hr for unused Elastic IP",
            "Only applies when not attached to running instance",
        ],
    },
    # ALB: $0.0225/hr + LCU charges
    "elbv2:load-balancer:application": {
        "hourly": Decimal("0.0225"),
        "monthly_base": Decimal("16.43"),  # 730 * 0.0225
        "confidence": "medium",
        "assumptions": [
            "$0.0225/hr ALB base rate",
            "LCU charges not included (traffic-dependent)",
        ],
    },
    # NLB: $0.0225/hr + NLCU charges
    "elbv2:load-balancer:network": {
        "hourly": Decimal("0.0225"),
        "monthly_base": Decimal("16.43"),
        "confidence": "medium",
        "assumptions": [
            "$0.0225/hr NLB base rate",
            "NLCU charges not included",
        ],
    },
    # EBS gp2/gp3: ~$0.10/GB-month
    "ec2:ebs-volume:gp2": {
        "per_gb_month": Decimal("0.10"),
        "confidence": "high",
        "assumptions": ["$0.10/GB-month for gp2"],
    },
    "ec2:ebs-volume:gp3": {
        "per_gb_month": Decimal("0.08"),
        "confidence": "high",
        "assumptions": ["$0.08/GB-month for gp3 base"],
    },
    # RDS instance classes (approximate)
    "rds:db-instance:db.t3.micro": {
        "monthly_base": Decimal("12.41"),
        "confidence": "medium",
        "assumptions": ["On-demand pricing, single-AZ"],
    },
    "rds:db-instance:db.t3.small": {
        "monthly_base": Decimal("24.82"),
        "confidence": "medium",
        "assumptions": ["On-demand pricing, single-AZ"],
    },
    "rds:db-instance:db.t3.medium": {
        "monthly_base": Decimal("49.64"),
        "confidence": "medium",
        "assumptions": ["On-demand pricing, single-AZ"],
    },
    "rds:db-instance:db.m5.large": {
        "monthly_base": Decimal("124.10"),
        "confidence": "medium",
        "assumptions": ["On-demand pricing, single-AZ"],
    },
}

# Optional regional overrides for static pricing
REGIONAL_PRICING: dict[str, dict[str, dict[str, Any]]] = {}

# Priority ranking for known high-cost resources
COST_PRIORITY = [
    "ec2:nat-gateway",
    "rds:db-instance",
    "elbv2:load-balancer",
    "ec2:ebs-volume",
    "ec2:elastic-ip",
]


@dataclass
class CostEstimate:
    """Cost estimate with provenance metadata."""

    monthly_cost_usd_estimate: Decimal
    cost_source: str  # "estimate", "pricing-api", "cost-explorer"
    confidence: str  # "high", "medium", "low"
    assumptions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "monthly_cost_usd_estimate": float(self.monthly_cost_usd_estimate),
            "cost_source": self.cost_source,
            "confidence": self.confidence,
            "assumptions": self.assumptions,
        }


class CostEstimator:
    """
    Estimate monthly costs for AWS resources.

    Default mode uses static pricing rules that require no extra permissions.
    Future modes can use AWS Pricing API or Cost Explorer for more accuracy.
    """

    def __init__(self, source: str = "estimate", *, region: str = "us-east-1"):
        """
        Initialize estimator.

        Args:
            source: Cost data source - "estimate", "pricing-api", "cost-explorer"
        """
        self._source = source
        self._region = region
        if source not in ("estimate", "pricing-api", "cost-explorer"):
            raise ValueError(f"Unknown cost source: {source}")

    @property
    def source(self) -> str:
        """Return configured cost source."""
        return self._source

    def estimate(self, asset: Asset) -> CostEstimate | None:
        """
        Estimate monthly cost for an asset.

        Returns None if no estimate is available for this asset type.
        """
        region = asset.aws_region or self._region
        if self._source == "estimate":
            return self._static_estimate(asset, region)
        elif self._source == "pricing-api":
            # Future: call AWS Pricing API
            return self._static_estimate(asset, region)  # Fallback for now
        elif self._source == "cost-explorer":
            # Future: call Cost Explorer
            return None  # Requires opt-in
        return None

    def _static_estimate(self, asset: Asset, region: str) -> CostEstimate | None:
        """Generate estimate from static pricing rules."""
        asset_type = asset.asset_type
        props = asset.properties or {}
        regional_table = REGIONAL_PRICING.get(region)
        region_fallback = region != "us-east-1" and regional_table is None

        def _get_pricing(key: str) -> dict[str, Any] | None:
            """Look up pricing by key, falling back from regional to static table."""
            if regional_table is not None and key in regional_table:
                return regional_table[key]
            return STATIC_PRICING.get(key)

        # NAT Gateway
        if asset_type == "ec2:nat-gateway":
            pricing = _get_pricing("ec2:nat-gateway")
            if pricing:
                return CostEstimate(
                    monthly_cost_usd_estimate=pricing["monthly_base"],
                    cost_source="estimate",
                    confidence=pricing["confidence"],
                    assumptions=self._assumptions_with_region(
                        pricing["assumptions"], region_fallback
                    ),
                )

        # Elastic IP (only if unattached)
        if asset_type == "ec2:elastic-ip":
            # Check if attached to an instance
            instance_id = props.get("instance_id") or props.get("InstanceId")
            if not instance_id:
                pricing = _get_pricing("ec2:elastic-ip")
                if pricing:
                    return CostEstimate(
                        monthly_cost_usd_estimate=pricing["monthly_base"],
                        cost_source="estimate",
                        confidence=pricing["confidence"],
                        assumptions=self._assumptions_with_region(
                            pricing["assumptions"], region_fallback
                        ),
                    )
            return None  # Attached EIPs are free

        # Load Balancers
        if asset_type == "elbv2:load-balancer":
            lb_type = props.get("type", "application").lower()
            key = f"elbv2:load-balancer:{lb_type}"
            pricing = _get_pricing(key)
            if pricing:
                return CostEstimate(
                    monthly_cost_usd_estimate=pricing["monthly_base"],
                    cost_source="estimate",
                    confidence=pricing["confidence"],
                    assumptions=self._assumptions_with_region(
                        pricing["assumptions"], region_fallback
                    ),
                )

        # EBS Volumes
        if asset_type == "ec2:ebs-volume":
            volume_type = props.get("volume_type", props.get("VolumeType", "gp2")).lower()
            size_gb = props.get("size", props.get("Size", 0))
            key = f"ec2:ebs-volume:{volume_type}"

            pricing = _get_pricing(key)
            if pricing and size_gb:
                monthly = pricing["per_gb_month"] * Decimal(str(size_gb))
                return CostEstimate(
                    monthly_cost_usd_estimate=monthly,
                    cost_source="estimate",
                    confidence=pricing["confidence"],
                    assumptions=self._assumptions_with_region(
                        pricing["assumptions"] + [f"{size_gb} GB volume"], region_fallback
                    ),
                )

        # RDS Instances
        if asset_type == "rds:db-instance":
            db_class = props.get("db_instance_class", props.get("DBInstanceClass", ""))
            key = f"rds:db-instance:{db_class}"

            pricing = _get_pricing(key)
            if pricing:
                return CostEstimate(
                    monthly_cost_usd_estimate=pricing["monthly_base"],
                    cost_source="estimate",
                    confidence=pricing["confidence"],
                    assumptions=self._assumptions_with_region(
                        pricing["assumptions"], region_fallback
                    ),
                )
            # Unknown class - return with low confidence indicator
            fallback_estimate = self._unknown_rds_estimate(STATIC_PRICING)
            return CostEstimate(
                monthly_cost_usd_estimate=fallback_estimate,
                cost_source="estimate",
                confidence="unknown",
                assumptions=self._assumptions_with_region(
                    ["Unknown RDS class - estimate uses median of known classes"],
                    region_fallback,
                ),
            )

        return None

    @staticmethod
    def _unknown_rds_estimate(pricing_table: dict[str, dict[str, Any]]) -> Decimal:
        """Return a fallback estimate for unknown RDS classes."""
        values = [
            p["monthly_base"]
            for key, p in pricing_table.items()
            if key.startswith("rds:db-instance:") and "monthly_base" in p
        ]
        if not values:
            return Decimal("1")
        values_sorted = sorted(values)
        return values_sorted[len(values_sorted) // 2]

    @staticmethod
    def _assumptions_with_region(assumptions: list[str], region_fallback: bool) -> list[str]:
        """Add region fallback note when needed."""
        if region_fallback:
            return assumptions + ["Pricing fallback: us-east-1 (region not supported)"]
        return assumptions

    def get_priority(self, asset: Asset) -> int:
        """
        Get cost priority ranking for an asset.

        Lower number = higher priority (more likely to be expensive waste).
        Returns 999 for unknown types.
        """
        asset_type = asset.asset_type

        for i, prefix in enumerate(COST_PRIORITY):
            if asset_type.startswith(prefix):
                return i

        return 999  # Unknown type

    def sort_by_cost_priority(self, assets: list[Asset]) -> list[Asset]:
        """Sort assets by cost priority (highest cost first)."""
        return sorted(assets, key=lambda a: self.get_priority(a))
