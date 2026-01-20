"""
Cost Estimator - metrics for ROI calculation.

Provides estimated monthly costs for assets to prioritize remediation
based on potential savings.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Literal

from cyntrisec.core.schema import Asset


@dataclass
class CostEstimate:
    """Estimated cost for a resource."""

    monthly_cost_usd_estimate: Decimal
    confidence: Literal["low", "medium", "high"]
    cost_source: Literal["estimate", "pricing-api", "cost-explorer"]
    assumptions: list[str]


class CostEstimator:
    """
    Estimates monthly cost of assets.

    Currently uses static pricing estimates (MVP).
    Future versions can integrate with AWS Price List API or Cost Explorer.
    """

    # Static estimates for common resources (USD/month)
    # Based on typical on-demand usage (e.g. m5.large, multi-AZ RDS)
    _STATIC_PRICING = {
        "ec2:instance": Decimal("70.00"),  # ~m5.large
        "ec2:natgateway": Decimal("32.00"),
        "elb:load-balancer": Decimal("20.00"),
        "elbv2:load-balancer": Decimal("22.00"),  # ALB min
        "rds:db-instance": Decimal("100.00"),  # ~db.m5.large
        "redshift:cluster": Decimal("250.00"),
        "opensearch:domain": Decimal("150.00"),
        "eks:cluster": Decimal("73.00"),
    }

    def __init__(self, source: str = "estimate"):
        self.source = source

    def estimate(self, asset: Asset) -> CostEstimate | None:
        """Get cost estimate for an asset."""
        
        # 1. Use existing cost if explicitly set on asset (e.g. from Cost Explorer ingestion)
        if asset.monthly_cost_usd is not None:
             return CostEstimate(
                 monthly_cost_usd_estimate=asset.monthly_cost_usd,
                 confidence="high",
                 cost_source="cost-explorer",
                 assumptions=["Actual usage data"]
             )

        # 2. Key-based lookup for unmanaged resources (e.g. NAT GW)
        # Some assets might have size info in properties to refine this.
        
        base_cost = self._STATIC_PRICING.get(asset.asset_type)
        
        if base_cost is not None:
            return CostEstimate(
                monthly_cost_usd_estimate=base_cost,
                confidence="low",
                cost_source="estimate",
                assumptions=["On-demand pricing", "Typical instance size"]
            )
            
        return None
