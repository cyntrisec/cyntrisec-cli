"""
Core Schema - Pydantic models for the capability graph.

Simplified from the SaaS version:
- No tenant_id, workspace_id, connection_id (single-account CLI)
- No SQLAlchemy relationship hints
- Added monthly_cost_usd for cost analysis
- Added proof field for evidence chains
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SnapshotStatus(str, Enum):
    """Status of a scan snapshot."""

    running = "running"
    completed = "completed"
    completed_with_errors = "completed_with_errors"
    failed = "failed"


class FindingSeverity(str, Enum):
    """Severity level for security findings."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class BaseSchema(BaseModel):
    """Base configuration for all models."""

    model_config = ConfigDict(
        extra="forbid",
        use_enum_values=True,
        str_strip_whitespace=True,
    )


class Snapshot(BaseSchema):
    """
    A snapshot represents a single scan run.

    Contains metadata about the scan including timing,
    status, and aggregate counts.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    aws_account_id: str = Field(..., min_length=12, max_length=12)
    regions: list[str]
    status: SnapshotStatus = SnapshotStatus.running
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None

    # Counts
    asset_count: int = 0
    relationship_count: int = 0
    finding_count: int = 0
    path_count: int = 0

    # Metadata
    scan_params: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    errors: list[dict[str, Any]] | None = None


class Asset(BaseSchema):
    """
    An asset represents a node in the capability graph.

    Assets include:
    - AWS resources (EC2, IAM roles, S3 buckets, Lambda, RDS, etc.)
    - Logical groupings (VPCs, subnets, security groups)
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    snapshot_id: uuid.UUID

    # Identity
    asset_type: str = Field(..., min_length=1, max_length=50)
    aws_region: str | None = None
    aws_resource_id: str = Field(..., min_length=1, max_length=255)
    arn: str | None = None
    name: str = Field(..., min_length=1, max_length=500)

    # Properties and tags
    properties: dict[str, Any] = Field(default_factory=dict)
    tags: dict[str, str] = Field(default_factory=dict)
    labels: set[str] = Field(default_factory=set)

    # Cost analysis
    monthly_cost_usd: Decimal | None = None

    # Flags for analysis
    is_internet_facing: bool = False
    is_sensitive_target: bool = False


class Relationship(BaseSchema):
    """
    A relationship represents an edge in the capability graph.

    Relationship types:
    - TRUSTS: IAM trust relationships
    - ALLOWS: Security group rules, NACLs, IAM policies
    - ROUTES_TO: Route table entries, LB targets
    - ATTACHED_TO: ENIs, EBS volumes, instance profiles
    - CONTAINS: VPC → Subnet, Subnet → Instance
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    snapshot_id: uuid.UUID

    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    relationship_type: str = Field(..., min_length=1, max_length=50)

    # Edge properties (ports, protocols, conditions)
    properties: dict[str, Any] = Field(default_factory=dict)
    labels: set[str] = Field(default_factory=set)

    # For attack path analysis
    traversal_cost: float = 1.0  # Lower = easier to traverse


class Finding(BaseSchema):
    """
    A security finding discovered during scanning.

    Findings include:
    - Misconfigurations (public S3, overly permissive IAM)
    - Security risks (missing encryption, weak TLS)
    - Attack surface exposure (internet-facing without WAF)
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    snapshot_id: uuid.UUID
    asset_id: uuid.UUID

    finding_type: str = Field(..., min_length=1, max_length=100)
    severity: FindingSeverity
    title: str = Field(..., min_length=1, max_length=500)
    description: str | None = None
    remediation: str | None = None

    # Evidence for proof-carrying output
    evidence: dict[str, Any] = Field(default_factory=dict)


class AttackPath(BaseSchema):
    """
    An attack path from an entry point to a sensitive target.

    Attack paths represent traversable routes through the graph
    that could be exploited by an attacker.

    Risk scoring:
    - entry_confidence: How likely an attacker can reach entry (0-1)
    - exploitability: Difficulty of traversing the path (higher = easier)
    - impact: Value of the target (higher = more valuable)
    - risk_score: Combined score (entry * exploit * impact)
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    snapshot_id: uuid.UUID

    # Path endpoints
    source_asset_id: uuid.UUID  # Entry point (internet-facing)
    target_asset_id: uuid.UUID  # Sensitive target

    # Full path
    path_asset_ids: list[uuid.UUID] = Field(..., min_length=2)
    path_relationship_ids: list[uuid.UUID] = Field(..., min_length=1)

    # Classification
    attack_vector: str = Field(..., min_length=1, max_length=100)
    path_length: int = Field(..., ge=1)

    # Risk scoring
    entry_confidence: Decimal = Field(..., ge=Decimal("0"), le=Decimal("1"))
    exploitability_score: Decimal = Field(..., ge=Decimal("0"))
    impact_score: Decimal = Field(..., ge=Decimal("0"))
    risk_score: Decimal = Field(..., ge=Decimal("0"))

    # Proof chain - evidence for why this path exists
    proof: dict[str, Any] = Field(default_factory=dict)


class CostCutCandidate(BaseSchema):
    """
    A resource that can potentially be removed or isolated.

    These are assets that:
    - Appear in attack paths but not in legitimate business paths
    - Have no observed usage (optional, if traffic data available)
    - Removal would reduce attack surface without breaking functionality
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    snapshot_id: uuid.UUID
    asset_id: uuid.UUID

    # Why this is a candidate
    reason: str
    action: str  # "remove", "isolate", "restrict"
    confidence: Decimal = Field(..., ge=Decimal("0"), le=Decimal("1"))

    # Cost impact
    monthly_savings_usd: Decimal = Field(default=Decimal("0"))

    # Security impact
    paths_blocked: int = 0  # How many attack paths this eliminates
    risk_reduction: Decimal = Field(default=Decimal("0"))

    # Evidence
    proof: dict[str, Any] = Field(default_factory=dict)
