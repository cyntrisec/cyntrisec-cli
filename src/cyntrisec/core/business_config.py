"""
Business Configuration - Define legitimate business context.

This module provides the schema for users to define what paths and assets
are "Business Critical" or "Legitimate Exposure". This inputs into the
graph engine to calculate the "Delta" (Attack Graph - Business Graph).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class BaseConfig(BaseModel):
    """Base configuration for business rules."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


class CriticalFlow(BaseConfig):
    """A required business flow between two assets."""

    source: str = Field(..., description="Source asset ID or tag selector")
    target: str = Field(..., description="Target asset ID or tag selector")
    description: str | None = None
    ports: list[int] | None = None


class EntrypointCriteria(BaseConfig):
    """Criteria for identifying legitimate entrypoints."""

    by_id: list[str] = Field(default_factory=list)
    by_tags: dict[str, str] = Field(default_factory=dict)
    by_type: list[str] = Field(
        default_factory=list,
        description="Asset types considered safe entrypoints (e.g. 'cloudfront:distribution')",
    )


class BusinessConfig(BaseConfig):
    """
    Configuration for defining legitimate business context.

    This allows the engine to distinguish between:
    - Business Critical paths (must exist)
    - Legitimate Exposure (accepted risk)
    - Attack Paths (unnecessary exposure)
    """

    # Versioning for the config file format
    version: Literal["1.0"] = "1.0"

    # 1. Entrypoints: Where legitimate traffic enters
    # Assets matching these criteria are considered "Authorized Exposure"
    entrypoints: EntrypointCriteria = Field(default_factory=EntrypointCriteria)

    # 2. Critical Flows: Traffic that MUST flow
    # Explicitly authorized paths
    critical_flows: list[CriticalFlow] = Field(default_factory=list)

    # 3. Global Allowlist: Tags that mark assets as "Business Critical"
    # Assets with these tags are considered "Authorized" even if exposed.
    # e.g. {"Environment": "Production", "App": "Frontend"}
    global_allowlist: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: str) -> BusinessConfig:
        """Load configuration from a JSON file."""
        import json
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)
