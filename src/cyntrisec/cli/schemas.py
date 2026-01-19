"""
Response schemas for CLI commands.

These Pydantic models provide lightweight enforcement for JSON/agent
outputs so agents can rely on a stable contract. Each command can
reference a schema by name in emit_agent_or_json to validate data
before it is printed.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class BaseSchema(BaseModel):
    """Base config shared by response schemas."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ActionModel(BaseSchema):
    command: str
    reason: str


class ArtifactPathsModel(BaseSchema):
    snapshot_dir: str | None = None
    snapshot: str | None = None
    assets: str | None = None
    relationships: str | None = None
    attack_paths: str | None = None
    findings: str | None = None


class AgentEnvelope(BaseSchema):
    schema_version: str
    status: str
    data: Any
    message: str | None = None
    error_code: str | None = None
    artifact_paths: ArtifactPathsModel | None = None
    suggested_actions: list[ActionModel] | None = None


class ScanResponse(BaseSchema):
    scan_id: str
    snapshot_id: str
    account_id: str | None = None
    regions: list[str]
    asset_count: int
    relationship_count: int
    finding_count: int
    attack_path_count: int
    warnings: list[str] | None = None


class AttackPathOut(BaseSchema):
    id: str
    snapshot_id: str | None = None
    source_asset_id: str
    target_asset_id: str
    path_asset_ids: list[str]
    path_relationship_ids: list[str]
    attack_vector: str
    path_length: int
    entry_confidence: float
    exploitability_score: float
    impact_score: float
    risk_score: float
    proof: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class AnalyzePathsResponse(BaseSchema):
    paths: list[AttackPathOut]
    returned: int
    total: int


class FindingOut(BaseSchema):
    id: str | None = None
    snapshot_id: str | None = None
    asset_id: str | None = None
    finding_type: str
    severity: str
    title: str
    description: str | None = None
    remediation: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class AnalyzeFindingsResponse(BaseSchema):
    findings: list[FindingOut]
    total: int
    filter: str


class AnalyzeStatsResponse(BaseSchema):
    snapshot_id: str | None = None
    scan_id: str | None = None
    account_id: str | None = None
    asset_count: int
    relationship_count: int
    finding_count: int
    path_count: int
    regions: list[str]
    status: str


class WasteCandidate(BaseSchema):
    name: str
    asset_type: str
    reason: str
    asset_id: str | None = None
    monthly_cost_usd: float | None = None


class BusinessAsset(BaseSchema):
    name: str
    asset_type: str
    reason: str
    asset_id: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class BusinessAnalysisResponse(BaseSchema):
    entrypoints_requested: list[str]
    entrypoints_found: list[str]
    attackable_count: int
    business_required_count: int
    waste_candidate_count: int
    waste_candidates: list[WasteCandidate]
    business_assets: list[BusinessAsset] | None = None
    unknown_assets: list[BusinessAsset] | None = None


class CutRemediation(BaseSchema):
    priority: int
    action: str
    description: str
    relationship_type: str | None = None
    source: str | None = None
    target: str | None = None
    paths_blocked: int
    path_ids: list[str] = Field(default_factory=list)


class CutsResponse(BaseSchema):
    snapshot_id: str | None = None
    account_id: str | None = None
    total_paths: int
    paths_blocked: int
    coverage: float
    remediations: list[CutRemediation]


class WasteCapability(BaseSchema):
    service: str | None = None
    service_name: str | None = None
    days_unused: int | None = None
    risk_level: str
    recommendation: str
    # Cost estimation fields
    monthly_cost_usd_estimate: float | None = None
    cost_source: str | None = None
    confidence: str | None = None
    assumptions: list[str] | None = None


class WasteRoleReport(BaseSchema):
    role_arn: str | None = None
    role_name: str
    total_services: int
    unused_services: int
    reduction: float
    unused_capabilities: list[WasteCapability]


class WasteResponse(BaseSchema):
    snapshot_id: str | None = None
    account_id: str | None = None
    days_threshold: int
    total_permissions: int
    total_unused: int
    blast_radius_reduction: float
    roles: list[WasteRoleReport]


class CanSimulation(BaseSchema):
    action: str
    resource: str | None = None
    decision: str
    matched_statements: int


class CanResponse(BaseSchema):
    snapshot_id: str | None = None
    principal: str
    resource: str
    action: str | None = None
    can_access: bool
    simulations: list[CanSimulation]
    proof: dict[str, Any] = Field(default_factory=dict)


class DiffChange(BaseSchema):
    change_type: str
    path_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class DiffResponse(BaseSchema):
    has_regressions: bool
    has_improvements: bool
    summary: dict[str, Any]
    path_changes: list[DiffChange]
    # Optional extra fields
    old_snapshot: dict[str, Any] | None = None
    new_snapshot: dict[str, Any] | None = None
    finding_changes: list[dict[str, Any]] | None = None
    asset_changes: list[dict[str, Any]] | None = None
    relationship_changes: list[dict[str, Any]] | None = None

    model_config = ConfigDict(extra="allow")


class ControlResult(BaseSchema):
    id: str
    title: str
    status: str
    severity: str | None = None
    description: str | None = None


class ComplyResponse(BaseSchema):
    framework: str
    compliance_score: float
    passing: int
    failing: int
    controls: list[ControlResult]


class ReportResponse(BaseSchema):
    output_path: str
    snapshot_id: str | None = None
    account_id: str | None = None
    findings: int
    paths: int


class ManifestResponse(BaseSchema):
    name: str
    version: str
    description: str
    capabilities: list[dict[str, Any]]
    schemas: dict[str, Any]
    agentic_features: dict[str, Any]
    usage_pattern: list[str]

    model_config = ConfigDict(extra="allow")


class RemediationItem(BaseSchema):
    priority: int
    action: str
    description: str
    source: str | None = None
    target: str | None = None
    relationship_type: str | None = None
    paths_blocked: int
    terraform: str | None = None
    status: str | None = None
    terraform_path: str | None = None
    terraform_result: dict[str, Any] | None = None


class RemediateApplyResult(BaseSchema):
    mode: str
    output_path: str | None = None
    terraform_path: str | None = None
    terraform_dir: str | None = None
    plan_exit_code: int | None = None
    plan_summary: str | None = None
    results: list[RemediationItem] | None = None


class RemediateResponse(BaseSchema):
    snapshot_id: str | None = None
    account_id: str | None = None
    total_paths: int
    paths_blocked: int
    coverage: float
    plan: list[RemediationItem]
    applied: bool
    mode: str
    output_path: str | None = None
    terraform_path: str | None = None
    terraform_dir: str | None = None
    apply: RemediateApplyResult | None = None


class AskResponse(BaseSchema):
    query: str
    intent: str
    results: dict[str, Any]
    snapshot_id: str | None = None
    entities: dict[str, Any]
    resolved: str


class ExplainResponse(BaseSchema):
    type: str
    id: str
    explanation: dict[str, Any]


class SetupIamResponse(BaseSchema):
    account_id: str
    role_name: str
    external_id: str | None = None
    template_format: str
    template: str
    output_path: str | None = None


class ValidateRoleResponse(BaseSchema):
    success: bool
    role_arn: str
    account: str | None = None
    arn: str | None = None
    user_id: str | None = None
    error: str | None = None
    error_type: str | None = None


class ServeToolsResponse(BaseSchema):
    tools: list[dict[str, Any]]


SCHEMA_REGISTRY = {
    "scan": ScanResponse,
    "analyze_paths": AnalyzePathsResponse,
    "analyze_findings": AnalyzeFindingsResponse,
    "analyze_stats": AnalyzeStatsResponse,
    "analyze_business": BusinessAnalysisResponse,
    "cuts": CutsResponse,
    "waste": WasteResponse,
    "can": CanResponse,
    "diff": DiffResponse,
    "comply": ComplyResponse,
    "report": ReportResponse,
    "manifest": ManifestResponse,
    "remediate": RemediateResponse,
    "ask": AskResponse,
    "explain": ExplainResponse,
    "setup_iam": SetupIamResponse,
    "validate_role": ValidateRoleResponse,
    "serve_tools": ServeToolsResponse,
}


def schema_json() -> dict[str, Any]:
    """Return JSON schemas for manifest exposure."""
    return {name: model.model_json_schema() for name, model in SCHEMA_REGISTRY.items()}
