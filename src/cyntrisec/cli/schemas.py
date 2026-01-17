"""
Response schemas for CLI commands.

These Pydantic models provide lightweight enforcement for JSON/agent
outputs so agents can rely on a stable contract. Each command can
reference a schema by name in emit_agent_or_json to validate data
before it is printed.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class BaseSchema(BaseModel):
    """Base config shared by response schemas."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ActionModel(BaseSchema):
    command: str
    reason: str


class ArtifactPathsModel(BaseSchema):
    snapshot_dir: Optional[str] = None
    snapshot: Optional[str] = None
    assets: Optional[str] = None
    relationships: Optional[str] = None
    attack_paths: Optional[str] = None
    findings: Optional[str] = None


class AgentEnvelope(BaseSchema):
    schema_version: str
    status: str
    data: Any
    message: Optional[str] = None
    error_code: Optional[str] = None
    artifact_paths: Optional[ArtifactPathsModel] = None
    suggested_actions: Optional[List[ActionModel]] = None


class ScanResponse(BaseSchema):
    snapshot_id: str
    account_id: Optional[str] = None
    regions: List[str]
    asset_count: int
    relationship_count: int
    finding_count: int
    attack_path_count: int


class AttackPathOut(BaseSchema):
    id: str
    snapshot_id: Optional[str] = None
    source_asset_id: str
    target_asset_id: str
    path_asset_ids: List[str]
    path_relationship_ids: List[str]
    attack_vector: str
    path_length: int
    entry_confidence: float
    exploitability_score: float
    impact_score: float
    risk_score: float
    proof: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class AnalyzePathsResponse(BaseSchema):
    paths: List[AttackPathOut]
    returned: int
    total: int


class FindingOut(BaseSchema):
    id: Optional[str] = None
    snapshot_id: Optional[str] = None
    asset_id: Optional[str] = None
    finding_type: str
    severity: str
    title: str
    description: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class AnalyzeFindingsResponse(BaseSchema):
    findings: List[FindingOut]
    total: int
    filter: str


class WasteCandidate(BaseSchema):
    name: str
    asset_type: str
    reason: str
    asset_id: Optional[str] = None
    monthly_cost_usd: Optional[float] = None


class BusinessAsset(BaseSchema):
    name: str
    asset_type: str
    reason: str
    asset_id: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)


class BusinessAnalysisResponse(BaseSchema):
    entrypoints_requested: List[str]
    entrypoints_found: List[str]
    attackable_count: int
    business_required_count: int
    waste_candidate_count: int
    waste_candidates: List[WasteCandidate]
    business_assets: Optional[List[BusinessAsset]] = None
    unknown_assets: Optional[List[BusinessAsset]] = None


class CutRemediation(BaseSchema):
    priority: int
    action: str
    description: str
    relationship_type: Optional[str] = None
    source: Optional[str] = None
    target: Optional[str] = None
    paths_blocked: int
    path_ids: List[str] = Field(default_factory=list)


class CutsResponse(BaseSchema):
    snapshot_id: Optional[str] = None
    account_id: Optional[str] = None
    total_paths: int
    paths_blocked: int
    coverage: float
    remediations: List[CutRemediation]


class WasteCapability(BaseSchema):
    service: Optional[str] = None
    service_name: Optional[str] = None
    days_unused: Optional[int] = None
    risk_level: str
    recommendation: str
    # Cost estimation fields
    monthly_cost_usd_estimate: Optional[float] = None
    cost_source: Optional[str] = None
    confidence: Optional[str] = None
    assumptions: Optional[List[str]] = None


class WasteRoleReport(BaseSchema):
    role_arn: Optional[str] = None
    role_name: str
    total_services: int
    unused_services: int
    reduction: float
    unused_capabilities: List[WasteCapability]


class WasteResponse(BaseSchema):
    snapshot_id: Optional[str] = None
    account_id: Optional[str] = None
    days_threshold: int
    total_permissions: int
    total_unused: int
    blast_radius_reduction: float
    roles: List[WasteRoleReport]


class CanSimulation(BaseSchema):
    action: str
    resource: Optional[str] = None
    decision: str
    matched_statements: int


class CanResponse(BaseSchema):
    snapshot_id: Optional[str] = None
    principal: str
    resource: str
    action: Optional[str] = None
    can_access: bool
    simulations: List[CanSimulation]
    proof: Dict[str, Any] = Field(default_factory=dict)


class DiffChange(BaseSchema):
    change_type: str
    path_id: Optional[str] = None
    detail: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class DiffResponse(BaseSchema):
    has_regressions: bool
    has_improvements: bool
    summary: Dict[str, Any]
    path_changes: List[DiffChange]
    # Optional extra fields
    old_snapshot: Optional[Dict[str, Any]] = None
    new_snapshot: Optional[Dict[str, Any]] = None
    finding_changes: Optional[List[Dict[str, Any]]] = None
    asset_changes: Optional[List[Dict[str, Any]]] = None
    relationship_changes: Optional[List[Dict[str, Any]]] = None

    model_config = ConfigDict(extra="allow")


class ControlResult(BaseSchema):
    id: str
    title: str
    status: str
    severity: Optional[str] = None
    description: Optional[str] = None


class ComplyResponse(BaseSchema):
    framework: str
    compliance_score: float
    passing: int
    failing: int
    controls: List[ControlResult]


class ReportResponse(BaseSchema):
    output_path: str
    snapshot_id: Optional[str] = None
    account_id: Optional[str] = None
    findings: int
    paths: int


class ManifestResponse(BaseSchema):
    name: str
    version: str
    description: str
    capabilities: List[Dict[str, Any]]
    schemas: Dict[str, Any]
    agentic_features: Dict[str, Any]
    usage_pattern: List[str]

    model_config = ConfigDict(extra="allow")


class RemediationItem(BaseSchema):
    priority: int
    action: str
    description: str
    source: Optional[str] = None
    target: Optional[str] = None
    relationship_type: Optional[str] = None
    paths_blocked: int
    terraform: Optional[str] = None
    status: Optional[str] = None
    terraform_path: Optional[str] = None
    terraform_result: Optional[Dict[str, Any]] = None


class RemediateApplyResult(BaseSchema):
    mode: str
    output_path: Optional[str] = None
    terraform_path: Optional[str] = None
    terraform_dir: Optional[str] = None
    plan_exit_code: Optional[int] = None
    plan_summary: Optional[str] = None
    results: Optional[List[RemediationItem]] = None


class RemediateResponse(BaseSchema):
    snapshot_id: Optional[str] = None
    account_id: Optional[str] = None
    total_paths: int
    paths_blocked: int
    coverage: float
    plan: List[RemediationItem]
    applied: bool
    mode: str
    output_path: Optional[str] = None
    terraform_path: Optional[str] = None
    terraform_dir: Optional[str] = None
    apply: Optional[RemediateApplyResult] = None


class AskResponse(BaseSchema):
    query: str
    intent: str
    results: Dict[str, Any]
    snapshot_id: Optional[str] = None
    entities: Dict[str, Any]
    resolved: str


class ExplainResponse(BaseSchema):
    type: str
    id: str
    explanation: Dict[str, Any]


class SetupIamResponse(BaseSchema):
    account_id: str
    role_name: str
    external_id: Optional[str] = None
    template_format: str
    template: str
    output_path: Optional[str] = None


class ValidateRoleResponse(BaseSchema):
    success: bool
    role_arn: str
    account: Optional[str] = None
    arn: Optional[str] = None
    user_id: Optional[str] = None
    error: Optional[str] = None
    error_type: Optional[str] = None


class ServeToolsResponse(BaseSchema):
    tools: List[Dict[str, Any]]


SCHEMA_REGISTRY = {
    "scan": ScanResponse,
    "analyze_paths": AnalyzePathsResponse,
    "analyze_findings": AnalyzeFindingsResponse,
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


def schema_json() -> Dict[str, Any]:
    """Return JSON schemas for manifest exposure."""
    return {name: model.model_json_schema() for name, model in SCHEMA_REGISTRY.items()}
