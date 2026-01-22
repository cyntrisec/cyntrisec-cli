# Changelog

All notable changes to this project will be documented in this file.
The format is based on Keep a Changelog, and this project adheres to
Semantic Versioning.
## [0.1.7] - 2026-01-22
### Fixed
- **MCP Server Crash**: Fixed `AttributeError: 'str' object has no attribute 'value'` when serializing `confidence_level` (and previously `edge_kind`) enums. Added graceful fallback to handle both Enum objects and raw strings.
- **Compare Scans Error**: Fixed logic error in `compare_scans` where `asset_map` lookups could fail if `snapshot.id` was missing. Added null safety checks for snapshot usage in cache keys.

## [0.1.6] - 2026-01-22
### Fixed
- **MCP Server Data Model Bugs**: Fixed 3 critical bugs preventing MCP tools from working in Claude Desktop:
  - `get_assets`: Changed `a.region` to `a.aws_region` to match Asset model field name
  - `get_assets`: Changed `is_entry_point` to `is_internet_facing` to match Asset model field name
  - `get_relationships`: Fixed `edge_kind.value` error - now handles both string and enum values (due to `use_enum_values=True` in Pydantic)
  - `get_findings`: Fixed `resource_type`/`recommendation` to use correct field names `finding_type`/`remediation`
  - `explain_finding`: Same field name fixes as `get_findings`
- **FileSystemStorage Type Handling**: Now accepts `Path | str | None` for `base_dir` parameter, automatically converting strings to Path objects

### Changed
- **MCP Server Code Quality**: Refactored redundant `asset_map` access pattern in `get_relationships()` with `get_asset_name()` helper function for cleaner, more readable code

## [0.1.5] - 2026-01-21
### Added
- **Capability Graph Algorithm Upgrade**:
  - **Edge Kind Classification**: Added `EdgeKind` enum (STRUCTURAL, CAPABILITY, UNKNOWN) to distinguish traversable capability edges from structural context
  - **EdgeEvidence Model**: Track policy provenance (policy_sid, policy_arn, permission, raw_statement) for audit trails
  - **Action-Specific IAM Edges**: Replaced generic `MAY_ACCESS` with specific edge types:
    - `MAY_READ_SECRET` (secretsmanager:GetSecretValue)
    - `MAY_READ_PARAMETER` (ssm:GetParameter*)
    - `MAY_DECRYPT` (kms:Decrypt)
    - `MAY_READ_S3_OBJECT` (s3:GetObject)
    - `MAY_CREATE_LAMBDA` (lambda:CreateFunction)
  - **Network Reachability Modeling**: Added `CAN_REACH` edges for:
    - Internet-facing assets (0.0.0.0/0, ::/0 ingress rules)
    - SG-to-SG lateral movement (UserIdGroupPairs)
    - CIDR containment inference for subnet reachability
  - **Condition Evaluation**: Added `ConditionEvaluator` with tri-state results (TRUE, FALSE, UNKNOWN) for IAM conditions
  - **Explicit Deny Awareness**: Detect permission boundaries, SCPs, and identity policy denies that may block access

- **Two-Phase Path Discovery**:
  - **Phase A (Discovery)**: Capability-only traversal using `AttackerState` (principals, network_identity, compromised_assets)
  - **Phase B (Validation)**: `PathValidator` verifies network preconditions and IAM motifs
  - **Confidence Scoring**: `ConfidenceLevel` (HIGH, MED, LOW) with specific `confidence_reason` explanations:
    - HIGH: All preconditions verified
    - MED: Some conditions UNKNOWN or explicit deny detected
    - LOW: PassRole motif incomplete or multiple unknowns

- **PassRole Privilege Escalation Detection**:
  - `CAN_PASS_TO` edge creation for iam:PassRole permissions
  - PassRole motif validation (role → PassRole → Lambda trust policy)
  - Confidence adjustment when target trust policy doesn't allow lambda.amazonaws.com

- **MCP Server - 6 New Tools**: Expanded MCP toolset from 9 to 15 tools:
  - `get_findings`: Security findings with severity filtering
  - `get_assets`: Assets with type/name filtering
  - `get_relationships`: Relationships between assets with filtering
  - `explain_path`: Detailed hop-by-hop attack path breakdown
  - `explain_finding`: Detailed finding explanation with remediation
  - `get_terraform_snippet`: Generate Terraform code for remediations

### Changed
- **PathFinder**: Now traverses only CAPABILITY edges (ignores STRUCTURAL for attack path discovery)
- **Entry Point Computation**: Uses `CAN_REACH` edges from "world" with port-based confidence (web=0.9, admin=0.7, db=0.6)
- **Risk Scoring**: Combined edge weights with confidence multipliers for more accurate risk assessment
- **CLI `analyze paths`**: Now displays confidence_level and confidence_reason, color-coded by confidence
- **JSON Output Schema**: Includes `attack_chain_relationship_ids`, `context_relationship_ids`, `confidence_level`, `confidence_reason`, and edge evidence
- **Backward Compatibility**: Added edge_kind inference for legacy scan data via `--include-unknown` flag
- **`get_attack_paths` MCP**: Enhanced with `min_risk` filter, `confidence_level`, path length, and resolved asset names
- **`list_tools` MCP**: Now returns all 15 tools organized by category

### Documentation
- Updated README MCP section with complete tool table organized by category

## [0.1.4] - 2026-01-20
### Added
- **Cost-Aware Graph**: Added `CostEstimator` with static pricing for AWS resources (NAT, ALB, RDS, EBS, etc.)
- **ROI Prioritization**: Updated `cuts` command and `MinCutFinder` to prioritize remediations based on ROI (Security + Cost Savings)
- **MCP Enhancements**: Exposed `estimated_savings` and `roi_score` in `get_remediations` MCP tool
- **Verification Scripts**: Added `verify_phase2.py` for cost/ROI logic validation
- **Security Audit**: Completed adversarial audit (Phase 2.5) verifying input safety and resilience

### Fixed
- **Scanner UX**: Improved error handling for invalid AWS credentials (now raises friendly `ConnectionError` instead of crashing)
- **Relationship Regression**: Fixed issue where `MAY_ACCESS` edges (Role -> Sensitive Target) were not being created
- **Test Mocking**: Corrected mock patching for `AwsScanner` and `FileSystemStorage` in unit tests
- **Schema Validation**: Fixed `cuts` command JSON output schema to include cost fields

## [0.1.3] - 2026-01-19
### Fixed
- Report format inference now handles dotfile outputs (.json/.html) on Windows
- `can` JSON/agent output now validates with mode/disclaimer fields
- Live policy simulation now tests correct S3 bucket vs object ARNs for `ListBucket` and object actions
- Comply suggested actions now reference the first failing control

### Added
- `can` live proof now includes resources_tested for S3 actions

## [0.1.2] - 2026-01-19
### Fixed
- MCP GraphBuilder.build() calls now use keyword arguments (fixes get_unused_permissions, get_remediations, check_access crashes)
- Scan ID vs snapshot UUID mismatch: storage now accepts both scan_id and snapshot UUID via resolve_scan_id()
- CLI scan output now includes scan_id and suggested_actions use scan_id format
- Live mode for `can --live` and `waste --live` now works (added default_session() to CredentialProvider)
- Report command no longer emits invalid "format" field in JSON/agent output
- MCP tools now return SNAPSHOT_NOT_FOUND when no scan data is loaded (instead of misleading empty/perfect results)
- MCP list_tools now includes set_session_snapshot and list_tools itself
- Partial scan failures now surface as warnings in output and set status to completed_with_errors
- Remediate dry-run no longer prompts for confirmation and correctly reports status as "dry_run" with applied=false
- Diff --all now populates asset_changes and relationship_changes in JSON/agent output
- Comply suggested actions no longer reference "top failing control" when there are no failures

### Added
- `analyze stats --format` option for JSON/agent output consistency
- AnalyzeStatsResponse schema for structured stats output
- Manifest entries for: report, validate-role, setup iam, explain, analyze findings, analyze stats
- Snapshot.errors field and completed_with_errors status for partial scan failure tracking

### Changed
- Manifest scan command: role_arn no longer required, added profile and format parameters
- Manifest commands now include snapshot parameter where CLI supports it
- Manifest format enums now include "agent" where CLI supports it
- Manifest cuts/waste commands include cost-source parameter
- Manifest waste command includes max-roles parameter
- Manifest analyze paths includes min-risk and limit parameters

## [0.1.1] - 2026-01-18
### Fixed
- MCP SDK 1.25.0 compatibility: removed unsupported `version` argument from FastMCP
- MCP SDK compatibility: fixed `Console.print(file=...)` argument error in serve.py
- Updated MCP version constraint from `>=0.1.0` to `>=1.0.0`

### Changed
- Modernized type annotations (`List` → `list`, `Dict` → `dict`, `Optional[X]` → `X | None`)
- Formatted all code with `ruff format`

### Documentation
- Added MCP installation instructions (`pip install "cyntrisec[mcp]"`) to README
- Removed unimplemented `--http` option from MCP server docstring

## [0.1.0] - 2026-01-17
### Added
- Initial Cyntrisec CLI release for AWS scanning, analysis, and reporting.
- Attack path discovery, minimal cut remediation, and waste analysis commands.
- MCP server mode for agent integrations and deterministic JSON output.
- PyPI packaging metadata, license file, and this changelog.
