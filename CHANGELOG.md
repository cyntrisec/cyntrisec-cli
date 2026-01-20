# Changelog

All notable changes to this project will be documented in this file.
The format is based on Keep a Changelog, and this project adheres to
Semantic Versioning.

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
