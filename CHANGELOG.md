# Changelog

All notable changes to this project will be documented in this file.
The format is based on Keep a Changelog, and this project adheres to
Semantic Versioning.

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
