# Cyntrisec CLI

AWS capability graph analysis and attack path discovery.

A read-only CLI tool that:
- Scans AWS infrastructure via AssumeRole
- Builds a capability graph (IAM, network, dependencies)
- Discovers attack paths from internet to sensitive targets
- Identifies unused capabilities (blast radius reduction)
- Outputs deterministic JSON with proof chains

## Installation

```bash
pip install cyntrisec
```

### Windows PATH Fix

If you see "cyntrisec is not recognized", the Scripts folder isn't on PATH:

```powershell
# Option 1: Run with python -m
python -m cyntrisec --help

# Option 2: Add to PATH for current session
$env:PATH += ";$env:APPDATA\Python\Python311\Scripts"
```

## Quick Start

```bash
# 1. Create the read-only IAM role in your account
cyntrisec setup iam 123456789012 --output role.tf

# 2. Apply the Terraform
cd your-infra && terraform apply

# 3. Run a scan
cyntrisec scan --role-arn arn:aws:iam::123456789012:role/CyntrisecReadOnly

# 4. View attack paths
cyntrisec analyze paths --min-risk 0.5

# 5. Find minimal fixes
cyntrisec cuts --format json

# 6. Generate HTML report
cyntrisec report --output report.html
```

## Commands

### Core Analysis

| Command | Description |
|---------|-------------|
| `scan` | Scan AWS infrastructure |
| `analyze paths` | View attack paths |
| `analyze findings` | View security findings |
| `analyze business` | Business entrypoint analysis |
| `report` | Generate HTML/JSON report |

### Remediation

| Command | Description |
|---------|-------------|
| `cuts` | Find minimal fixes for attack paths |
| `waste` | Find unused IAM permissions |
| `remediate` | Generate Terraform remediation plan |

### Policy Testing

| Command | Description |
|---------|-------------|
| `can` | Test "can X access Y?" |
| `diff` | Compare scan snapshots |
| `comply` | Check CIS AWS / SOC2 compliance |

### Agentic Interface

| Command | Description |
|---------|-------------|
| `manifest` | Output machine-readable capabilities |
| `explain` | Natural language explanations |
| `ask` | Query scans in plain English |
| `serve` | Run as MCP server for AI agents |

## MCP Server Mode

Run Cyntrisec as an MCP server for AI agent integration:

```bash
cyntrisec serve              # Start stdio server
cyntrisec serve --list-tools # List available tools
```

**MCP Tools:** `get_scan_summary`, `get_attack_paths`, `get_remediations`, `check_access`, `get_unused_permissions`, `check_compliance`, `compare_scans`

### Claude Desktop Config

```json
{
  "mcpServers": {
    "cyntrisec": {
      "command": "python",
      "args": ["-m", "cyntrisec", "serve"]
    }
  }
}
```

## Trust & Safety

### Read-Only Guarantees

This tool makes **read-only API calls** to your AWS account. The IAM role
should have only `Describe*`, `Get*`, `List*` permissions.

### No Data Exfiltration

All data stays on your local machine. Nothing is sent to external servers.
Scan results are stored in `~/.cyntrisec/scans/`.

### No Auto-Remediation

The tool only analyzes. It never modifies your infrastructure.
All suggested actions are informational.

### Auditable

Every AWS API call is logged in CloudTrail under session name `cyntrisec-cli`.

## Output Format

Primary output is JSON to stdout. When stdout is not a TTY, the CLI automatically switches to JSON:

```bash
cyntrisec analyze paths --format json | jq '.paths[] | select(.risk_score > 0.7)'
```

Agent-friendly output wraps results in a structured envelope:

```bash
cyntrisec analyze paths --format agent
```

```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {...},
  "artifact_paths": {...},
  "suggested_actions": [...]
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / compliant |
| 1 | Findings / regressions / denied |
| 2 | Usage error |
| 3 | Transient error (retry) |
| 4 | Internal error |

Use in CI/CD:

```bash
cyntrisec scan --role-arn $ROLE_ARN || exit 1
cyntrisec diff || echo "Regressions detected"
```

## Storage

Scan results are stored locally:

```
~/.cyntrisec/
├── scans/
│   ├── 2026-01-17_123456_123456789012/
│   │   ├── snapshot.json
│   │   ├── assets.json
│   │   ├── relationships.json
│   │   ├── findings.json
│   │   └── attack_paths.json
│   └── latest -> 2026-01-17_...
└── config.yaml
```

## Versioning

This project follows Semantic Versioning. See `CHANGELOG.md` for release notes.

## License

MIT
