# Cyntrisec CLI

AWS capability graph analysis and attack path discovery.

A read-only CLI tool that:
- Scans AWS infrastructure via AssumeRole
- Builds a capability graph (IAM, network, dependencies)
- Discovers attack paths from internet to sensitive targets
- Identifies cost-cut candidates (unused capabilities)
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

# Option 3: Create a batch file cyntrisec.cmd in a folder on PATH:
# @echo off
# python -m cyntrisec %*
```

## Quick Start

```bash
# 1. Create the read-only IAM role in your account
cyntrisec setup iam 123456789012 --output role.tf

# 2. Apply the Terraform (or use CloudFormation)
cd your-infra && terraform apply

# 3. Run a scan
cyntrisec scan --role-arn arn:aws:iam::123456789012:role/CyntrisecReadOnly

# 4. View attack paths
cyntrisec analyze paths --min-risk 0.5

# 5. View cost-cut candidates
cyntrisec analyze waste --min-savings 100

# 6. Generate HTML report
cyntrisec report --output report.html
```

## Commands

| Command | Description |
|---------|-------------|
| `cyntrisec scan` | Run AWS scan |
| `cyntrisec analyze paths` | Show attack paths |
| `cyntrisec analyze waste` | Show cost-cut candidates |
| `cyntrisec cuts` | Show minimal graph cuts |
| `cyntrisec explain <id>` | Explain an asset's role |
| `cyntrisec report` | Generate HTML report |
| `cyntrisec setup iam` | Generate IAM policy/role |

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

### Required IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "CyntrisecReadOnly",
    "Effect": "Allow",
    "Action": [
      "ec2:Describe*",
      "iam:Get*",
      "iam:List*",
      "s3:GetBucketAcl",
      "s3:GetBucketPolicy",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:ListAllMyBuckets",
      "lambda:GetFunction",
      "lambda:GetFunctionConfiguration",
      "lambda:GetPolicy",
      "lambda:ListFunctions",
      "rds:Describe*",
      "elasticloadbalancing:Describe*",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

Generate with: `cyntrisec setup iam YOUR_ACCOUNT_ID`

## Output Format

Primary output is JSON to stdout, suitable for piping to `jq`:

```bash
cyntrisec analyze paths --format json | jq '.paths[] | select(.risk_score > 0.7)'
```

Human-readable table format:

```bash
cyntrisec analyze paths --format table
```

## Storage

Scan results are stored locally:

```
~/.cyntrisec/
├── scans/
│   ├── 2026-01-16_123456_123456789012/
│   │   ├── snapshot.json
│   │   ├── assets.json
│   │   ├── relationships.json
│   │   ├── findings.json
│   │   └── attack_paths.json
│   └── latest -> 2026-01-16_123456_123456789012
└── config.yaml
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no high-risk paths |
| 1 | High-risk attack paths found |
| 2 | Error during execution |

Use in CI/CD:

```bash
cyntrisec scan --role-arn $ROLE_ARN || exit 1
```

## License

MIT
