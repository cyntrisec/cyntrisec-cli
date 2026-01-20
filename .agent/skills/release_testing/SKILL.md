---
name: Release Testing
description: Test cyntrisec-cli before release (Lint, Types, Unit Tests, Live AWS, MCP, Regressions)
---

# Release Testing Skill

This skill guides you through the process of testing `cyntrisec-cli` before a release.
It includes static analysis, unit/integration tests, and live verification against AWS and MCP.

## Prerequisites

-   Active AWS credentials (profile or env vars) with read-only access to at least one region (e.g., `us-east-1`).
-   Python 3.11+ installed.

## 1. Environment Setup

Ensure your development environment is set up and dependencies are up to date.

```powershell
pip install -e .[dev,mcp]
```

## 2. Static Analysis

Run linting and type checking to catch static errors.

### Linting (Ruff)
```powershell
ruff check .
```

### Type Checking (MyPy)
```powershell
mypy src
```

## 3. Automated Tests

Run the standard test suite.

```powershell
pytest
```

## 4. Live Verification

These scripts perform live checks against your environment.

### AWS Integration
Verifies that `cyntrisec scan` works against a real AWS account.
*Requires AWS credentials.*

```powershell
python scripts/verify_aws.py
```

**Using a specific profile (Recommended):**
```powershell
python scripts/verify_aws.py --profile <your-profile-name>
```

> [!TIP]
> The `CyntriSecReadOnlyScannerRole` in `272493677165` is restricted to the `DevAdmin` user by default. Use a profile with these credentials (often `default`) to successfully verify the scan.

**Using a specific role:**
*Note: Ensure the target role's Trust Policy allows your identity to assume it.*
```powershell
python scripts/verify_aws.py --role-arn arn:aws:iam::123456789012:role/MyRole --external-id "See 1Password"
```

#### Role Configuration (Trust Policy)
If using `verify_aws.py` with a specific role, the role's **Trust Policy** must allow your identity.
Example Trust Policy to allow SSO users:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "REQUIRED_EXTERNAL_ID"
                }
            }
        }
    ]
}
```

### MCP Server
Verifies that the MCP server starts and tools are discoverable.

```powershell
python scripts/verify_mcp.py
```

### Issue Regression
Verifies fixes for reported bugs (v0.1.3 issues).

```powershell
python scripts/verify_issues.py
```


### Logic Verification
Verifies business logic correctness (e.g., Waste safety).

```powershell
python scripts/verify_logic.py
```

### Phase 1 & 2 Verification
Verifies Delta Logic (Attack vs Business) and Cost-Aware Graph (ROI Ranking).

```powershell
python scripts/verify_phase1.py
python scripts/verify_phase2.py
```

## 5. Build Verification

Verify that the package builds correctly.

```powershell
./scripts/build.ps1
```

## Checklist

- [ ] Linting passed (Ruff)
- [ ] Type checking passed (MyPy)
- [ ] Unit/Integration tests passed (Pytest)
- [ ] Live AWS scan succeeded (`verify_aws.py`)
- [ ] MCP server verified (`verify_mcp.py`)
- [ ] Regression tests passed (`verify_issues.py`)
- [ ] Logic checks passed (`verify_logic.py`)
- [ ] Phase 1 verified (`verify_phase1.py`)
- [ ] Phase 2 verified (`verify_phase2.py`)
- [ ] Build succeeded
