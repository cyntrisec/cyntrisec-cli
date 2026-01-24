---
name: aws-security-analysis
description: Analyze AWS infrastructure security using Cyntrisec MCP tools. Use when asked about AWS attack paths, security findings, IAM permissions, compliance status, or remediation recommendations. Guides tool selection and workflow patterns for comprehensive security assessments.
license: Apache-2.0
metadata:
  author: cyntrisec
  version: "0.1.7"
---

# AWS Security Analysis

This skill guides you through analyzing AWS infrastructure security using Cyntrisec MCP tools.

## Prerequisites

Before using any tool, ensure a scan exists:
- Call `get_scan_summary` first to verify scan data is available
- If you receive `SNAPSHOT_NOT_FOUND`, inform the user to run `cyntrisec scan` first

## Tool Selection Guide

### When User Asks About...

| User Question | Tool to Use |
|--------------|-------------|
| "What's in my AWS account?" | `get_scan_summary` → `get_assets` |
| "What are the security issues?" | `get_findings` (filter by severity if specified) |
| "Show me attack paths" | `get_attack_paths` |
| "Explain this attack path" | `explain_path` (requires path_id) |
| "How do I fix this?" | `get_remediations` → `get_terraform_snippet` |
| "Can role X access resource Y?" | `check_access` |
| "What permissions are unused?" | `get_unused_permissions` |
| "Are we compliant?" | `check_compliance` |
| "What changed since last scan?" | `compare_scans` |

### Tool Categories

**Discovery (start here)**
- `get_scan_summary` - Always call first to understand scope
- `list_tools` - Show available capabilities

**Data Retrieval**
- `get_assets` - Browse AWS resources (EC2, IAM, S3, RDS, Lambda)
- `get_relationships` - See how assets connect (CAN_ASSUME, CAN_REACH, MAY_ACCESS)
- `get_findings` - Security issues found in the scan

**Attack Analysis**
- `get_attack_paths` - Paths from internet to sensitive targets
- `explain_path` - Step-by-step breakdown of an attack path
- `explain_finding` - Deep dive into a specific finding

**Remediation**
- `get_remediations` - Optimal fixes using min-cut algorithm
- `get_terraform_snippet` - IaC code to implement a fix

**Advanced**
- `check_access` - Simulate IAM access decisions
- `get_unused_permissions` - Find permission bloat
- `check_compliance` - CIS AWS or SOC 2 frameworks

## Common Workflows

### Workflow 1: Security Assessment

User wants to understand their security posture.

```
1. get_scan_summary
   → Understand scope: account, regions, asset counts

2. get_findings(severity="CRITICAL")
   → Focus on highest priority issues first

3. get_attack_paths(min_risk=0.7)
   → Find high-risk paths to sensitive targets

4. explain_path(path_id=<from step 3>)
   → Understand the most critical path in detail
```

### Workflow 2: Remediation Planning

User wants to fix security issues efficiently.

```
1. get_attack_paths
   → See all attack paths

2. get_remediations(max_cuts=5)
   → Find minimal set of changes to block most paths

3. For each remediation:
   get_terraform_snippet(source, target, relationship_type)
   → Generate IaC code
```

### Workflow 3: Compliance Audit

User needs compliance status for audit.

```
1. check_compliance(framework="cis-aws")  # or "soc2"
   → Get compliance score and failing controls

2. get_findings(severity="HIGH")
   → Correlate findings with compliance gaps

3. get_remediations
   → Prioritize fixes by compliance impact
```

### Workflow 4: Access Investigation

User asks "Can X access Y?" or investigates lateral movement.

```
1. check_access(principal="RoleName", resource="s3://bucket-name")
   → Direct answer: yes/no with relationship type

2. If access exists, use:
   get_relationships(source_name="RoleName")
   → Understand the full access chain
```

### Workflow 5: Permission Optimization

User wants to reduce blast radius or clean up IAM.

```
1. get_unused_permissions(days_threshold=90)
   → Find stale permissions

2. get_assets(asset_type="iam:role")
   → List all roles for context

3. Present reduction opportunities by blast_radius_reduction score
```

### Workflow 6: Drift Detection

User wants to know what changed.

```
1. compare_scans
   → Shows new/removed assets, relationships, paths, findings

2. If regressions detected:
   get_attack_paths
   → Focus on new attack paths
```

## Best Practices

### Always Do

- **Start with `get_scan_summary`** - Establishes context and verifies data exists
- **Use severity filters** - Focus on CRITICAL/HIGH first: `get_findings(severity="CRITICAL")`
- **Use min_risk filter** - Focus on high-risk paths: `get_attack_paths(min_risk=0.7)`
- **Chain explain tools** - After listing, offer to explain specific items
- **Present ROI scores** - When showing remediations, highlight `roi_score` for prioritization

### Never Do

- **Skip the summary** - Always verify scan data exists first
- **Return raw IDs without context** - Always include names and descriptions
- **Overwhelm with data** - Use `max_*` parameters to limit results
- **Ignore error codes** - Handle `SNAPSHOT_NOT_FOUND` and `INSUFFICIENT_DATA` gracefully

### Response Patterns

When showing attack paths:
```
Found {total} attack paths. Top {n} by risk:

1. **{source_name} → {target_name}** (Risk: {risk_score})
   Vector: {attack_vector}
   Path: {path_assets joined by " → "}
```

When showing remediations:
```
Top remediation opportunities:

1. **Block {source} → {target}** ({relationship_type})
   - Blocks {paths_blocked} attack paths
   - Estimated savings: ${estimated_savings}
   - ROI Score: {roi_score}
```

## Troubleshooting

### No scan data found
```
Error: SNAPSHOT_NOT_FOUND
```
→ User needs to run `cyntrisec scan` with AWS credentials configured.

### Need multiple scans for comparison
```
Error: INSUFFICIENT_DATA
```
→ User needs at least 2 scans to use `compare_scans`.

### No attack paths found
This is good news! The infrastructure has no detected paths from internet-facing resources to sensitive targets.

### Empty findings
Either the infrastructure is well-configured, or the scan may need to cover more services/regions.

## Tool Parameter Reference

### Severity Values
`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`

### Asset Types
`iam:role`, `iam:user`, `iam:policy`, `ec2:instance`, `ec2:security-group`, `s3:bucket`, `rds:instance`, `lambda:function`

### Relationship Types
`CAN_ASSUME`, `CAN_REACH`, `MAY_ACCESS`, `ALLOWS_TRAFFIC_TO`, `HAS_POLICY`, `MEMBER_OF`

### Compliance Frameworks
`cis-aws`, `soc2`
