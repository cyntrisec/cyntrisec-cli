# Cyntrisec CLI - Demo Outputs

Generated: 2026-01-22 15:47:18.537479 UTC

This file is generated from synthetic demo data only.

## Command Outputs

### cyntrisec manifest
```bash
cyntrisec manifest --format agent
```
```
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "name": "cyntrisec",
    "version": "0.1.6",
    "description": "AWS capability graph analysis and attack path discovery",
    "capabilities": [
      {
        "name": "scan",
        "description": "Scan an AWS account for security issues and attack paths",
        "parameters": [
          {
            "name": "role_arn",
            "type": "string",
            "required": false,
            "description": "AWS IAM role ARN to assume for scanning (uses default credentials if not provided)"
          },
          {
            "name": "external_id",
            "type": "string",
            "required": false,
            "description": "External ID for role assumption"
          },
          {
            "name": "regions",
            "type": "array",
            "required": false,
            "default": [
              "us-east-1"
            ],
            "description": "AWS regions to scan"
          },
          {
            "name": "profile",
            "type": "string",
            "required": false,
            "description": "AWS CLI profile for base credentials"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "text",
            "enum": [
              "text",
              "json",
              "agent"
            ],
            "description": "Output format"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "scan_id": {
              "type": "string"
            },
            "snapshot_id": {
              "type": "string"
            },
            "account_id": {
              "type": "string"
            },
            "regions": {
              "type": "array"
            },
            "asset_count": {
              "type": "integer"
            },
            "relationship_count": {
              "type": "integer"
            },
            "finding_count": {
              "type": "integer"
            },
            "attack_path_count": {
              "type": "integer"
            },
            "warnings": {
              "type": "array"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "1": "scan completed with findings",
          "2": "error"
        },
        "example": "cyntrisec scan --role-arn arn:aws:iam::123:role/Scanner"
      },
      {
        "name": "cuts",
        "description": "Find minimal set of remediations that block all attack paths",
        "parameters": [
          {
            "name": "max_cuts",
            "type": "integer",
            "required": false,
            "default": 5,
            "description": "Maximum number of remediations to return"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "table",
            "enum": [
              "table",
              "json",
              "agent"
            ],
            "description": "Output format"
          },
          {
            "name": "snapshot",
            "type": "string",
            "required": false,
            "description": "Specific snapshot ID (default: latest)"
          },
          {
            "name": "cost_source",
            "type": "string",
            "required": false,
            "default": "estimate",
            "description": "Cost data source: estimate (static), pricing-api, cost-explorer"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "total_paths": {
              "type": "integer"
            },
            "paths_blocked": {
              "type": "integer"
            },
            "coverage": {
              "type": "number"
            },
            "remediations": {
              "type": "array"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "2": "error"
        },
        "example": "cyntrisec cuts --format json",
        "suggested_after": [
          "scan"
        ]
      },
      {
        "name": "waste",
        "description": "Analyze IAM roles for unused permissions (blast radius reduction)",
        "parameters": [
          {
            "name": "days",
            "type": "integer",
            "required": false,
            "default": 90,
            "description": "Days threshold for considering a permission unused"
          },
          {
            "name": "live",
            "type": "boolean",
            "required": false,
            "default": false,
            "description": "Fetch live usage data from AWS IAM Access Advisor"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "table",
            "enum": [
              "table",
              "json",
              "agent"
            ],
            "description": "Output format"
          },
          {
            "name": "snapshot",
            "type": "string",
            "required": false,
            "description": "Specific snapshot ID (default: latest)"
          },
          {
            "name": "cost_source",
            "type": "string",
            "required": false,
            "default": "estimate",
            "description": "Cost data source: estimate (static), pricing-api, cost-explorer"
          },
          {
            "name": "max_roles",
            "type": "integer",
            "required": false,
            "default": 20,
            "description": "Maximum number of roles to analyze (API throttling)"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "total_permissions": {
              "type": "integer"
            },
            "total_unused": {
              "type": "integer"
            },
            "blast_radius_reduction": {
              "type": "number"
            },
            "roles": {
              "type": "array"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "2": "error"
        },
        "example": "cyntrisec waste --live --format json",
        "suggested_after": [
          "scan"
        ]
      },
      {
        "name": "can",
        "description": "Test if a principal can access a resource (IAM policy simulation)",
        "parameters": [
          {
            "name": "principal",
            "type": "string",
            "required": true,
            "description": "IAM principal (role/user name or ARN)"
          },
          {
            "name": "access",
            "type": "string",
            "required": true,
            "const": "access",
            "description": "Literal 'access' keyword"
          },
          {
            "name": "resource",
            "type": "string",
            "required": true,
            "description": "Target resource (ARN, bucket name, or s3://path)"
          },
          {
            "name": "action",
            "type": "string",
            "required": false,
            "description": "Specific action to test (auto-detected if not provided)"
          },
          {
            "name": "live",
            "type": "boolean",
            "required": false,
            "default": false,
            "description": "Use AWS Policy Simulator API"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "text",
            "enum": [
              "text",
              "json",
              "agent"
            ],
            "description": "Output format"
          },
          {
            "name": "snapshot",
            "type": "string",
            "required": false,
            "description": "Specific snapshot ID (default: latest)"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "principal": {
              "type": "string"
            },
            "resource": {
              "type": "string"
            },
            "can_access": {
              "type": "boolean"
            },
            "simulations": {
              "type": "array"
            }
          }
        },
        "exit_codes": {
          "0": "access allowed",
          "1": "access denied",
          "2": "error"
        },
        "example": "cyntrisec can ECforS access s3://prod-bucket --format json",
        "suggested_after": [
          "scan",
          "cuts"
        ]
      },
      {
        "name": "diff",
        "description": "Compare two scan snapshots to detect changes and regressions",
        "parameters": [
          {
            "name": "old",
            "type": "string",
            "required": false,
            "description": "Old snapshot ID (default: second most recent)"
          },
          {
            "name": "new",
            "type": "string",
            "required": false,
            "description": "New snapshot ID (default: most recent)"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "table",
            "enum": [
              "table",
              "json",
              "agent"
            ],
            "description": "Output format"
          },
          {
            "name": "all",
            "type": "boolean",
            "required": false,
            "default": false,
            "description": "Show all changes including assets and relationships"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "has_regressions": {
              "type": "boolean"
            },
            "has_improvements": {
              "type": "boolean"
            },
            "summary": {
              "type": "object"
            },
            "path_changes": {
              "type": "array"
            }
          }
        },
        "exit_codes": {
          "0": "no regressions",
          "1": "regressions detected",
          "2": "error"
        },
        "example": "cyntrisec diff --format json",
        "suggested_after": [
          "scan"
        ]
      },
      {
        "name": "comply",
        "description": "Check compliance against CIS AWS Foundations or SOC 2",
        "parameters": [
          {
            "name": "framework",
            "type": "string",
            "required": false,
            "default": "cis-aws",
            "enum": [
              "cis-aws",
              "soc2"
            ],
            "description": "Compliance framework"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "table",
            "enum": [
              "table",
              "json",
              "agent"
            ],
            "description": "Output format"
          },
          {
            "name": "snapshot",
            "type": "string",
            "required": false,
            "description": "Specific snapshot ID (default: latest)"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "framework": {
              "type": "string"
            },
            "compliance_score": {
              "type": "number"
            },
            "passing": {
              "type": "integer"
            },
            "failing": {
              "type": "integer"
            },
            "controls": {
              "type": "array"
            }
          }
        },
        "exit_codes": {
          "0": "fully compliant",
          "1": "compliance failures",
          "2": "error"
        },
        "example": "cyntrisec comply --framework soc2 --format json",
        "suggested_after": [
          "scan"
        ]
      },
      {
        "name": "analyze paths",
        "description": "View discovered attack paths from the latest scan",
        "parameters": [
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "table",
            "enum": [
              "table",
              "json",
              "agent"
            ],
            "description": "Output format"
          },
          {
            "name": "scan",
            "type": "string",
            "required": false,
            "description": "Scan ID (default: latest)"
          },
          {
            "name": "min_risk",
            "type": "number",
            "required": false,
            "default": 0.0,
            "description": "Minimum risk score (0-1)"
          },
          {
            "name": "limit",
            "type": "integer",
            "required": false,
            "default": 20,
            "description": "Maximum number of paths to show"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "paths": {
              "type": "array"
            },
            "total": {
              "type": "integer"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "2": "error"
        },
        "example": "cyntrisec analyze paths --format json",
        "suggested_after": [
          "scan"
        ]
      },
      {
        "name": "analyze business",
        "description": "Map business entrypoints vs attackable assets (waste = attackable - business)",
        "parameters": [
          {
            "name": "entrypoints",
            "type": "array",
            "required": false,
            "description": "Business entrypoint names/ARNs (comma-separated)"
          },
          {
            "name": "business_entrypoint",
            "type": "array",
            "required": false,
            "description": "Repeatable business entrypoint flags (--business-entrypoint)"
          },
          {
            "name": "business_tags",
            "type": "object",
            "required": false,
            "description": "Tag filters marking business assets"
          },
          {
            "name": "business_config",
            "type": "string",
            "required": false,
            "description": "Path to business config (JSON/YAML)"
          },
          {
            "name": "report",
            "type": "boolean",
            "required": false,
            "default": false,
            "description": "Emit full coverage report"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "table",
            "enum": [
              "table",
              "json",
              "agent"
            ],
            "description": "Output format"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "entrypoints_found": {
              "type": "array"
            },
            "attackable_count": {
              "type": "integer"
            },
            "waste_candidate_count": {
              "type": "integer"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "2": "error"
        },
        "example": "cyntrisec analyze business --entrypoints web,api --format agent",
        "suggested_after": [
          "scan"
        ]
      },
      {
        "name": "remediate",
        "description": "Generate remediation plan or optionally execute Terraform (gated)",
        "parameters": [
          {
            "name": "max_cuts",
            "type": "integer",
            "required": false,
            "default": 5,
            "description": "Maximum remediations to include"
          },
          {
            "name": "apply",
            "type": "boolean",
            "required": false,
            "default": false,
            "description": "Write remediation plan to disk (safety stub)"
          },
          {
            "name": "dry_run",
            "type": "boolean",
            "required": false,
            "default": false,
            "description": "Simulate apply and write plan/IaC artifacts"
          },
          {
            "name": "execute_terraform",
            "type": "boolean",
            "required": false,
            "default": false,
            "description": "UNSAFE: execute terraform apply locally. Requires --enable-unsafe-write-mode."
          },
          {
            "name": "terraform_plan",
            "type": "boolean",
            "required": false,
            "default": false,
            "description": "Run terraform init/plan against generated module"
          },
          {
            "name": "terraform_output",
            "type": "string",
            "required": false,
            "description": "Terraform hints output path"
          },
          {
            "name": "enable_unsafe_write_mode",
            "type": "boolean",
            "required": false,
            "description": "Required to allow --apply/--execute-terraform (defaults to off for safety)"
          },
          {
            "name": "terraform_dir",
            "type": "string",
            "required": false,
            "description": "Directory to write Terraform module"
          },
          {
            "name": "output",
            "type": "string",
            "required": false,
            "description": "Output path for remediation plan"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "table",
            "enum": [
              "table",
              "json",
              "agent"
            ],
            "description": "Output format"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "plan": {
              "type": "array"
            },
            "coverage": {
              "type": "number"
            },
            "paths_blocked": {
              "type": "integer"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "2": "error"
        },
        "example": "cyntrisec remediate --format agent",
        "suggested_after": [
          "cuts",
          "analyze paths"
        ]
      },
      {
        "name": "ask",
        "description": "Natural language interface to query scan results",
        "parameters": [
          {
            "name": "query",
            "type": "string",
            "required": true,
            "description": "NL question"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "text",
            "enum": [
              "text",
              "json",
              "agent"
            ],
            "description": "Output format"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "intent": {
              "type": "string"
            },
            "results": {
              "type": "object"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "2": "error"
        },
        "example": "cyntrisec ask \"what can reach the production database?\" --format agent",
        "suggested_after": [
          "scan",
          "analyze paths"
        ]
      },
      {
        "name": "report",
        "description": "Generate HTML or JSON report from scan results",
        "parameters": [
          {
            "name": "scan",
            "type": "string",
            "required": false,
            "description": "Scan ID (default: latest)"
          },
          {
            "name": "output",
            "type": "string",
            "required": false,
            "default": "cyntrisec-report.html",
            "description": "Output file path"
          },
          {
            "name": "title",
            "type": "string",
            "required": false,
            "description": "Report title"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "html",
            "enum": [
              "html",
              "json",
              "agent"
            ],
            "description": "Output format"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "snapshot_id": {
              "type": "string"
            },
            "account_id": {
              "type": "string"
            },
            "output_path": {
              "type": "string"
            },
            "findings": {
              "type": "integer"
            },
            "paths": {
              "type": "integer"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "2": "error"
        },
        "example": "cyntrisec report --output report.html",
        "suggested_after": [
          "scan"
        ]
      },
      {
        "name": "validate-role",
        "description": "Validate that an IAM role can be assumed",
        "parameters": [
          {
            "name": "role_arn",
            "type": "string",
            "required": true,
            "description": "IAM role ARN to validate"
          },
          {
            "name": "external_id",
            "type": "string",
            "required": false,
            "description": "External ID for role assumption"
          },
          {
            "name": "profile",
            "type": "string",
            "required": false,
            "description": "AWS CLI profile for base credentials"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "text",
            "enum": [
              "text",
              "json",
              "agent"
            ],
            "description": "Output format"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "success": {
              "type": "boolean"
            },
            "role_arn": {
              "type": "string"
            },
            "account": {
              "type": "string"
            },
            "arn": {
              "type": "string"
            },
            "user_id": {
              "type": "string"
            }
          }
        },
        "exit_codes": {
          "0": "role valid",
          "1": "role invalid",
          "2": "error"
        },
        "example": "cyntrisec validate-role --role-arn arn:aws:iam::123:role/Scanner"
      },
      {
        "name": "setup iam",
        "description": "Generate IAM role template for Cyntrisec scanning",
        "parameters": [
          {
            "name": "account_id",
            "type": "string",
            "required": true,
            "description": "AWS account ID (12 digits)"
          },
          {
            "name": "role_name",
            "type": "string",
            "required": false,
            "default": "CyntrisecReadOnly",
            "description": "Name for the IAM role"
          },
          {
            "name": "external_id",
            "type": "string",
            "required": false,
            "description": "External ID for extra security"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "terraform",
            "enum": [
              "terraform",
              "cloudformation",
              "policy"
            ],
            "description": "Template format"
          },
          {
            "name": "output",
            "type": "string",
            "required": false,
            "description": "Output file path"
          },
          {
            "name": "output_format",
            "type": "string",
            "required": false,
            "default": "text",
            "enum": [
              "text",
              "json",
              "agent"
            ],
            "description": "Render format for CLI output"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "account_id": {
              "type": "string"
            },
            "role_name": {
              "type": "string"
            },
            "external_id": {
              "type": "string"
            },
            "template_format": {
              "type": "string"
            },
            "template": {
              "type": "string"
            },
            "output_path": {
              "type": "string"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "2": "error"
        },
        "example": "cyntrisec setup iam 123456789012 --output role.tf"
      },
      {
        "name": "explain",
        "description": "Get natural language explanation of paths, controls, or findings",
        "parameters": [
          {
            "name": "category",
            "type": "string",
            "required": true,
            "enum": [
              "finding",
              "path",
              "control"
            ],
            "description": "Category to explain: finding, path, control"
          },
          {
            "name": "identifier",
            "type": "string",
            "required": true,
            "description": "Identifier of the item to explain"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "text",
            "enum": [
              "text",
              "json",
              "markdown",
              "agent"
            ],
            "description": "Output format"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "type": {
              "type": "string"
            },
            "id": {
              "type": "string"
            },
            "explanation": {
              "type": "object"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "2": "error"
        },
        "example": "cyntrisec explain finding security_group_open_to_world --format agent"
      },
      {
        "name": "analyze findings",
        "description": "View security findings from the latest scan",
        "parameters": [
          {
            "name": "scan",
            "type": "string",
            "required": false,
            "description": "Scan ID (default: latest)"
          },
          {
            "name": "severity",
            "type": "string",
            "required": false,
            "enum": [
              "critical",
              "high",
              "medium",
              "low",
              "info"
            ],
            "description": "Filter by severity"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "table",
            "enum": [
              "table",
              "json",
              "agent"
            ],
            "description": "Output format"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "findings": {
              "type": "array"
            },
            "total": {
              "type": "integer"
            },
            "filter": {
              "type": "string"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "2": "error"
        },
        "example": "cyntrisec analyze findings --severity high --format json",
        "suggested_after": [
          "scan"
        ]
      },
      {
        "name": "analyze stats",
        "description": "View summary statistics from the latest scan",
        "parameters": [
          {
            "name": "scan",
            "type": "string",
            "required": false,
            "description": "Scan ID (default: latest)"
          },
          {
            "name": "format",
            "type": "string",
            "required": false,
            "default": "text",
            "enum": [
              "text",
              "json",
              "agent"
            ],
            "description": "Output format"
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "snapshot_id": {
              "type": "string"
            },
            "scan_id": {
              "type": "string"
            },
            "account_id": {
              "type": "string"
            },
            "asset_count": {
              "type": "integer"
            },
            "relationship_count": {
              "type": "integer"
            },
            "finding_count": {
              "type": "integer"
            },
            "path_count": {
              "type": "integer"
            },
            "regions": {
              "type": "array"
            },
            "status": {
              "type": "string"
            }
          }
        },
        "exit_codes": {
          "0": "success",
          "2": "error"
        },
        "example": "cyntrisec analyze stats --format json",
        "suggested_after": [
          "scan"
        ]
      }
    ],
    "schemas": {
      "version": "1.0",
      "base_url": "https://cyntrisec.dev/schemas/cli",
      "responses": {
        "scan": {
          "additionalProperties": false,
          "properties": {
            "scan_id": {
              "title": "Scan Id",
              "type": "string"
            },
            "snapshot_id": {
              "title": "Snapshot Id",
              "type": "string"
            },
            "status": {
              "title": "Status",
              "type": "string"
            },
            "account_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Account Id"
            },
            "regions": {
              "items": {
                "type": "string"
              },
              "title": "Regions",
              "type": "array"
            },
            "asset_count": {
              "title": "Asset Count",
              "type": "integer"
            },
            "relationship_count": {
              "title": "Relationship Count",
              "type": "integer"
            },
            "finding_count": {
              "title": "Finding Count",
              "type": "integer"
            },
            "attack_path_count": {
              "title": "Attack Path Count",
              "type": "integer"
            },
            "warnings": {
              "anyOf": [
                {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Warnings"
            }
          },
          "required": [
            "scan_id",
            "snapshot_id",
            "status",
            "regions",
            "asset_count",
            "relationship_count",
            "finding_count",
            "attack_path_count"
          ],
          "title": "ScanResponse",
          "type": "object"
        },
        "analyze_paths": {
          "$defs": {
            "AttackPathOut": {
              "additionalProperties": true,
              "properties": {
                "id": {
                  "title": "Id",
                  "type": "string"
                },
                "snapshot_id": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Snapshot Id"
                },
                "source_asset_id": {
                  "title": "Source Asset Id",
                  "type": "string"
                },
                "target_asset_id": {
                  "title": "Target Asset Id",
                  "type": "string"
                },
                "path_asset_ids": {
                  "items": {
                    "type": "string"
                  },
                  "title": "Path Asset Ids",
                  "type": "array"
                },
                "path_relationship_ids": {
                  "items": {
                    "type": "string"
                  },
                  "title": "Path Relationship Ids",
                  "type": "array"
                },
                "attack_vector": {
                  "title": "Attack Vector",
                  "type": "string"
                },
                "path_length": {
                  "title": "Path Length",
                  "type": "integer"
                },
                "entry_confidence": {
                  "title": "Entry Confidence",
                  "type": "number"
                },
                "exploitability_score": {
                  "title": "Exploitability Score",
                  "type": "number"
                },
                "impact_score": {
                  "title": "Impact Score",
                  "type": "number"
                },
                "risk_score": {
                  "title": "Risk Score",
                  "type": "number"
                },
                "confidence_level": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Confidence Level"
                },
                "confidence_reason": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Confidence Reason"
                },
                "attack_chain_relationship_ids": {
                  "anyOf": [
                    {
                      "items": {
                        "type": "string"
                      },
                      "type": "array"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Attack Chain Relationship Ids"
                },
                "context_relationship_ids": {
                  "anyOf": [
                    {
                      "items": {
                        "type": "string"
                      },
                      "type": "array"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Context Relationship Ids"
                },
                "proof": {
                  "additionalProperties": true,
                  "title": "Proof",
                  "type": "object"
                }
              },
              "required": [
                "id",
                "source_asset_id",
                "target_asset_id",
                "path_asset_ids",
                "path_relationship_ids",
                "attack_vector",
                "path_length",
                "entry_confidence",
                "exploitability_score",
                "impact_score",
                "risk_score"
              ],
              "title": "AttackPathOut",
              "type": "object"
            }
          },
          "additionalProperties": false,
          "properties": {
            "paths": {
              "items": {
                "$ref": "#/$defs/AttackPathOut"
              },
              "title": "Paths",
              "type": "array"
            },
            "returned": {
              "title": "Returned",
              "type": "integer"
            },
            "total": {
              "title": "Total",
              "type": "integer"
            }
          },
          "required": [
            "paths",
            "returned",
            "total"
          ],
          "title": "AnalyzePathsResponse",
          "type": "object"
        },
        "analyze_findings": {
          "$defs": {
            "FindingOut": {
              "additionalProperties": true,
              "properties": {
                "id": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Id"
                },
                "snapshot_id": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Snapshot Id"
                },
                "asset_id": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Asset Id"
                },
                "finding_type": {
                  "title": "Finding Type",
                  "type": "string"
                },
                "severity": {
                  "title": "Severity",
                  "type": "string"
                },
                "title": {
                  "title": "Title",
                  "type": "string"
                },
                "description": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Description"
                },
                "remediation": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Remediation"
                },
                "evidence": {
                  "additionalProperties": true,
                  "title": "Evidence",
                  "type": "object"
                }
              },
              "required": [
                "finding_type",
                "severity",
                "title"
              ],
              "title": "FindingOut",
              "type": "object"
            }
          },
          "additionalProperties": false,
          "properties": {
            "findings": {
              "items": {
                "$ref": "#/$defs/FindingOut"
              },
              "title": "Findings",
              "type": "array"
            },
            "total": {
              "title": "Total",
              "type": "integer"
            },
            "filter": {
              "title": "Filter",
              "type": "string"
            }
          },
          "required": [
            "findings",
            "total",
            "filter"
          ],
          "title": "AnalyzeFindingsResponse",
          "type": "object"
        },
        "analyze_stats": {
          "additionalProperties": false,
          "properties": {
            "snapshot_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Snapshot Id"
            },
            "scan_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Scan Id"
            },
            "account_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Account Id"
            },
            "asset_count": {
              "title": "Asset Count",
              "type": "integer"
            },
            "relationship_count": {
              "title": "Relationship Count",
              "type": "integer"
            },
            "finding_count": {
              "title": "Finding Count",
              "type": "integer"
            },
            "path_count": {
              "title": "Path Count",
              "type": "integer"
            },
            "regions": {
              "items": {
                "type": "string"
              },
              "title": "Regions",
              "type": "array"
            },
            "status": {
              "title": "Status",
              "type": "string"
            }
          },
          "required": [
            "asset_count",
            "relationship_count",
            "finding_count",
            "path_count",
            "regions",
            "status"
          ],
          "title": "AnalyzeStatsResponse",
          "type": "object"
        },
        "analyze_business": {
          "$defs": {
            "BusinessAsset": {
              "additionalProperties": false,
              "properties": {
                "name": {
                  "title": "Name",
                  "type": "string"
                },
                "asset_type": {
                  "title": "Asset Type",
                  "type": "string"
                },
                "reason": {
                  "title": "Reason",
                  "type": "string"
                },
                "asset_id": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Asset Id"
                },
                "tags": {
                  "additionalProperties": {
                    "type": "string"
                  },
                  "title": "Tags",
                  "type": "object"
                }
              },
              "required": [
                "name",
                "asset_type",
                "reason"
              ],
              "title": "BusinessAsset",
              "type": "object"
            },
            "WasteCandidate": {
              "additionalProperties": false,
              "properties": {
                "name": {
                  "title": "Name",
                  "type": "string"
                },
                "asset_type": {
                  "title": "Asset Type",
                  "type": "string"
                },
                "reason": {
                  "title": "Reason",
                  "type": "string"
                },
                "asset_id": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Asset Id"
                },
                "monthly_cost_usd": {
                  "anyOf": [
                    {
                      "type": "number"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Monthly Cost Usd"
                }
              },
              "required": [
                "name",
                "asset_type",
                "reason"
              ],
              "title": "WasteCandidate",
              "type": "object"
            }
          },
          "additionalProperties": false,
          "properties": {
            "entrypoints_requested": {
              "items": {
                "type": "string"
              },
              "title": "Entrypoints Requested",
              "type": "array"
            },
            "entrypoints_found": {
              "items": {
                "type": "string"
              },
              "title": "Entrypoints Found",
              "type": "array"
            },
            "attackable_count": {
              "title": "Attackable Count",
              "type": "integer"
            },
            "business_required_count": {
              "title": "Business Required Count",
              "type": "integer"
            },
            "waste_candidate_count": {
              "title": "Waste Candidate Count",
              "type": "integer"
            },
            "waste_candidates": {
              "items": {
                "$ref": "#/$defs/WasteCandidate"
              },
              "title": "Waste Candidates",
              "type": "array"
            },
            "business_assets": {
              "anyOf": [
                {
                  "items": {
                    "$ref": "#/$defs/BusinessAsset"
                  },
                  "type": "array"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Business Assets"
            },
            "unknown_assets": {
              "anyOf": [
                {
                  "items": {
                    "$ref": "#/$defs/BusinessAsset"
                  },
                  "type": "array"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Unknown Assets"
            }
          },
          "required": [
            "entrypoints_requested",
            "entrypoints_found",
            "attackable_count",
            "business_required_count",
            "waste_candidate_count",
            "waste_candidates"
          ],
          "title": "BusinessAnalysisResponse",
          "type": "object"
        },
        "cuts": {
          "$defs": {
            "CutRemediation": {
              "additionalProperties": false,
              "properties": {
                "priority": {
                  "title": "Priority",
                  "type": "integer"
                },
                "action": {
                  "title": "Action",
                  "type": "string"
                },
                "description": {
                  "title": "Description",
                  "type": "string"
                },
                "relationship_type": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Relationship Type"
                },
                "source": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Source"
                },
                "target": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Target"
                },
                "paths_blocked": {
                  "title": "Paths Blocked",
                  "type": "integer"
                },
                "path_ids": {
                  "items": {
                    "type": "string"
                  },
                  "title": "Path Ids",
                  "type": "array"
                },
                "estimated_monthly_savings": {
                  "anyOf": [
                    {
                      "type": "number"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Estimated Monthly Savings"
                },
                "cost_source": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Cost Source"
                },
                "cost_confidence": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Cost Confidence"
                },
                "cost_assumptions": {
                  "anyOf": [
                    {
                      "items": {
                        "type": "string"
                      },
                      "type": "array"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Cost Assumptions"
                }
              },
              "required": [
                "priority",
                "action",
                "description",
                "paths_blocked"
              ],
              "title": "CutRemediation",
              "type": "object"
            }
          },
          "additionalProperties": false,
          "properties": {
            "snapshot_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Snapshot Id"
            },
            "account_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Account Id"
            },
            "total_paths": {
              "title": "Total Paths",
              "type": "integer"
            },
            "paths_blocked": {
              "title": "Paths Blocked",
              "type": "integer"
            },
            "coverage": {
              "title": "Coverage",
              "type": "number"
            },
            "remediations": {
              "items": {
                "$ref": "#/$defs/CutRemediation"
              },
              "title": "Remediations",
              "type": "array"
            }
          },
          "required": [
            "total_paths",
            "paths_blocked",
            "coverage",
            "remediations"
          ],
          "title": "CutsResponse",
          "type": "object"
        },
        "waste": {
          "$defs": {
            "WasteCapability": {
              "additionalProperties": false,
              "properties": {
                "service": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Service"
                },
                "service_name": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Service Name"
                },
                "days_unused": {
                  "anyOf": [
                    {
                      "type": "integer"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Days Unused"
                },
                "risk_level": {
                  "title": "Risk Level",
                  "type": "string"
                },
                "recommendation": {
                  "title": "Recommendation",
                  "type": "string"
                },
                "monthly_cost_usd_estimate": {
                  "anyOf": [
                    {
                      "type": "number"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Monthly Cost Usd Estimate"
                },
                "cost_source": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Cost Source"
                },
                "confidence": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Confidence"
                },
                "assumptions": {
                  "anyOf": [
                    {
                      "items": {
                        "type": "string"
                      },
                      "type": "array"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Assumptions"
                }
              },
              "required": [
                "risk_level",
                "recommendation"
              ],
              "title": "WasteCapability",
              "type": "object"
            },
            "WasteRoleReport": {
              "additionalProperties": false,
              "properties": {
                "role_arn": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Role Arn"
                },
                "role_name": {
                  "title": "Role Name",
                  "type": "string"
                },
                "total_services": {
                  "title": "Total Services",
                  "type": "integer"
                },
                "unused_services": {
                  "title": "Unused Services",
                  "type": "integer"
                },
                "reduction": {
                  "title": "Reduction",
                  "type": "number"
                },
                "unused_capabilities": {
                  "items": {
                    "$ref": "#/$defs/WasteCapability"
                  },
                  "title": "Unused Capabilities",
                  "type": "array"
                }
              },
              "required": [
                "role_name",
                "total_services",
                "unused_services",
                "reduction",
                "unused_capabilities"
              ],
              "title": "WasteRoleReport",
              "type": "object"
            }
          },
          "additionalProperties": false,
          "properties": {
            "snapshot_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Snapshot Id"
            },
            "account_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Account Id"
            },
            "days_threshold": {
              "title": "Days Threshold",
              "type": "integer"
            },
            "total_permissions": {
              "title": "Total Permissions",
              "type": "integer"
            },
            "total_unused": {
              "title": "Total Unused",
              "type": "integer"
            },
            "blast_radius_reduction": {
              "title": "Blast Radius Reduction",
              "type": "number"
            },
            "roles": {
              "items": {
                "$ref": "#/$defs/WasteRoleReport"
              },
              "title": "Roles",
              "type": "array"
            }
          },
          "required": [
            "days_threshold",
            "total_permissions",
            "total_unused",
            "blast_radius_reduction",
            "roles"
          ],
          "title": "WasteResponse",
          "type": "object"
        },
        "can": {
          "$defs": {
            "CanSimulation": {
              "additionalProperties": false,
              "properties": {
                "action": {
                  "title": "Action",
                  "type": "string"
                },
                "resource": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Resource"
                },
                "decision": {
                  "title": "Decision",
                  "type": "string"
                },
                "matched_statements": {
                  "title": "Matched Statements",
                  "type": "integer"
                }
              },
              "required": [
                "action",
                "decision",
                "matched_statements"
              ],
              "title": "CanSimulation",
              "type": "object"
            }
          },
          "additionalProperties": false,
          "properties": {
            "snapshot_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Snapshot Id"
            },
            "principal": {
              "title": "Principal",
              "type": "string"
            },
            "resource": {
              "title": "Resource",
              "type": "string"
            },
            "action": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Action"
            },
            "can_access": {
              "title": "Can Access",
              "type": "boolean"
            },
            "simulations": {
              "items": {
                "$ref": "#/$defs/CanSimulation"
              },
              "title": "Simulations",
              "type": "array"
            },
            "proof": {
              "additionalProperties": true,
              "title": "Proof",
              "type": "object"
            },
            "mode": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Mode"
            },
            "disclaimer": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Disclaimer"
            }
          },
          "required": [
            "principal",
            "resource",
            "can_access",
            "simulations"
          ],
          "title": "CanResponse",
          "type": "object"
        },
        "diff": {
          "$defs": {
            "DiffChange": {
              "additionalProperties": true,
              "properties": {
                "change_type": {
                  "title": "Change Type",
                  "type": "string"
                },
                "path_id": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Path Id"
                },
                "detail": {
                  "additionalProperties": true,
                  "title": "Detail",
                  "type": "object"
                }
              },
              "required": [
                "change_type"
              ],
              "title": "DiffChange",
              "type": "object"
            }
          },
          "additionalProperties": true,
          "properties": {
            "has_regressions": {
              "title": "Has Regressions",
              "type": "boolean"
            },
            "has_improvements": {
              "title": "Has Improvements",
              "type": "boolean"
            },
            "summary": {
              "additionalProperties": true,
              "title": "Summary",
              "type": "object"
            },
            "path_changes": {
              "items": {
                "$ref": "#/$defs/DiffChange"
              },
              "title": "Path Changes",
              "type": "array"
            },
            "old_snapshot": {
              "anyOf": [
                {
                  "additionalProperties": true,
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Old Snapshot"
            },
            "new_snapshot": {
              "anyOf": [
                {
                  "additionalProperties": true,
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "New Snapshot"
            },
            "finding_changes": {
              "anyOf": [
                {
                  "items": {
                    "additionalProperties": true,
                    "type": "object"
                  },
                  "type": "array"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Finding Changes"
            },
            "asset_changes": {
              "anyOf": [
                {
                  "items": {
                    "additionalProperties": true,
                    "type": "object"
                  },
                  "type": "array"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Asset Changes"
            },
            "relationship_changes": {
              "anyOf": [
                {
                  "items": {
                    "additionalProperties": true,
                    "type": "object"
                  },
                  "type": "array"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Relationship Changes"
            }
          },
          "required": [
            "has_regressions",
            "has_improvements",
            "summary",
            "path_changes"
          ],
          "title": "DiffResponse",
          "type": "object"
        },
        "comply": {
          "$defs": {
            "ControlResult": {
              "additionalProperties": false,
              "properties": {
                "id": {
                  "title": "Id",
                  "type": "string"
                },
                "title": {
                  "title": "Title",
                  "type": "string"
                },
                "status": {
                  "title": "Status",
                  "type": "string"
                },
                "severity": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Severity"
                },
                "description": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Description"
                }
              },
              "required": [
                "id",
                "title",
                "status"
              ],
              "title": "ControlResult",
              "type": "object"
            },
            "DataGap": {
              "additionalProperties": false,
              "properties": {
                "control_id": {
                  "title": "Control Id",
                  "type": "string"
                },
                "reason": {
                  "title": "Reason",
                  "type": "string"
                },
                "required_assets": {
                  "anyOf": [
                    {
                      "items": {
                        "type": "string"
                      },
                      "type": "array"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Required Assets"
                },
                "services": {
                  "anyOf": [
                    {
                      "items": {
                        "type": "string"
                      },
                      "type": "array"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Services"
                }
              },
              "required": [
                "control_id",
                "reason"
              ],
              "title": "DataGap",
              "type": "object"
            }
          },
          "additionalProperties": false,
          "properties": {
            "framework": {
              "title": "Framework",
              "type": "string"
            },
            "compliance_score": {
              "title": "Compliance Score",
              "type": "number"
            },
            "passing": {
              "title": "Passing",
              "type": "integer"
            },
            "failing": {
              "title": "Failing",
              "type": "integer"
            },
            "controls": {
              "items": {
                "$ref": "#/$defs/ControlResult"
              },
              "title": "Controls",
              "type": "array"
            },
            "data_gaps": {
              "anyOf": [
                {
                  "items": {
                    "$ref": "#/$defs/DataGap"
                  },
                  "type": "array"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Data Gaps"
            }
          },
          "required": [
            "framework",
            "compliance_score",
            "passing",
            "failing",
            "controls"
          ],
          "title": "ComplyResponse",
          "type": "object"
        },
        "report": {
          "additionalProperties": false,
          "properties": {
            "output_path": {
              "title": "Output Path",
              "type": "string"
            },
            "snapshot_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Snapshot Id"
            },
            "account_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Account Id"
            },
            "findings": {
              "title": "Findings",
              "type": "integer"
            },
            "paths": {
              "title": "Paths",
              "type": "integer"
            }
          },
          "required": [
            "output_path",
            "findings",
            "paths"
          ],
          "title": "ReportResponse",
          "type": "object"
        },
        "manifest": {
          "additionalProperties": true,
          "properties": {
            "name": {
              "title": "Name",
              "type": "string"
            },
            "version": {
              "title": "Version",
              "type": "string"
            },
            "description": {
              "title": "Description",
              "type": "string"
            },
            "capabilities": {
              "items": {
                "additionalProperties": true,
                "type": "object"
              },
              "title": "Capabilities",
              "type": "array"
            },
            "schemas": {
              "additionalProperties": true,
              "title": "Schemas",
              "type": "object"
            },
            "agentic_features": {
              "additionalProperties": true,
              "title": "Agentic Features",
              "type": "object"
            },
            "usage_pattern": {
              "items": {
                "type": "string"
              },
              "title": "Usage Pattern",
              "type": "array"
            }
          },
          "required": [
            "name",
            "version",
            "description",
            "capabilities",
            "schemas",
            "agentic_features",
            "usage_pattern"
          ],
          "title": "ManifestResponse",
          "type": "object"
        },
        "remediate": {
          "$defs": {
            "RemediateApplyResult": {
              "additionalProperties": false,
              "properties": {
                "mode": {
                  "title": "Mode",
                  "type": "string"
                },
                "output_path": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Output Path"
                },
                "terraform_path": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Terraform Path"
                },
                "terraform_dir": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Terraform Dir"
                },
                "plan_exit_code": {
                  "anyOf": [
                    {
                      "type": "integer"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Plan Exit Code"
                },
                "plan_summary": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Plan Summary"
                },
                "results": {
                  "anyOf": [
                    {
                      "items": {
                        "$ref": "#/$defs/RemediationItem"
                      },
                      "type": "array"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Results"
                }
              },
              "required": [
                "mode"
              ],
              "title": "RemediateApplyResult",
              "type": "object"
            },
            "RemediationItem": {
              "additionalProperties": false,
              "properties": {
                "priority": {
                  "title": "Priority",
                  "type": "integer"
                },
                "action": {
                  "title": "Action",
                  "type": "string"
                },
                "description": {
                  "title": "Description",
                  "type": "string"
                },
                "source": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Source"
                },
                "target": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Target"
                },
                "relationship_type": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Relationship Type"
                },
                "paths_blocked": {
                  "title": "Paths Blocked",
                  "type": "integer"
                },
                "terraform": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Terraform"
                },
                "status": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Status"
                },
                "terraform_path": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Terraform Path"
                },
                "terraform_result": {
                  "anyOf": [
                    {
                      "additionalProperties": true,
                      "type": "object"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null,
                  "title": "Terraform Result"
                }
              },
              "required": [
                "priority",
                "action",
                "description",
                "paths_blocked"
              ],
              "title": "RemediationItem",
              "type": "object"
            }
          },
          "additionalProperties": false,
          "properties": {
            "snapshot_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Snapshot Id"
            },
            "account_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Account Id"
            },
            "total_paths": {
              "title": "Total Paths",
              "type": "integer"
            },
            "paths_blocked": {
              "title": "Paths Blocked",
              "type": "integer"
            },
            "coverage": {
              "title": "Coverage",
              "type": "number"
            },
            "plan": {
              "items": {
                "$ref": "#/$defs/RemediationItem"
              },
              "title": "Plan",
              "type": "array"
            },
            "applied": {
              "title": "Applied",
              "type": "boolean"
            },
            "mode": {
              "title": "Mode",
              "type": "string"
            },
            "output_path": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Output Path"
            },
            "terraform_path": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Terraform Path"
            },
            "terraform_dir": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Terraform Dir"
            },
            "apply": {
              "anyOf": [
                {
                  "$ref": "#/$defs/RemediateApplyResult"
                },
                {
                  "type": "null"
                }
              ],
              "default": null
            }
          },
          "required": [
            "total_paths",
            "paths_blocked",
            "coverage",
            "plan",
            "applied",
            "mode"
          ],
          "title": "RemediateResponse",
          "type": "object"
        },
        "ask": {
          "additionalProperties": false,
          "properties": {
            "query": {
              "title": "Query",
              "type": "string"
            },
            "intent": {
              "title": "Intent",
              "type": "string"
            },
            "results": {
              "additionalProperties": true,
              "title": "Results",
              "type": "object"
            },
            "snapshot_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Snapshot Id"
            },
            "entities": {
              "additionalProperties": true,
              "title": "Entities",
              "type": "object"
            },
            "resolved": {
              "title": "Resolved",
              "type": "string"
            }
          },
          "required": [
            "query",
            "intent",
            "results",
            "entities",
            "resolved"
          ],
          "title": "AskResponse",
          "type": "object"
        },
        "explain": {
          "additionalProperties": false,
          "properties": {
            "type": {
              "title": "Type",
              "type": "string"
            },
            "id": {
              "title": "Id",
              "type": "string"
            },
            "explanation": {
              "additionalProperties": true,
              "title": "Explanation",
              "type": "object"
            }
          },
          "required": [
            "type",
            "id",
            "explanation"
          ],
          "title": "ExplainResponse",
          "type": "object"
        },
        "setup_iam": {
          "additionalProperties": false,
          "properties": {
            "account_id": {
              "title": "Account Id",
              "type": "string"
            },
            "role_name": {
              "title": "Role Name",
              "type": "string"
            },
            "external_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "External Id"
            },
            "template_format": {
              "title": "Template Format",
              "type": "string"
            },
            "template": {
              "title": "Template",
              "type": "string"
            },
            "output_path": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Output Path"
            }
          },
          "required": [
            "account_id",
            "role_name",
            "template_format",
            "template"
          ],
          "title": "SetupIamResponse",
          "type": "object"
        },
        "validate_role": {
          "additionalProperties": false,
          "properties": {
            "success": {
              "title": "Success",
              "type": "boolean"
            },
            "role_arn": {
              "title": "Role Arn",
              "type": "string"
            },
            "account": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Account"
            },
            "arn": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Arn"
            },
            "user_id": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "User Id"
            },
            "error": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Error"
            },
            "error_type": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null,
              "title": "Error Type"
            }
          },
          "required": [
            "success",
            "role_arn"
          ],
          "title": "ValidateRoleResponse",
          "type": "object"
        },
        "serve_tools": {
          "additionalProperties": false,
          "properties": {
            "tools": {
              "items": {
                "additionalProperties": true,
                "type": "object"
              },
              "title": "Tools",
              "type": "array"
            }
          },
          "required": [
            "tools"
          ],
          "title": "ServeToolsResponse",
          "type": "object"
        }
      }
    },
    "agentic_features": {
      "json_output": true,
      "structured_errors": true,
      "exit_codes": true,
      "suggested_actions": true,
      "artifact_paths": true
    },
    "usage_pattern": [
      "1. Run 'cyntrisec scan' to collect AWS data",
      "2. Run 'cyntrisec analyze paths' to see attack paths",
      "3. Run 'cyntrisec cuts' to get prioritized fixes",
      "4. Run 'cyntrisec can X access Y' to verify specific access"
    ],
    "error_codes": [
      "AWS_ACCESS_DENIED",
      "AWS_THROTTLED",
      "AWS_REGION_DISABLED",
      "SNAPSHOT_NOT_FOUND",
      "SCHEMA_MISMATCH",
      "INVALID_QUERY",
      "INTERNAL_ERROR"
    ]
  },
  "message": null,
  "error_code": null,
  "artifact_paths": null,
  "suggested_actions": null
}
```

### cyntrisec analyze paths
```bash
cyntrisec analyze paths --scan 2026-01-18_000000_123456789012 --format agent
```
```
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "paths": [
      {
        "id": "bbbbbbb1-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
        "source_asset_id": "00000000-0000-0000-0000-000000000000",
        "target_asset_id": "44444444-4444-4444-4444-444444444444",
        "path_asset_ids": [
          "00000000-0000-0000-0000-000000000000",
          "11111111-1111-1111-1111-111111111111",
          "33333333-3333-3333-3333-333333333333",
          "44444444-4444-4444-4444-444444444444"
        ],
        "path_relationship_ids": [
          "aaaaaaa6-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa3-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        ],
        "attack_vector": "instance-compromise",
        "path_length": 3,
        "entry_confidence": 0.9,
        "exploitability_score": 0.8,
        "impact_score": 0.9,
        "risk_score": 0.65,
        "confidence_level": "high",
        "confidence_reason": "All preconditions verified: CAN_REACH from Internet, CAN_ASSUME via instance profile, MAY_READ_SECRET with valid policy",
        "attack_chain_relationship_ids": [
          "aaaaaaa6-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa3-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        ],
        "context_relationship_ids": [
          "aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        ],
        "proof": {
          "steps": [
            {
              "name": "Internet",
              "asset_type": "pseudo:internet"
            },
            {
              "name": "entry-instance",
              "asset_type": "ec2:instance"
            },
            {
              "name": "AdminRole",
              "asset_type": "iam:role"
            },
            {
              "name": "prod-database-creds",
              "asset_type": "secretsmanager:secret"
            }
          ]
        }
      },
      {
        "id": "bbbbbbb2-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
        "source_asset_id": "00000000-0000-0000-0000-000000000000",
        "target_asset_id": "55555555-5555-5555-5555-555555555555",
        "path_asset_ids": [
          "00000000-0000-0000-0000-000000000000",
          "11111111-1111-1111-1111-111111111111",
          "33333333-3333-3333-3333-333333333333",
          "55555555-5555-5555-5555-555555555555"
        ],
        "path_relationship_ids": [
          "aaaaaaa6-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa4-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        ],
        "attack_vector": "data-exfiltration",
        "path_length": 3,
        "entry_confidence": 0.9,
        "exploitability_score": 0.7,
        "impact_score": 0.8,
        "risk_score": 0.5,
        "confidence_level": "high",
        "confidence_reason": "All preconditions verified: CAN_REACH from Internet, CAN_ASSUME via instance profile, MAY_READ_S3_OBJECT with valid policy",
        "attack_chain_relationship_ids": [
          "aaaaaaa6-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa4-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        ],
        "context_relationship_ids": [
          "aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        ],
        "proof": {
          "steps": [
            {
              "name": "Internet",
              "asset_type": "pseudo:internet"
            },
            {
              "name": "entry-instance",
              "asset_type": "ec2:instance"
            },
            {
              "name": "AdminRole",
              "asset_type": "iam:role"
            },
            {
              "name": "public-bucket",
              "asset_type": "s3:bucket"
            }
          ]
        }
      }
    ],
    "returned": 2,
    "total": 2
  },
  "message": null,
  "error_code": null,
  "artifact_paths": {
    "snapshot_dir": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012",
    "snapshot": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012\\snapshot.json",
    "assets": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012\\assets.json",
    "relationships": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012\\relationships.json",
    "attack_paths": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012\\attack_paths.json",
    "findings": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012\\findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec cuts --snapshot 00000000-0000-0000-0000-0000000000b2",
      "reason": "Prioritize fixes that block these paths"
    },
    {
      "command": "cyntrisec explain path instance-compromise",
      "reason": "Get human-friendly context for a path"
    }
  ]
}
```

### cyntrisec cuts (ROI Table)
```bash
cyntrisec cuts --snapshot 2026-01-18_000000_123456789012 --format table
```
```
Error:
```

### cyntrisec cuts (JSON with Cost)
```bash
cyntrisec cuts --snapshot 2026-01-18_000000_123456789012 --format json
```
```
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
    "account_id": "123456789012",
    "total_paths": 2,
    "paths_blocked": 2,
    "coverage": 1.0,
    "remediations": [
      {
        "priority": 1,
        "action": "review",
        "description": "Review CAN_REACH: Internet \u2192 entry-instance",
        "relationship_type": "CAN_REACH",
        "source": "Internet",
        "target": "entry-instance",
        "paths_blocked": 2,
        "path_ids": [
          "bbbbbbb1-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
          "bbbbbbb2-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        ],
        "estimated_monthly_savings": null,
        "cost_source": null,
        "cost_confidence": null,
        "cost_assumptions": null
      }
    ]
  },
  "message": null,
  "error_code": null,
  "artifact_paths": {
    "snapshot_dir": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012",
    "snapshot": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012\\snapshot.json",
    "assets": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012\\assets.json",
    "relationships": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012\\relationships.json",
    "attack_paths": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012\\attack_paths.json",
    "findings": "<demo_home>\\.cyntrisec\\scans\\2026-01-18_000000_123456789012\\findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec can Internet access entry-instance",
      "reason": "Verify the highest-priority remediation closes access"
    },
    {
      "command": "cyntrisec report --scan 2026-01-18_000000_123456789012",
      "reason": "Export a full report for stakeholders"
    }
  ]
}
```

### cyntrisec waste
```bash
cyntrisec waste --snapshot 2026-01-18_000000_123456789012 --format table
```
```
+------------------------------ cyntrisec waste ------------------------------+
| Unused Permissions Analysis                                                 |
| Account: 123456789012                                                       |
| Threshold: 90 days                                                          |
| Unused: 0 / 0 permissions                                                   |
| Blast Radius Reduction: 0%                                                  |
+-----------------------------------------------------------------------------+

No obvious waste found.
Run with --live for detailed IAM Access Advisor analysis.
```

### cyntrisec can
```bash
cyntrisec can --snapshot 2026-01-18_000000_123456789012 Admin access s3://prod-bucket --format json
```
```
Error:
```

### cyntrisec ask
```bash
cyntrisec ask --snapshot 2026-01-18_000000_123456789012 'what can reach the database?' --format text
```
```
+------------------------------- cyntrisec ask -------------------------------+
| Query: what can reach the database?                                         |
| Intent: access_check                                                        |
| Snapshot: 123456789012                                                      |
+-----------------------------------------------------------------------------+
No attack paths found to 'what can reach the database?' in the graph.

Use --format agent for structured responses and follow-ups.
```
