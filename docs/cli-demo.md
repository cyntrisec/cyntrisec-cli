# Cyntrisec CLI - Demo Outputs (Sanitized)

Generated: 2026-01-18 00:21:49 UTC

This file is generated from synthetic demo data only. It contains no real AWS account data.
All IDs, ARNs, and paths are placeholders.

## Command coverage
| Command | Exit code | Notes |
| --- | --- | --- |
| cyntrisec scan | n/a | Live AWS command. Sample output included below. |
| cyntrisec validate-role | n/a | Live AWS command. Sample output included below. |
| cyntrisec manifest | 0 | ok |
| cyntrisec serve --list-tools | 0 | ok |
| cyntrisec setup iam | 0 | ok |
| cyntrisec analyze paths | 0 | ok |
| cyntrisec analyze findings | 0 | ok |
| cyntrisec analyze business | 0 | ok |
| cyntrisec analyze stats | 0 | ok |
| cyntrisec cuts | 0 | ok |
| cyntrisec waste | 0 | ok |
| cyntrisec can | 0 | ok |
| cyntrisec comply | 1 | non-zero exit (compliance failures) |
| cyntrisec diff | 1 | non-zero exit (regressions detected) |
| cyntrisec remediate (dry-run) | 0 | ok |
| cyntrisec report | 0 | ok |
| cyntrisec ask | 0 | ok |
| cyntrisec explain finding | 0 | ok |
| cyntrisec explain path | 0 | ok |
| cyntrisec explain control | 0 | ok |

## Sample output: cyntrisec scan (synthetic)
```
python -m cyntrisec scan --role-arn arn:aws:iam::123456789012:role/CyntriSecReadOnly --regions us-east-1 --format agent
```
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
    "account_id": "123456789012",
    "regions": [
      "us-east-1"
    ],
    "asset_count": 6,
    "relationship_count": 5,
    "finding_count": 2,
    "attack_path_count": 2
  },
  "message": null,
  "error_code": null,
  "artifact_paths": {
    "snapshot_dir": "<demo_home>/...",
    "snapshot": "<demo_home>/.../snapshot.json",
    "assets": "<demo_home>/.../assets.json",
    "relationships": "<demo_home>/.../relationships.json",
    "attack_paths": "<demo_home>/.../attack_paths.json",
    "findings": "<demo_home>/.../findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec analyze paths --scan <scan_id>",
      "reason": "Review discovered attack paths"
    },
    {
      "command": "cyntrisec cuts --snapshot <scan_id>",
      "reason": "Prioritize fixes that block paths"
    },
    {
      "command": "cyntrisec report --scan <scan_id> --output cyntrisec-report.html",
      "reason": "Generate a full report"
    }
  ]
}
```

## Sample output: cyntrisec validate-role (synthetic)
```
python -m cyntrisec validate-role --role-arn arn:aws:iam::123456789012:role/CyntriSecReadOnly --format agent
```
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "success": true,
    "role_arn": "arn:aws:iam::123456789012:role/CyntriSecReadOnly",
    "account": "123456789012",
    "arn": "arn:aws:sts::123456789012:assumed-role/CyntriSecReadOnly/cyntrisec-validate",
    "user_id": "AROAEXAMPLE:cyntrisec-validate"
  },
  "message": null,
  "error_code": null,
  "artifact_paths": null,
  "suggested_actions": [
    {
      "command": "cyntrisec scan --role-arn arn:aws:iam::123456789012:role/CyntriSecReadOnly",
      "reason": "Start a scan"
    }
  ]
}
```

## cyntrisec manifest
```
python -m cyntrisec manifest --format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "name": "cyntrisec",
    "version": "0.1.0",
    "description": "AWS capability graph analysis and attack path discovery",
    "capabilities": [
      {
        "name": "scan",
        "description": "Scan an AWS account for security issues and attack paths",
        "parameters": [
          {
            "name": "role_arn",
            "type": "string",
            "required": true,
            "description": "AWS IAM role ARN to assume for scanning"
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
          }
        ],
        "output": {
          "type": "object",
          "properties": {
            "snapshot_id": {
              "type": "string"
            },
            "assets": {
              "type": "integer"
            },
            "relationships": {
              "type": "integer"
            },
            "findings": {
              "type": "integer"
            },
            "attack_paths": {
              "type": "integer"
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
              "json"
            ],
            "description": "Output format"
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
              "json"
            ],
            "description": "Output format"
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
              "json"
            ],
            "description": "Output format"
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
              "json"
            ],
            "description": "Output format"
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
              "json"
            ],
            "description": "Output format"
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
        "description": "Generate remediation plan to block attack paths",
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
            "description": "Required to run apply/terraform"
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
      }
    ],
    "schemas": {
      "version": "1.0",
      "base_url": "https://cyntrisec.dev/schemas/cli",
      "responses": {
        "scan": {
          "additionalProperties": false,
          "properties": {
            "snapshot_id": {
              "title": "Snapshot Id",
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
            }
          },
          "required": [
            "snapshot_id",
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

## cyntrisec serve --list-tools
```
python -m cyntrisec serve --list-tools --format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "tools": [
      {
        "name": "get_scan_summary",
        "description": "Get summary of the latest AWS scan",
        "parameters": []
      },
      {
        "name": "get_attack_paths",
        "description": "Get discovered attack paths with risk scores",
        "parameters": [
          {
            "name": "max_paths",
            "type": "integer",
            "default": 10
          }
        ]
      },
      {
        "name": "get_remediations",
        "description": "Find minimal set of fixes to block attack paths",
        "parameters": [
          {
            "name": "max_cuts",
            "type": "integer",
            "default": 5
          }
        ]
      },
      {
        "name": "check_access",
        "description": "Test if a principal can access a resource",
        "parameters": [
          {
            "name": "principal",
            "type": "string",
            "required": true
          },
          {
            "name": "resource",
            "type": "string",
            "required": true
          }
        ]
      },
      {
        "name": "get_unused_permissions",
        "description": "Find unused IAM permissions",
        "parameters": [
          {
            "name": "days_threshold",
            "type": "integer",
            "default": 90
          }
        ]
      },
      {
        "name": "check_compliance",
        "description": "Check CIS AWS or SOC 2 compliance",
        "parameters": [
          {
            "name": "framework",
            "type": "string",
            "enum": [
              "cis-aws",
              "soc2"
            ],
            "default": "cis-aws"
          }
        ]
      },
      {
        "name": "compare_scans",
        "description": "Compare latest scan to previous for regressions",
        "parameters": []
      }
    ]
  },
  "message": null,
  "error_code": null,
  "artifact_paths": null,
  "suggested_actions": null
}
```

## cyntrisec setup iam
```
python -m cyntrisec setup iam 123456789012 --format policy --output-format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "account_id": "123456789012",
    "role_name": "CyntrisecReadOnly",
    "external_id": null,
    "template_format": "policy",
    "template": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"CyntrisecReadOnly\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"ec2:Describe*\",\n        \"iam:Get*\",\n        \"iam:List*\",\n        \"s3:GetBucketAcl\",\n        \"s3:GetBucketPolicy\",\n        \"s3:GetBucketPolicyStatus\",\n        \"s3:GetBucketPublicAccessBlock\",\n        \"s3:GetBucketLocation\",\n        \"s3:ListBucket\",\n        \"s3:ListAllMyBuckets\",\n        \"lambda:GetFunction\",\n        \"lambda:GetFunctionConfiguration\",\n        \"lambda:GetPolicy\",\n        \"lambda:ListFunctions\",\n        \"rds:Describe*\",\n        \"elasticloadbalancing:Describe*\",\n        \"route53:List*\",\n        \"route53:Get*\",\n        \"cloudfront:Get*\",\n        \"cloudfront:List*\",\n        \"apigateway:GET\",\n        \"sts:GetCallerIdentity\"\n      ],\n      \"Resource\": \"*\"\n    }\n  ]\n}",
    "output_path": null
  },
  "message": null,
  "error_code": null,
  "artifact_paths": null,
  "suggested_actions": [
    {
      "command": "cyntrisec validate-role --role-arn arn:aws:iam::123456789012:role/CyntrisecReadOnly",
      "reason": "Verify trust and permissions"
    },
    {
      "command": "cyntrisec scan --role-arn <role_arn>",
      "reason": "Kick off the first scan"
    }
  ]
}
```

## cyntrisec analyze paths
```
python -m cyntrisec analyze paths --scan 2026-01-18_000000_123456789012 --format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "paths": [
      {
        "id": "bbbbbbb1-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
        "source_asset_id": "22222222-2222-2222-2222-222222222222",
        "target_asset_id": "44444444-4444-4444-4444-444444444444",
        "path_asset_ids": [
          "22222222-2222-2222-2222-222222222222",
          "11111111-1111-1111-1111-111111111111",
          "33333333-3333-3333-3333-333333333333",
          "44444444-4444-4444-4444-444444444444"
        ],
        "path_relationship_ids": [
          "aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa3-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        ],
        "attack_vector": "instance-compromise",
        "path_length": 3,
        "entry_confidence": 0.9,
        "exploitability_score": 0.8,
        "impact_score": 0.9,
        "risk_score": 0.65,
        "proof": {
          "steps": [
            {
              "name": "sg-web"
            },
            {
              "name": "entry-instance"
            },
            {
              "name": "AdminRole"
            },
            {
              "name": "prod-database"
            }
          ]
        }
      },
      {
        "id": "bbbbbbb2-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
        "source_asset_id": "22222222-2222-2222-2222-222222222222",
        "target_asset_id": "55555555-5555-5555-5555-555555555555",
        "path_asset_ids": [
          "22222222-2222-2222-2222-222222222222",
          "11111111-1111-1111-1111-111111111111",
          "33333333-3333-3333-3333-333333333333",
          "55555555-5555-5555-5555-555555555555"
        ],
        "path_relationship_ids": [
          "aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "aaaaaaa4-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        ],
        "attack_vector": "data-exfiltration",
        "path_length": 3,
        "entry_confidence": 0.9,
        "exploitability_score": 0.7,
        "impact_score": 0.8,
        "risk_score": 0.5,
        "proof": {
          "steps": [
            {
              "name": "sg-web"
            },
            {
              "name": "entry-instance"
            },
            {
              "name": "AdminRole"
            },
            {
              "name": "public-bucket"
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
    "snapshot_dir": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012",
    "snapshot": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/snapshot.json",
    "assets": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/assets.json",
    "relationships": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/relationships.json",
    "attack_paths": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/attack_paths.json",
    "findings": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec cuts --snapshot 2026-01-18_000000_123456789012",
      "reason": "Prioritize fixes that block these paths"
    },
    {
      "command": "cyntrisec explain path instance-compromise",
      "reason": "Get human-friendly context for a path"
    }
  ]
}
```

## cyntrisec analyze findings
```
python -m cyntrisec analyze findings --scan 2026-01-18_000000_123456789012 --format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "findings": [
      {
        "id": "ccccccc2-cccc-cccc-cccc-cccccccccccc",
        "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
        "asset_id": "55555555-5555-5555-5555-555555555555",
        "finding_type": "s3_public_bucket",
        "severity": "critical",
        "title": "S3 bucket is public",
        "description": "Bucket allows public access.",
        "remediation": "Enable Block Public Access and remove public ACLs.",
        "evidence": {
          "public": true
        }
      },
      {
        "id": "ccccccc1-cccc-cccc-cccc-cccccccccccc",
        "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
        "asset_id": "22222222-2222-2222-2222-222222222222",
        "finding_type": "security_group_open_to_world",
        "severity": "high",
        "title": "Security group allows 0.0.0.0/0 ingress",
        "description": "Inbound rule allows traffic from anywhere.",
        "remediation": "Restrict ingress to known IP ranges.",
        "evidence": {
          "cidr": "0.0.0.0/0"
        }
      }
    ],
    "total": 2,
    "filter": "any"
  },
  "message": null,
  "error_code": null,
  "artifact_paths": {
    "snapshot_dir": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012",
    "snapshot": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/snapshot.json",
    "assets": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/assets.json",
    "relationships": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/relationships.json",
    "attack_paths": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/attack_paths.json",
    "findings": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec explain finding s3_public_bucket",
      "reason": "See remediation context for the most common finding"
    },
    {
      "command": "cyntrisec comply --format agent",
      "reason": "Map findings to compliance controls"
    }
  ]
}
```

## cyntrisec analyze business
```
python -m cyntrisec analyze business --scan 2026-01-18_000000_123456789012 --business-tag Environment=prod,Critical=true --report --format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "entrypoints_requested": [],
    "entrypoints_found": [
      "prod-database"
    ],
    "attackable_count": 5,
    "business_required_count": 1,
    "waste_candidate_count": 4,
    "waste_candidates": [
      {
        "name": "sg-web",
        "asset_type": "ec2:security-group",
        "reason": "in attack paths",
        "asset_id": "22222222-2222-2222-2222-222222222222",
        "monthly_cost_usd": null
      },
      {
        "name": "entry-instance",
        "asset_type": "ec2:instance",
        "reason": "in attack paths",
        "asset_id": "11111111-1111-1111-1111-111111111111",
        "monthly_cost_usd": 50.0
      },
      {
        "name": "AdminRole",
        "asset_type": "iam:role",
        "reason": "in attack paths",
        "asset_id": "33333333-3333-3333-3333-333333333333",
        "monthly_cost_usd": null
      },
      {
        "name": "public-bucket",
        "asset_type": "s3:bucket",
        "reason": "in attack paths",
        "asset_id": "55555555-5555-5555-5555-555555555555",
        "monthly_cost_usd": 5.0
      }
    ],
    "business_assets": [
      {
        "name": "prod-database",
        "asset_type": "rds:db-instance",
        "reason": "tags",
        "asset_id": "44444444-4444-4444-4444-444444444444",
        "tags": {
          "Environment": "prod",
          "Critical": "true"
        }
      }
    ],
    "unknown_assets": [
      {
        "name": "sg-web",
        "asset_type": "ec2:security-group",
        "reason": "attackable_not_business",
        "asset_id": "22222222-2222-2222-2222-222222222222",
        "tags": {
          "Environment": "prod"
        }
      },
      {
        "name": "entry-instance",
        "asset_type": "ec2:instance",
        "reason": "attackable_not_business",
        "asset_id": "11111111-1111-1111-1111-111111111111",
        "tags": {
          "Environment": "prod"
        }
      },
      {
        "name": "AdminRole",
        "asset_type": "iam:role",
        "reason": "attackable_not_business",
        "asset_id": "33333333-3333-3333-3333-333333333333",
        "tags": {
          "Owner": "security"
        }
      },
      {
        "name": "public-bucket",
        "asset_type": "s3:bucket",
        "reason": "attackable_not_business",
        "asset_id": "55555555-5555-5555-5555-555555555555",
        "tags": {
          "Environment": "prod"
        }
      }
    ]
  },
  "message": null,
  "error_code": null,
  "artifact_paths": {
    "snapshot_dir": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012",
    "snapshot": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/snapshot.json",
    "assets": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/assets.json",
    "relationships": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/relationships.json",
    "attack_paths": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/attack_paths.json",
    "findings": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec waste --format agent",
      "reason": "Review unused permissions/waste"
    },
    {
      "command": "cyntrisec cuts --format agent",
      "reason": "Prioritize fixes to reduce attackable surface"
    },
    {
      "command": "cyntrisec analyze business --report --format agent",
      "reason": "Show full business coverage report"
    }
  ]
}
```

## cyntrisec analyze stats
```
python -m cyntrisec analyze stats --scan 2026-01-18_000000_123456789012
```
Exit code: 0

Output:
```
=== Scan Statistics ===

Account: 123456789012
Regions: us-east-1
Status: completed
Started: 2026-01-18 00:00:00+00:00
Completed: 2026-01-18 00:01:00+00:00

--- Counts ---
Assets: 6
Findings: 2
Attack paths: 2

--- Assets by Type ---
  ec2:security-group: 1
  ec2:instance: 1
  iam:role: 1
  rds:db-instance: 1
  s3:bucket: 1
  lambda:function: 1

--- Findings by Severity ---
  critical: 1
  high: 1

--- Attack Paths ---
  Highest risk: 0.650
  Average risk: 0.575
```

## cyntrisec cuts
```
python -m cyntrisec cuts --snapshot 2026-01-18_000000_123456789012 --format agent
```
Exit code: 0

Output:
```json
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
        "action": "restrict",
        "description": "Remove 0.0.0.0/0 ingress from sg-web",
        "relationship_type": "ALLOWS_TRAFFIC_TO",
        "source": "sg-web",
        "target": "entry-instance",
        "paths_blocked": 2,
        "path_ids": [
          "bbbbbbb1-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
          "bbbbbbb2-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        ]
      }
    ]
  },
  "message": null,
  "error_code": null,
  "artifact_paths": {
    "snapshot_dir": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012",
    "snapshot": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/snapshot.json",
    "assets": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/assets.json",
    "relationships": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/relationships.json",
    "attack_paths": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/attack_paths.json",
    "findings": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec can sg-web access entry-instance",
      "reason": "Verify the highest-priority remediation closes access"
    },
    {
      "command": "cyntrisec report --scan 00000000-0000-0000-0000-0000000000b2",
      "reason": "Export a full report for stakeholders"
    }
  ]
}
```

## cyntrisec waste
```
python -m cyntrisec waste --snapshot 2026-01-18_000000_123456789012 --format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
    "account_id": "123456789012",
    "days_threshold": 90,
    "total_permissions": 1,
    "total_unused": 1,
    "blast_radius_reduction": 1.0,
    "roles": [
      {
        "role_arn": "arn:aws:iam::123456789012:role/AdminRole",
        "role_name": "AdminRole",
        "total_services": 1,
        "unused_services": 1,
        "reduction": 1.0,
        "unused_capabilities": [
          {
            "service": "*",
            "service_name": "All Services",
            "days_unused": null,
            "risk_level": "high",
            "recommendation": "Review AdminRole - broad name suggests over-permissioning",
            "monthly_cost_usd_estimate": null,
            "cost_source": null,
            "confidence": null,
            "assumptions": null
          }
        ]
      }
    ]
  },
  "message": null,
  "error_code": null,
  "artifact_paths": {
    "snapshot_dir": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012",
    "snapshot": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/snapshot.json",
    "assets": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/assets.json",
    "relationships": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/relationships.json",
    "attack_paths": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/attack_paths.json",
    "findings": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec comply --snapshot 2026-01-18_000000_123456789012 --format agent",
      "reason": "Connect unused permissions to compliance gaps"
    },
    {
      "command": "cyntrisec cuts --snapshot 2026-01-18_000000_123456789012",
      "reason": "Prioritize fixes that remove risky unused permissions"
    }
  ]
}
```

## cyntrisec can
```
python -m cyntrisec can AdminRole access arn:aws:rds:us-east-1:123456789012:db:prod-database --snapshot 2026-01-18_000000_123456789012 --format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
    "principal": "arn:aws:iam::123456789012:role/AdminRole",
    "resource": "arn:aws:rds:us-east-1:123456789012:db:prod-database",
    "action": "*",
    "can_access": true,
    "simulations": [],
    "proof": {
      "relationship_type": "MAY_ACCESS",
      "properties": {}
    }
  },
  "message": null,
  "error_code": null,
  "artifact_paths": null,
  "suggested_actions": [
    {
      "command": "cyntrisec cuts --snapshot 00000000-0000-0000-0000-0000000000b2",
      "reason": "Identify changes that would block this access"
    },
    {
      "command": "cyntrisec can arn:aws:iam::123456789012:role/AdminRole access arn:aws:rds:us-east-1:123456789012:db:prod-database --live",
      "reason": "Validate against live IAM policy simulation"
    }
  ]
}
```

## cyntrisec comply
```
python -m cyntrisec comply --snapshot 2026-01-18_000000_123456789012 --format agent
```
Exit code: 1

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "framework": "CIS-AWS",
    "compliance_score": 0.7692307692307693,
    "passing": 10,
    "failing": 3,
    "controls": [
      {
        "id": "2.1.1",
        "title": "Ensure S3 bucket Block Public Access is enabled",
        "status": "fail",
        "severity": "high",
        "description": "Ensure S3 bucket Block Public Access is enabled"
      },
      {
        "id": "2.1.2",
        "title": "Ensure S3 bucket Block Public Access at account level",
        "status": "fail",
        "severity": "high",
        "description": "Ensure S3 bucket Block Public Access at account level"
      },
      {
        "id": "5.1",
        "title": "Ensure no open Security Groups to 0.0.0.0/0",
        "status": "fail",
        "severity": "high",
        "description": "Ensure no open Security Groups to 0.0.0.0/0"
      }
    ]
  },
  "message": null,
  "error_code": null,
  "artifact_paths": {
    "snapshot_dir": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012",
    "snapshot": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/snapshot.json",
    "assets": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/assets.json",
    "relationships": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/relationships.json",
    "attack_paths": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/attack_paths.json",
    "findings": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec explain control 1.4",
      "reason": "Explain top failing control"
    },
    {
      "command": "cyntrisec cuts --snapshot 00000000-0000-0000-0000-0000000000b2",
      "reason": "Map compliance fixes to attack path cuts"
    }
  ]
}
```

## cyntrisec diff
```
python -m cyntrisec diff --format agent
```
Exit code: 1

Output:
```json
{
  "schema_version": "1.0",
  "status": "regressions",
  "data": {
    "has_regressions": true,
    "has_improvements": false,
    "summary": {
      "assets_added": 0,
      "assets_removed": 0,
      "relationships_added": 0,
      "relationships_removed": 0,
      "paths_added": 1,
      "paths_removed": 0,
      "findings_new": 1,
      "findings_resolved": 0
    },
    "path_changes": [
      {
        "change_type": "added",
        "path_id": null,
        "detail": {},
        "attack_vector": "data-exfiltration",
        "risk_score": 0.5,
        "is_regression": true,
        "is_improvement": false
      }
    ],
    "old_snapshot": {
      "id": "00000000-0000-0000-0000-0000000000a1",
      "account_id": "123456789012",
      "timestamp": "2026-01-17T00:00:00+00:00"
    },
    "new_snapshot": {
      "id": "00000000-0000-0000-0000-0000000000b2",
      "account_id": "123456789012",
      "timestamp": "2026-01-18T00:00:00+00:00"
    },
    "finding_changes": [
      {
        "change_type": "added",
        "severity": "critical",
        "title": "S3 bucket is public",
        "is_regression": true
      }
    ],
    "asset_changes": null,
    "relationship_changes": null
  },
  "message": null,
  "error_code": null,
  "artifact_paths": {
    "snapshot_dir": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012",
    "snapshot": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/snapshot.json",
    "assets": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/assets.json",
    "relationships": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/relationships.json",
    "attack_paths": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/attack_paths.json",
    "findings": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec analyze paths --scan latest",
      "reason": "Review new attack paths"
    },
    {
      "command": "cyntrisec cuts --snapshot latest",
      "reason": "Find fixes for new regressions"
    }
  ]
}
```

## cyntrisec remediate (dry-run)
```
python -m cyntrisec remediate --snapshot 2026-01-18_000000_123456789012 --format agent --dry-run --enable-unsafe-write-mode --yes --output <demo_home>\remediation-plan.json --terraform-dir <demo_home>\remediation-tf
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "applied",
  "data": {
    "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
    "account_id": "123456789012",
    "total_paths": 2,
    "paths_blocked": 2,
    "coverage": 1.0,
    "plan": [
      {
        "priority": 1,
        "action": "restrict",
        "description": "Remove 0.0.0.0/0 ingress from sg-web",
        "source": "sg-web",
        "target": "entry-instance",
        "relationship_type": "ALLOWS_TRAFFIC_TO",
        "paths_blocked": 2,
        "terraform": "# Restrict security group ingress\nresource \"aws_security_group_rule\" \"restrict_ingress\" {\n  description = \"Restrict sg-web -> entry-instance\"\n  type        = \"ingress\"\n  from_port   = 0\n  to_port     = 0\n  protocol    = \"tcp\"\n  cidr_blocks = [\"10.0.0.0/8\"]\n}",
        "status": null,
        "terraform_path": null,
        "terraform_result": null
      }
    ],
    "applied": true,
    "mode": "dry-run",
    "output_path": "<demo_home>/remediation-plan.json",
    "terraform_path": "<demo_home>/remediation-tf/main.tf",
    "terraform_dir": "<demo_home>/remediation-tf",
    "apply": {
      "mode": "dry-run",
      "output_path": "<demo_home>/remediation-plan.json",
      "terraform_path": "<demo_home>/remediation-tf/main.tf",
      "terraform_dir": "<demo_home>/remediation-tf",
      "plan_exit_code": null,
      "plan_summary": null,
      "results": [
        {
          "priority": 1,
          "action": "restrict",
          "description": "Remove 0.0.0.0/0 ingress from sg-web",
          "source": null,
          "target": null,
          "relationship_type": null,
          "paths_blocked": 2,
          "terraform": null,
          "status": "pending_dry_run",
          "terraform_path": "<demo_home>/remediation-tf/main.tf",
          "terraform_result": null
        }
      ]
    }
  },
  "message": null,
  "error_code": null,
  "artifact_paths": {
    "snapshot_dir": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012",
    "snapshot": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/snapshot.json",
    "assets": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/assets.json",
    "relationships": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/relationships.json",
    "attack_paths": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/attack_paths.json",
    "findings": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec can <principal> access <resource>",
      "reason": "Verify access is closed after remediation"
    },
    {
      "command": "cyntrisec diff --format agent",
      "reason": "Detect regressions after applying fixes"
    }
  ]
}
```

## cyntrisec report
```
python -m cyntrisec report --scan 2026-01-18_000000_123456789012 --format agent --output <demo_home>\report.json
```
Exit code: 4

Output:
```json
{
  "schema_version": "1.0",
  "status": "error",
  "data": {
    "errors": [
      {
        "type": "extra_forbidden",
        "loc": [
          "format"
        ],
        "msg": "Extra inputs are not permitted",
        "input": "json",
        "url": "https://errors.pydantic.dev/2.12/v/extra_forbidden"
      }
    ]
  },
  "message": "Response schema validation failed",
  "error_code": "SCHEMA_MISMATCH",
  "artifact_paths": null,
  "suggested_actions": null
}
```

## cyntrisec ask
```
python -m cyntrisec ask show public s3 buckets --snapshot 2026-01-18_000000_123456789012 --format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "query": "show public s3 buckets",
    "intent": "public_s3",
    "results": {
      "public_buckets": [
        {
          "name": "public-bucket",
          "arn": "arn:aws:s3:::public-bucket"
        }
      ],
      "count": 1
    },
    "snapshot_id": "00000000-0000-0000-0000-0000000000b2",
    "entities": {
      "buckets": [],
      "arns": [],
      "roles": []
    },
    "resolved": "list_public_buckets"
  },
  "message": null,
  "error_code": null,
  "artifact_paths": {
    "snapshot_dir": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012",
    "snapshot": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/snapshot.json",
    "assets": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/assets.json",
    "relationships": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/relationships.json",
    "attack_paths": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/attack_paths.json",
    "findings": "<demo_home>/.cyntrisec/scans/2026-01-18_000000_123456789012/findings.json"
  },
  "suggested_actions": [
    {
      "command": "cyntrisec explain finding s3_public_bucket",
      "reason": "See why public buckets are risky"
    },
    {
      "command": "cyntrisec can <principal> access s3://bucket --format agent",
      "reason": "Verify specific access"
    }
  ]
}
```

## cyntrisec explain finding
```
python -m cyntrisec explain finding security_group_open_to_world --format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "type": "finding",
    "id": "security_group_open_to_world",
    "explanation": {
      "title": "Security Group Open to World",
      "severity": "HIGH",
      "what": "A security group has an inbound rule allowing traffic from 0.0.0.0/0 (all IPs).",
      "why": "This exposes the resource to the entire internet. Attackers can scan and probe the exposed ports, potentially leading to exploitation if vulnerabilities exist.",
      "fix": "Restrict the source IP to specific trusted ranges. Use VPN or bastion hosts for remote access instead of direct internet exposure.",
      "next_command": "cyntrisec cuts"
    }
  },
  "message": null,
  "error_code": null,
  "artifact_paths": null,
  "suggested_actions": [
    {
      "command": "cyntrisec cuts",
      "reason": "Suggested next step"
    }
  ]
}
```

## cyntrisec explain path
```
python -m cyntrisec explain path instance-compromise --format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "type": "path",
    "id": "instance-compromise",
    "explanation": {
      "title": "Instance Compromise Attack Path",
      "description": "An attacker who gains access to an EC2 instance can leverage its IAM role to access other resources.",
      "stages": [
        "1. **Initial Access**: Attacker exploits vulnerability or uses stolen credentials to access EC2 instance",
        "2. **Credential Theft**: Instance metadata service (IMDS) provides temporary IAM credentials",
        "3. **Lateral Movement**: Attacker uses IAM role permissions to access S3, RDS, or other services",
        "4. **Impact**: Data exfiltration, privilege escalation, or further infrastructure compromise"
      ],
      "mitigations": [
        "Use IMDSv2 instead of IMDSv1 to prevent SSRF-based credential theft",
        "Apply least-privilege to instance IAM roles",
        "Use VPC endpoints to restrict network paths",
        "Enable GuardDuty for anomaly detection"
      ]
    }
  },
  "message": null,
  "error_code": null,
  "artifact_paths": null,
  "suggested_actions": [
    {
      "command": "cyntrisec analyze paths --format agent",
      "reason": "List concrete paths of this type"
    }
  ]
}
```

## cyntrisec explain control
```
python -m cyntrisec explain control CIS-AWS:5.1 --format agent
```
Exit code: 0

Output:
```json
{
  "schema_version": "1.0",
  "status": "success",
  "data": {
    "type": "control",
    "id": "CIS-AWS:5.1",
    "explanation": {
      "id": "CIS-AWS:5.1",
      "title": "Ensure no open Security Groups to 0.0.0.0/0",
      "description": "Security groups should not allow 0.0.0.0/0 ingress",
      "severity": "high",
      "framework": "CIS-AWS"
    }
  },
  "message": null,
  "error_code": null,
  "artifact_paths": null,
  "suggested_actions": [
    {
      "command": "cyntrisec comply --format agent",
      "reason": "Run a full compliance check"
    }
  ]
}
```
