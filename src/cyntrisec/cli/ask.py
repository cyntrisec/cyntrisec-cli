"""
ask command - Natural language queries over scan results.

Maps simple natural language questions to existing commands/results and
returns agent-friendly structured output.
"""

from __future__ import annotations

import re

import typer
from rich.console import Console
from rich.panel import Panel

from cyntrisec.cli.errors import EXIT_CODE_MAP, CyntriError, ErrorCode, handle_errors
from cyntrisec.cli.output import (
    build_artifact_paths,
    emit_agent_or_json,
    resolve_format,
    suggested_actions,
)
from cyntrisec.cli.schemas import AskResponse

console = Console()


@handle_errors
def ask_cmd(
    query: str = typer.Argument(..., help="Natural language question"),
    snapshot_id: str | None = typer.Option(
        None,
        "--snapshot",
        "-s",
        help="Snapshot UUID (default: latest; scan_id accepted)",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: text, json, agent (defaults to json when piped)",
    ),
):
    """
    Ask natural language questions about the security graph.

    Examples:
        cyntrisec ask "what can reach the production database?"
        cyntrisec ask "show me public s3 buckets"
        cyntrisec ask "which roles have admin access?"
    """
    from cyntrisec.storage import FileSystemStorage

    output_format = resolve_format(
        format,
        default_tty="text",
        allowed=["text", "json", "agent"],
    )

    classification = _classify_query(query)
    intent = classification["intent"]
    storage = FileSystemStorage()
    snapshot = storage.get_snapshot(snapshot_id)

    if not snapshot:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="No scan data found. Run 'cyntrisec scan' first.",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    response = _execute_intent(classification, query, storage, snapshot_id)

    if output_format in {"json", "agent"}:
        actions = suggested_actions(response["suggested_actions"])
        payload = {
            "query": query,
            "intent": intent,
            "results": response["results"],
            "snapshot_id": str(snapshot.id),
            "entities": classification["entities"],
            "resolved": response.get("resolved_query", intent),
        }
        emit_agent_or_json(
            output_format,
            payload,
            suggested=actions,
            artifact_paths=build_artifact_paths(storage, snapshot_id),
            schema=AskResponse,
        )
        raise typer.Exit(0)

    _print_text_response(query, intent, response, snapshot)
    raise typer.Exit(0)


def _classify_query(query: str) -> dict:
    """Heuristic intent classification with lightweight scoring and entity extraction."""
    q = query.lower()
    entities = _extract_entities(query)

    intents = {
        "attack_paths": ["reach", "path", "attack", "kill chain", "route"],
        "public_s3": ["bucket", "s3"],  # Removed "public" - handled in scoring
        "public_ec2": ["ec2", "instance", "server", "compute"],  # New intent for EC2
        "admin_roles": ["admin", "root", "privileged", "full access"],
        "compliance": ["compliance", "cis", "soc2", "benchmark"],
        "access_check": ["can", "access", "reach", "allowed"],
        "waste": ["unused", "waste", "reduce", "permissions", "cost"],
    }

    scores = {}
    for intent, keywords in intents.items():
        score = sum(1 for kw in keywords if kw in q)
        # boost if entities suggest buckets/roles
        if intent == "public_s3" and entities.get("buckets"):
            score += 2
        # Boost S3 intent only if "public" AND "bucket" or "s3" are present
        if intent == "public_s3" and "public" in q and ("bucket" in q or "s3" in q):
            score += 3
        # Boost EC2 intent if "public" AND EC2-related keywords are present
        if (
            intent == "public_ec2"
            and "public" in q
            and any(kw in q for kw in ["ec2", "instance", "server"])
        ):
            score += 3
        if intent == "admin_roles" and entities.get("roles"):
            score += 2
        if intent == "access_check" and (entities.get("arns") or entities.get("roles")):
            score += 2
        if intent == "waste" and ("cost" in q or "spend" in q):
            score += 1
        scores[intent] = score

    # choose highest scoring intent or default general
    intent = max(scores, key=scores.get)
    if scores[intent] == 0:
        intent = "general"

    return {"intent": intent, "scores": scores, "entities": entities}


def _extract_entities(query: str) -> dict:
    """Extract simple entities like bucket names, ARNs, and role-like tokens."""
    buckets = re.findall(r"s3://[\w\-.]+", query)
    buckets += re.findall(r"\b([a-z0-9\-\.]+bucket[a-z0-9\-\.]*)\b", query, re.IGNORECASE)
    arns = re.findall(r"arn:[^\s]+", query)
    roles = re.findall(r"\b[A-Za-z0-9+=,.@_-]+Role\b", query, re.IGNORECASE)
    roles += re.findall(r"\brole[:/ ]+([A-Za-z0-9+=,.@_-]+)\b", query, re.IGNORECASE)
    return {
        "buckets": list({b for b in buckets}),
        "arns": list({a for a in arns}),
        "roles": list({r for r in roles}),
    }


def _execute_intent(classification: dict, query: str, storage, snapshot_id: str | None):
    """Execute intent using existing data; returns results and suggested actions."""
    intent = classification["intent"]
    entities = classification["entities"]

    if intent == "attack_paths":
        paths = storage.get_attack_paths(snapshot_id)
        top = [
            {
                "attack_vector": p.attack_vector,
                "risk_score": float(p.risk_score),
                "source": str(p.source_asset_id),
                "target": str(p.target_asset_id),
            }
            for p in sorted(paths, key=lambda p: float(p.risk_score), reverse=True)[:5]
        ]
        return {
            "results": {"attack_paths": top, "count": len(paths)},
            "resolved_query": "list_top_attack_paths",
            "suggested_actions": [
                ("cyntrisec analyze paths --format agent", "List full attack paths"),
                ("cyntrisec cuts --format agent", "Get remediations to block paths"),
            ],
        }

    if intent == "public_s3":
        assets = storage.get_assets(snapshot_id)
        public_buckets = [
            {"name": a.name, "arn": a.arn or a.aws_resource_id}
            for a in assets
            if "s3" in a.asset_type.lower()
            and ("public" in a.name.lower() or a.properties.get("public"))
        ]
        if not public_buckets and entities.get("buckets"):
            public_buckets = [{"name": b, "arn": ""} for b in entities["buckets"]]
        return {
            "results": {"public_buckets": public_buckets, "count": len(public_buckets)},
            "resolved_query": "list_public_buckets",
            "suggested_actions": [
                ("cyntrisec explain finding s3_public_bucket", "See why public buckets are risky"),
                (
                    "cyntrisec can <principal> access s3://bucket --format agent",
                    "Verify specific access",
                ),
            ],
        }

    if intent == "public_ec2":
        assets = storage.get_assets(snapshot_id)
        public_instances = [
            {
                "name": a.name,
                "arn": a.arn or a.aws_resource_id,
                "public_ip": a.properties.get("public_ip"),
            }
            for a in assets
            if a.asset_type == "ec2:instance"
            and (a.properties.get("public_ip") or a.properties.get("public_dns_name"))
        ]
        return {
            "results": {"public_ec2_instances": public_instances, "count": len(public_instances)},
            "resolved_query": "list_public_ec2_instances",
            "suggested_actions": [
                (
                    "cyntrisec explain finding ec2-public-ip",
                    "See why public EC2 instances are risky",
                ),
                (
                    "cyntrisec analyze paths --format agent",
                    "Review attack paths involving these instances",
                ),
            ],
        }

    if intent == "admin_roles":
        assets = storage.get_assets(snapshot_id)
        roles = [
            {"name": a.name, "arn": a.arn or a.aws_resource_id}
            for a in assets
            if a.asset_type == "iam:role" and re.search(r"admin", a.name, re.IGNORECASE)
        ]
        if not roles and entities.get("roles"):
            roles = [{"name": r, "arn": ""} for r in entities["roles"]]
        return {
            "results": {"admin_like_roles": roles, "count": len(roles)},
            "resolved_query": "list_admin_like_roles",
            "suggested_actions": [
                (
                    "cyntrisec can <role> access <resource> --format agent",
                    "Validate least privilege",
                ),
                ("cyntrisec waste --format agent", "Find unused permissions"),
            ],
        }

    if intent == "access_check":
        principal = entities["roles"][0] if entities.get("roles") else None
        target = (
            entities["arns"][0]
            if entities.get("arns")
            else (entities["buckets"][0] if entities.get("buckets") else None)
        )

        # Query graph data for access-related information
        paths = storage.get_attack_paths(snapshot_id)
        assets = storage.get_assets(snapshot_id)

        # Build asset lookup for matching targets
        asset_lookup = {}
        for a in assets:
            asset_lookup[str(a.id)] = a
            if a.arn:
                asset_lookup[a.arn.lower()] = a
            if a.name:
                asset_lookup[a.name.lower()] = a
            if a.aws_resource_id:
                asset_lookup[a.aws_resource_id.lower()] = a

        # Find paths to/from the target
        relevant_paths = []
        if target:
            target_lower = target.lower()
            for p in paths:
                target_asset = asset_lookup.get(str(p.target_asset_id))
                source_asset = asset_lookup.get(str(p.source_asset_id))

                # Check if target matches the path's target or source
                target_matches = target_asset and (
                    target_lower in (target_asset.arn or "").lower()
                    or target_lower in (target_asset.name or "").lower()
                    or target_lower in (target_asset.aws_resource_id or "").lower()
                )
                source_matches = source_asset and (
                    target_lower in (source_asset.arn or "").lower()
                    or target_lower in (source_asset.name or "").lower()
                    or target_lower in (source_asset.aws_resource_id or "").lower()
                )

                if target_matches or source_matches:
                    relevant_paths.append(p)

        target_display = target or query

        # If we found relevant paths, return graph results
        if relevant_paths:
            top_paths = sorted(relevant_paths, key=lambda p: float(p.risk_score), reverse=True)[:5]
            return {
                "results": {
                    "paths_to_target": len(relevant_paths),
                    "target": target_display,
                    "top_paths": [
                        {
                            "attack_vector": p.attack_vector,
                            "risk_score": float(p.risk_score),
                            "source": str(p.source_asset_id),
                            "target": str(p.target_asset_id),
                            "path_length": p.path_length,
                        }
                        for p in top_paths
                    ],
                },
                "resolved_query": "graph_access_check",
                "suggested_actions": [
                    ("cyntrisec analyze paths --format agent", "View all attack paths"),
                    ("cyntrisec cuts --format agent", "Get remediations to block paths"),
                    (
                        f"cyntrisec can <principal> access {target or '<resource>'} --live --format agent",
                        "Run live access simulation for precise results",
                    ),
                ],
            }

        # No paths found - return helpful response with graph context
        principal_display = principal or "<principal>"
        resource_display = target_display
        return {
            "results": {
                "paths_to_target": 0,
                "target": target_display,
                "message": f"No attack paths found to '{target_display}' in the graph.",
            },
            "resolved_query": "graph_access_check",
            "suggested_actions": [
                (
                    f"cyntrisec can {principal_display} access {resource_display} --live --format agent",
                    "Run live access simulation",
                ),
                ("cyntrisec analyze paths --format agent", "View all attack paths"),
            ],
        }

    if intent == "waste":
        return {
            "results": {"message": "Analyze unused permissions to reduce blast radius."},
            "resolved_query": "waste_candidates",
            "suggested_actions": [
                ("cyntrisec waste --format agent", "Find unused permissions"),
            ],
        }

    if intent == "compliance":
        return {
            "results": {"message": "Run compliance checks with 'cyntrisec comply --format agent'."},
            "resolved_query": "compliance_check",
            "suggested_actions": [
                ("cyntrisec comply --format agent", "Check CIS/SOC2 compliance"),
                (
                    "cyntrisec explain control CIS-AWS:1.1 --format agent",
                    "Explain specific controls",
                ),
            ],
        }

    return {
        "results": {
            "message": "Query understood. Use analyze paths/findings, cuts, can, or comply for details."
        },
        "resolved_query": "general_help",
        "suggested_actions": [
            ("cyntrisec analyze paths --format agent", "View attack paths"),
            ("cyntrisec analyze findings --format agent", "Review findings by severity"),
        ],
    }


def _print_text_response(query: str, intent: str, response: dict, snapshot):
    """Render a simple text response."""
    console.print()
    console.print(
        Panel(
            f"Query: {query}\n"
            f"Intent: {intent}\n"
            f"Snapshot: {snapshot.aws_account_id if snapshot else 'unknown'}",
            title="cyntrisec ask",
            border_style="cyan",
        )
    )

    results = response.get("results", {})
    if intent == "attack_paths":
        paths = results.get("attack_paths", [])
        if not paths:
            console.print("[yellow]No attack paths found.[/yellow]")
        else:
            for p in paths:
                console.print(f"- {p['attack_vector']} (risk {p['risk_score']:.2f})")
    elif intent == "public_s3":
        buckets = results.get("public_buckets", [])
        if not buckets:
            console.print("[yellow]No public buckets detected by heuristics.[/yellow]")
        else:
            for b in buckets:
                console.print(f"- {b['name']} ({b['arn']})")
    elif intent == "admin_roles":
        roles = results.get("admin_like_roles", [])
        if not roles:
            console.print("[yellow]No admin-like roles detected by name pattern.[/yellow]")
        else:
            for r in roles:
                console.print(f"- {r['name']} ({r['arn']})")
    else:
        console.print(results.get("message", ""))

    console.print()
    console.print("[dim]Use --format agent for structured responses and follow-ups.[/dim]")
