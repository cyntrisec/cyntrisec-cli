"""
Analyze Commands - Analyze scan results.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

import typer

log = logging.getLogger(__name__)

from cyntrisec.cli.errors import EXIT_CODE_MAP, CyntriError, ErrorCode, handle_errors
from cyntrisec.cli.output import (
    build_artifact_paths,
    emit_agent_or_json,
    resolve_format,
    suggested_actions,
)
from cyntrisec.cli.schemas import (
    AnalyzeFindingsResponse,
    AnalyzePathsResponse,
    BusinessAnalysisResponse,
)
from cyntrisec.core.cost_estimator import CostEstimator
from cyntrisec.core.schema import ConfidenceLevel

analyze_app = typer.Typer(help="Analyze scan results")


@analyze_app.command("paths")
@handle_errors
def analyze_paths(
    scan_id: str | None = typer.Option(
        None,
        "--scan",
        "-s",
        help="Scan ID (default: latest)",
    ),
    min_risk: float = typer.Option(
        0.0,
        "--min-risk",
        help="Minimum risk score (0-1)",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        help="Maximum number of paths to show",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: table, json, agent (defaults to json when piped)",
    ),
    verify: bool = typer.Option(
        False,
        "--verify",
        help="Verify paths using AWS Policy Simulator (requires AWS credentials)",
    ),
):
    """
    Show attack paths from scan results.

    Attack paths are routes from internet-facing entry points
    to sensitive targets through the infrastructure.

    Examples:

        cyntrisec analyze paths --min-risk 0.5

        cyntrisec analyze paths --format json | jq '.paths[:5]'
    """
    from cyntrisec.storage import FileSystemStorage

    storage = FileSystemStorage()
    snapshot = storage.get_snapshot(scan_id)
    if not snapshot:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="No scan data found. Run 'cyntrisec scan' first.",
            exit_code=EXIT_CODE_MAP["usage"],
        )
    paths = storage.get_attack_paths(scan_id)
    output_format = resolve_format(
        format,
        default_tty="table",
        allowed=["table", "json", "agent"],
    )

    # Filter by risk
    if min_risk > 0:
        paths = [p for p in paths if float(p.risk_score) >= min_risk]

    # Sort by risk
    paths.sort(key=lambda p: float(p.risk_score), reverse=True)

    total_paths = len(paths)
    paths = paths[:limit]

    # Verify paths if requested
    if verify:
        from cyntrisec.aws.credentials import CredentialProvider
        from cyntrisec.core.simulator import PolicySimulator

        try:
            # Initialize simulator
            provider = CredentialProvider()
            session = provider.default_session()
            simulator = PolicySimulator(session)

            # Hydrate assets for verification
            all_assets = {a.id: a for a in storage.get_assets(scan_id)}

            typer.echo("Verifying paths with AWS Policy Simulator...", err=True)

            for path in paths:
                if not path.path_asset_ids or len(path.path_asset_ids) < 2:
                    continue

                # Verify last hop if it's a capability edge
                # (Ideally we'd verify the whole chain, but let's start with the immediate impact)
                target_id = path.path_asset_ids[-1]
                source_id = path.path_asset_ids[-2]

                source_asset = all_assets.get(uuid.UUID(str(source_id)))
                target_asset = all_assets.get(uuid.UUID(str(target_id)))

                if not source_asset or not target_asset:
                    continue

                # Only check if source is an IAM principal
                if source_asset.asset_type not in ("iam:role", "iam:user"):
                    continue

                # Find the relationship to get the action
                # We need the graph or relationship list, but storage.get_attack_paths relies on
                # stored paths which usually have IDs. We don't have relationships loaded here easily.
                # However, we can infer action from edge type if we loaded relationships, OR
                # we can try common actions based on target type.

                # For now, let's use the simulator's inference
                try:
                    result = simulator.can_access(
                        principal_arn=source_asset.arn or source_asset.aws_resource_id,
                        target_resource=target_asset.arn or target_asset.aws_resource_id,
                    )

                    if result.can_access:
                        if path.confidence_level != ConfidenceLevel.HIGH:
                            path.confidence_level = ConfidenceLevel.HIGH
                            path.confidence_reason = (
                                f"Verified via AWS Policy Simulator (Action: {result.action})"
                            )
                    else:
                        path.confidence_level = ConfidenceLevel.LOW
                        path.confidence_reason = (
                            "Verification Failed: AWS Policy Simulator denied access"
                        )

                except Exception as ex:
                    log.debug("Path verification failed for %s: %s", path.id, ex)

        except Exception as e:
            typer.echo(f"Verification failed: {e}", err=True)
            # Don't fail the command, just warn

    if output_format in {"json", "agent"}:
        artifact_paths = build_artifact_paths(storage, scan_id)
        data = {
            "paths": [p.model_dump(mode="json") for p in paths],
            "returned": len(paths),
            "total": total_paths,
        }
        snapshot_uuid = str(snapshot.id)
        actions = suggested_actions(
            [
                (
                    f"cyntrisec cuts --snapshot {snapshot_uuid}",
                    "Prioritize fixes that block these paths",
                ),
                (
                    "cyntrisec explain path instance-compromise",
                    "Get human-friendly context for a path",
                ),
            ]
        )
        emit_agent_or_json(
            output_format,
            data,
            suggested=actions,
            artifact_paths=artifact_paths,
            schema=AnalyzePathsResponse,
        )
        return

    # Table format
    if not paths:
        typer.echo("No attack paths found.")
        return

    typer.echo(f"{'Risk':<8} {'Conf':<6} {'Vector':<25} {'Length':<8} {'Entry':<8} {'Impact':<8}")
    typer.echo("-" * 75)

    for p in paths:
        risk = float(p.risk_score)
        conf = (p.confidence_level or "UNK")[:3]
        vector = p.attack_vector[:24]
        length = p.path_length
        entry = float(p.entry_confidence)
        impact = float(p.impact_score)

        # Color coding
        color = None
        if risk >= 0.7:
            color = typer.colors.RED
        elif risk >= 0.4:
            color = typer.colors.YELLOW

        line = f"{risk:<8.3f} {conf:<6} {vector:<25} {length:<8} {entry:<8.3f} {impact:<8.3f}"
        if color:
            typer.secho(line, fg=color)
        else:
            typer.echo(line)

    typer.echo("")
    typer.echo(f"Total: {len(paths)} paths")


@analyze_app.command("findings")
@handle_errors
def analyze_findings(
    scan_id: str | None = typer.Option(
        None,
        "--scan",
        "-s",
        help="Scan ID (default: latest)",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Filter by severity: critical, high, medium, low, info",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: table, json, agent (defaults to json when piped)",
    ),
):
    """
    Show security findings from scan results.
    """
    from cyntrisec.storage import FileSystemStorage

    storage = FileSystemStorage()
    snapshot = storage.get_snapshot(scan_id)
    if not snapshot:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="No scan data found. Run 'cyntrisec scan' first.",
            exit_code=EXIT_CODE_MAP["usage"],
        )
    findings = storage.get_findings(scan_id)
    output_format = resolve_format(
        format,
        default_tty="table",
        allowed=["table", "json", "agent"],
    )

    # Filter by severity
    if severity:
        findings = [f for f in findings if f.severity == severity]

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    if output_format in {"json", "agent"}:
        artifact_paths = build_artifact_paths(storage, scan_id)
        data = {
            "findings": [f.model_dump(mode="json") for f in findings],
            "total": len(findings),
            "filter": severity or "any",
        }
        actions = suggested_actions(
            [
                (
                    f"cyntrisec explain finding {findings[0].finding_type}" if findings else "",
                    "See remediation context for the most common finding" if findings else "",
                ),
                ("cyntrisec comply --format agent", "Map findings to compliance controls"),
            ]
        )
        emit_agent_or_json(
            output_format,
            data,
            suggested=actions,
            artifact_paths=artifact_paths,
            schema=AnalyzeFindingsResponse,
        )
        return

    if not findings:
        typer.echo("No findings found.")
        return

    typer.echo(f"{'Severity':<10} {'Type':<35} {'Title':<50}")
    typer.echo("-" * 95)

    for f in findings:
        sev = f.severity.upper()[:9]
        ftype = f.finding_type[:34]
        title = f.title[:49]
        typer.echo(f"{sev:<10} {ftype:<35} {title:<50}")

    typer.echo("")
    typer.echo(f"Total: {len(findings)} findings")


@analyze_app.command("stats")
@handle_errors
def analyze_stats(
    scan_id: str | None = typer.Option(
        None,
        "--scan",
        "-s",
        help="Scan ID (default: latest)",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: text, json, agent (defaults to json when piped)",
    ),
):
    """
    Show summary statistics for a scan.
    """
    from cyntrisec.storage import FileSystemStorage

    storage = FileSystemStorage()
    output_format = resolve_format(
        format,
        default_tty="text",
        allowed=["text", "json", "agent"],
    )

    snapshot = storage.get_snapshot(scan_id)
    if not snapshot:
        if output_format in {"json", "agent"}:
            from cyntrisec.cli.errors import ErrorCode

            emit_agent_or_json(
                output_format,
                {},
                status="error",
                error_code=ErrorCode.SNAPSHOT_NOT_FOUND.value,
                message="No scan found.",
            )
            raise typer.Exit(2)
        typer.echo("No scan found.", err=True)
        raise typer.Exit(2)

    assets = storage.get_assets(scan_id)
    findings = storage.get_findings(scan_id)
    paths = storage.get_attack_paths(scan_id)
    resolved_scan_id = storage.resolve_scan_id(scan_id)

    if output_format in {"json", "agent"}:
        from cyntrisec.cli.schemas import AnalyzeStatsResponse

        payload = {
            "snapshot_id": str(snapshot.id),
            "scan_id": resolved_scan_id,
            "account_id": snapshot.aws_account_id,
            "asset_count": len(assets),
            "relationship_count": snapshot.relationship_count,
            "finding_count": len(findings),
            "path_count": len(paths),
            "regions": snapshot.regions,
            "status": snapshot.status.value
            if hasattr(snapshot.status, "value")
            else str(snapshot.status),
        }
        actions = suggested_actions(
            [
                (
                    f"cyntrisec analyze paths --scan {resolved_scan_id or 'latest'}",
                    "View attack paths",
                ),
                (
                    f"cyntrisec analyze findings --scan {resolved_scan_id or 'latest'}",
                    "View security findings",
                ),
            ]
        )
        emit_agent_or_json(
            output_format,
            payload,
            suggested=actions,
            artifact_paths=build_artifact_paths(storage, scan_id),
            schema=AnalyzeStatsResponse,
        )
        raise typer.Exit(0)

    typer.echo("=== Scan Statistics ===")
    typer.echo("")
    typer.echo(f"Account: {snapshot.aws_account_id}")
    typer.echo(f"Regions: {', '.join(snapshot.regions)}")
    typer.echo(f"Status: {snapshot.status}")
    typer.echo(f"Started: {snapshot.started_at}")
    typer.echo(f"Completed: {snapshot.completed_at}")
    typer.echo("")

    typer.echo("--- Counts ---")
    typer.echo(f"Assets: {len(assets)}")
    typer.echo(f"Findings: {len(findings)}")
    typer.echo(f"Attack paths: {len(paths)}")
    typer.echo("")

    # Asset types
    asset_types = {}
    for a in assets:
        asset_types[a.asset_type] = asset_types.get(a.asset_type, 0) + 1

    typer.echo("--- Assets by Type ---")
    for t, count in sorted(asset_types.items(), key=lambda x: -x[1])[:10]:
        typer.echo(f"  {t}: {count}")

    # Finding severities
    severities = {}
    for f in findings:
        severities[f.severity] = severities.get(f.severity, 0) + 1

    if severities:
        typer.echo("")
        typer.echo("--- Findings by Severity ---")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severities:
                typer.echo(f"  {sev}: {severities[sev]}")

    # Attack path stats
    if paths:
        risks = [float(p.risk_score) for p in paths]
        typer.echo("")
        typer.echo("--- Attack Paths ---")
        typer.echo(f"  Highest risk: {max(risks):.3f}")
        typer.echo(f"  Average risk: {sum(risks) / len(risks):.3f}")


@analyze_app.command("business")
@handle_errors
def analyze_business(
    entrypoints: str | None = typer.Option(
        None,
        "--entrypoints",
        "-e",
        help="Comma-separated business entrypoint names/arns",
    ),
    business_entrypoint: list[str] | None = typer.Option(
        None,
        "--business-entrypoint",
        "-b",
        help="Repeatable business entrypoint (name or ARN)",
    ),
    business_tags: list[str] | None = typer.Option(
        None,
        "--business-tag",
        help="Tag filters marking business assets (repeatable, key=value or comma-separated)",
    ),
    business_config: str | None = typer.Option(
        None,
        "--business-config",
        help="Path to business config (JSON or YAML) with entrypoints/tags",
    ),
    report: bool = typer.Option(
        False,
        "--report",
        help="Output coverage report for business-required assets",
    ),
    scan_id: str | None = typer.Option(
        None,
        "--scan",
        "-s",
        help="Scan ID (default: latest)",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: table, json, agent (defaults to json when piped)",
    ),
    cost_source: str = typer.Option(
        "estimate",
        "--cost-source",
        help="Cost data source: estimate (static), pricing-api, cost-explorer",
    ),
):
    """
    Analyze business-required entrypoints vs attack-reachable assets.

    Waste ~= attackable assets minus business-required set.
    """
    from cyntrisec.storage import FileSystemStorage

    output_format = resolve_format(
        format,
        default_tty="table",
        allowed=["table", "json", "agent"],
    )

    cost_estimator = CostEstimator(source=cost_source)
    storage = FileSystemStorage()
    assets = storage.get_assets(scan_id)
    snapshot = storage.get_snapshot(scan_id)

    if not assets or not snapshot:
        raise CyntriError(
            error_code=ErrorCode.SNAPSHOT_NOT_FOUND,
            message="No scan data found. Run 'cyntrisec scan' first.",
            exit_code=EXIT_CODE_MAP["usage"],
        )

    # Parse business config from all sources
    config = _parse_business_config(
        entrypoints, business_entrypoint, business_tags, business_config
    )

    # Classify assets
    path_assets = {aid for p in storage.get_attack_paths(scan_id) for aid in p.path_asset_ids}
    analysis = _classify_assets(assets, config, path_assets)

    # Sort waste by cost priority
    sorted_waste = cost_estimator.sort_by_cost_priority(analysis["waste_candidates"])

    # Build result
    result = _build_business_result(
        config, analysis, sorted_waste, path_assets, cost_estimator, report
    )

    if output_format in {"json", "agent"}:
        emit_agent_or_json(
            output_format,
            result,
            suggested=suggested_actions(
                [
                    ("cyntrisec waste --format agent", "Review unused permissions/waste"),
                    (
                        "cyntrisec cuts --format agent",
                        "Prioritize fixes to reduce attackable surface",
                    ),
                    (
                        "cyntrisec analyze business --report --format agent",
                        "Show full business coverage report",
                    ),
                ]
            ),
            artifact_paths=build_artifact_paths(storage, scan_id),
            schema=BusinessAnalysisResponse,
        )
        return

    _output_business_table(analysis)


def _parse_business_config(
    entrypoints: str | None,
    business_entrypoint: list[str] | None,
    business_tags: list[str] | None,
    business_config: str | None,
) -> dict:
    """Parse business configuration from all input sources."""
    entry_list = [e.strip() for e in (entrypoints.split(",") if entrypoints else []) if e.strip()]
    if business_entrypoint:
        entry_list.extend([e for e in business_entrypoint if e])

    tag_filters = _parse_tag_filters(business_tags)
    critical_assets: set = set()

    if business_config:
        cfg_path = Path(business_config)
        if not cfg_path.exists():
            raise CyntriError(
                error_code=ErrorCode.INVALID_QUERY,
                message=f"Business config not found at {business_config}",
                exit_code=EXIT_CODE_MAP["usage"],
            )
        loaded = _load_config_file(cfg_path)
        if isinstance(loaded, dict):
            entry_list.extend([str(e) for e in loaded.get("entrypoints", [])])
            for key, value in (loaded.get("tags", {}) or {}).items():
                tag_filters[str(key)] = str(value)
            critical_assets = {str(item) for item in loaded.get("critical_assets", []) or []}

    return {
        "entry_list": [e for e in entry_list if e],
        "tag_filters": tag_filters,
        "critical_assets": critical_assets,
    }


def _parse_tag_filters(business_tags: list[str] | None) -> dict:
    """Parse tag filters from CLI option."""
    tag_filters: dict[str, str] = {}
    if not business_tags:
        return tag_filters

    for raw in business_tags:
        for pair in raw.split(","):
            if not pair:
                continue
            if "=" not in pair:
                raise CyntriError(
                    error_code=ErrorCode.INVALID_QUERY,
                    message=f"Invalid tag filter '{pair}'. Use key=value.",
                    exit_code=EXIT_CODE_MAP["usage"],
                )
            key, value = pair.split("=", 1)
            tag_filters[key.strip()] = value.strip()

    return tag_filters


def _load_config_file(cfg_path: Path) -> dict:
    """Load YAML or JSON config file."""
    text = cfg_path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except Exception:
        pass
    try:
        import json

        return json.loads(text)
    except Exception:
        raise CyntriError(
            error_code=ErrorCode.SCHEMA_MISMATCH,
            message="Failed to parse business config (expected YAML or JSON).",
            exit_code=EXIT_CODE_MAP["usage"],
        )


def _classify_assets(assets, config: dict, path_assets: set) -> dict:
    """Classify assets into business, attackable, and waste categories."""
    entry_list = config["entry_list"]
    tag_filters = config["tag_filters"]
    critical_assets = config["critical_assets"]

    business_assets = []
    attackable = []
    waste_candidates = []

    for asset in assets:
        attackable_flag = (
            asset.is_internet_facing or asset.is_sensitive_target or asset.id in path_assets
        )
        if attackable_flag:
            attackable.append(asset)

        reasons = _get_business_reasons(asset, entry_list, tag_filters, critical_assets)

        if reasons:
            business_assets.append(
                {
                    "name": asset.name,
                    "asset_type": asset.asset_type,
                    "asset_id": str(asset.id),
                    "reason": ",".join(reasons),
                    "tags": asset.tags,
                }
            )
        elif attackable_flag:
            waste_candidates.append(asset)

    return {
        "business_assets": business_assets,
        "attackable": attackable,
        "waste_candidates": waste_candidates,
    }


def _get_business_reasons(asset, entry_list, tag_filters, critical_assets) -> list:
    """Determine why an asset is considered business-required."""
    reasons = []
    if asset.name in entry_list or (asset.arn and asset.arn in entry_list):
        reasons.append("entrypoint")
    if tag_filters and all(asset.tags.get(k) == v for k, v in tag_filters.items()):
        reasons.append("tags")
    if asset.name in critical_assets or (asset.arn and asset.arn in critical_assets):
        reasons.append("config-critical")
    return reasons


def _build_business_result(
    config, analysis, sorted_waste, path_assets, cost_estimator, report
) -> dict:
    """Build the result dictionary for business analysis."""
    return {
        "entrypoints_requested": config["entry_list"],
        "entrypoints_found": [a["name"] for a in analysis["business_assets"]],
        "attackable_count": len(analysis["attackable"]),
        "business_required_count": len(analysis["business_assets"]),
        "waste_candidates": [
            _build_waste_candidate_dict(a, path_assets, cost_estimator) for a in sorted_waste[:20]
        ],
        "waste_candidate_count": len(analysis["waste_candidates"]),
        "business_assets": analysis["business_assets"] if report else None,
        "unknown_assets": [
            {
                "name": a.name,
                "asset_type": a.asset_type,
                "asset_id": str(a.id),
                "reason": "attackable_not_business",
                "tags": a.tags,
            }
            for a in analysis["waste_candidates"][:20]
        ]
        if report
        else None,
    }


def _output_business_table(analysis: dict) -> None:
    """Output business analysis in table format."""
    typer.echo("=== Business vs Attackable Analysis ===")
    typer.echo(f"Attackable assets: {len(analysis['attackable'])}")
    typer.echo(f"Business-required (provided): {len(analysis['business_assets'])}")
    typer.echo(f"Waste candidates (attackable minus business): {len(analysis['waste_candidates'])}")
    if analysis["waste_candidates"]:
        typer.echo("\nSample waste candidates:")
        for a in analysis["waste_candidates"][:10]:
            typer.echo(f"- {a.name} ({a.asset_type})")


def _build_waste_candidate_dict(asset, path_assets, cost_estimator):
    """Build waste candidate dict with optional cost estimate."""
    result = {
        "name": asset.name,
        "asset_type": asset.asset_type,
        "asset_id": str(asset.id),
        "reason": "in attack paths" if asset.id in path_assets else "internet-facing/sensitive",
        "monthly_cost_usd": float(asset.monthly_cost_usd)
        if getattr(asset, "monthly_cost_usd", None)
        else None,
    }

    if cost_estimator:
        estimate = cost_estimator.estimate(asset)
        if estimate:
            result["monthly_cost_usd_estimate"] = float(estimate.monthly_cost_usd_estimate)
            result["cost_source"] = estimate.cost_source
            result["confidence"] = estimate.confidence
            result["assumptions"] = estimate.assumptions

    return result
