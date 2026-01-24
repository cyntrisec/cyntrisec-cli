"""
Shared output utilities for Cyntrisec CLI commands.

Provides:
- Format detection that defaults to JSON when stdout is not a TTY
- Agent format envelope with suggested actions
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Sequence

import typer
from pydantic import BaseModel

from cyntrisec.cli.schemas import (
    ActionModel,
    AgentEnvelope,
    ArtifactPathsModel,
)

Action = dict[str, str]
SCHEMA_VERSION = "1.0"

# Error taxonomy (keep small and stable)
AWS_ACCESS_DENIED = "AWS_ACCESS_DENIED"
AWS_THROTTLED = "AWS_THROTTLED"
AWS_REGION_DISABLED = "AWS_REGION_DISABLED"
SNAPSHOT_NOT_FOUND = "SNAPSHOT_NOT_FOUND"
SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
INVALID_QUERY = "INVALID_QUERY"
INTERNAL_ERROR = "INTERNAL_ERROR"


def resolve_format(
    format_option: str | None,
    *,
    default_tty: str,
    allowed: Sequence[str],
) -> str:
    """
    Choose an output format, defaulting to JSON when stdout is piped.
    """
    chosen = format_option or ("json" if not sys.stdout.isatty() else default_tty)

    if chosen not in allowed:
        raise typer.BadParameter(f"Invalid format '{chosen}'. Choose from {', '.join(allowed)}")

    return chosen


def suggested_actions(actions: Iterable[tuple[str, str]]) -> list[Action]:
    """Normalize suggested actions to a list of dicts."""
    return [
        {"command": command, "reason": reason} for command, reason in actions if command and reason
    ]


def emit_agent_or_json(
    format: str,
    data: dict[str, Any],
    *,
    suggested: Sequence[Action] | None = None,
    status: str = "success",
    artifact_paths: dict[str, str] | None = None,
    error_code: str | None = None,
    message: str | None = None,
    schema: type[BaseModel] | None = None,
) -> None:
    """
    Emit JSON or agent-formatted output to stdout.
    """
    validated_data: object = data
    if schema:
        validated_data = schema.model_validate(data).model_dump(mode="json")

    actions: list[ActionModel] | None = (
        [ActionModel.model_validate(a) for a in suggested] if suggested else None
    )
    artifacts_model: ArtifactPathsModel | None = (
        ArtifactPathsModel.model_validate(artifact_paths) if artifact_paths else None
    )

    envelope = AgentEnvelope(
        schema_version=SCHEMA_VERSION,
        status=status,
        message=message,
        error_code=error_code,
        data=validated_data,
        artifact_paths=artifacts_model,
        suggested_actions=actions,
    )
    typer.echo(json.dumps(envelope.model_dump(mode="json"), indent=2, default=str))


def build_artifact_paths(storage, snapshot_id: str | None) -> dict[str, str] | None:
    """Return key artifact paths for a snapshot, if available."""
    try:
        # Resolve the identifier to a scan_id first
        resolved_id = storage.resolve_scan_id(snapshot_id)
        if not resolved_id:
            return None
        scan_dir = storage.get_scan_path(resolved_id)
    except Exception:
        return None
    if not scan_dir:
        return None
    return {
        "snapshot_dir": str(scan_dir),
        "snapshot": str(scan_dir / "snapshot.json"),
        "assets": str(scan_dir / "assets.json"),
        "relationships": str(scan_dir / "relationships.json"),
        "attack_paths": str(scan_dir / "attack_paths.json"),
        "findings": str(scan_dir / "findings.json"),
    }
