from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
import typer

from cyntrisec.cli.analyze import analyze_paths, analyze_business
from cyntrisec.cli.remediate import remediate_cmd
from cyntrisec.cli.manifest import manifest_cmd
from cyntrisec.cli.errors import ErrorCode, EXIT_CODE_MAP
from cyntrisec.cli.schemas import RemediateResponse


def _write_snapshot(tmp_home: Path) -> str:
    scans = tmp_home / ".cyntrisec" / "scans"
    scans.mkdir(parents=True, exist_ok=True)
    scan_id = "2026-01-17_000000_123456789012"
    scan_dir = scans / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    snap_uuid = str(uuid.uuid4())
    asset1 = str(uuid.uuid4())
    asset2 = str(uuid.uuid4())
    rel1 = str(uuid.uuid4())
    path1 = str(uuid.uuid4())

    (scan_dir / "snapshot.json").write_text(json.dumps({
        "id": snap_uuid,
        "aws_account_id": "123456789012",
        "regions": ["us-east-1"],
        "status": "completed",
        "asset_count": 2,
        "relationship_count": 1,
        "finding_count": 0,
        "path_count": 1,
        "scan_params": {},
        "started_at": "2026-01-17T00:00:00Z",
        "completed_at": "2026-01-17T00:01:00Z",
    }), encoding="utf-8")

    (scan_dir / "assets.json").write_text(json.dumps([{
        "id": asset1,
        "snapshot_id": snap_uuid,
        "asset_type": "ec2:instance",
        "aws_region": "us-east-1",
        "aws_resource_id": "i-123",
        "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-123",
        "name": "entry",
        "properties": {},
        "tags": {"Environment": "dev"},
        "is_internet_facing": True,
        "is_sensitive_target": False,
    }, {
        "id": asset2,
        "snapshot_id": snap_uuid,
        "asset_type": "rds:db-instance",
        "aws_region": "us-east-1",
        "aws_resource_id": "db-123",
        "arn": "arn:aws:rds:us-east-1:123456789012:db:db-123",
        "name": "db",
        "properties": {},
        "tags": {"Environment": "prod", "Critical": "true"},
        "is_internet_facing": False,
        "is_sensitive_target": True,
    }]), encoding="utf-8")

    (scan_dir / "relationships.json").write_text(json.dumps([{
        "id": rel1,
        "snapshot_id": snap_uuid,
        "source_asset_id": asset1,
        "target_asset_id": asset2,
        "relationship_type": "CONNECTS_TO",
        "properties": {},
        "traversal_cost": 1.0
    }]), encoding="utf-8")

    (scan_dir / "attack_paths.json").write_text(json.dumps([{
        "id": path1,
        "snapshot_id": snap_uuid,
        "source_asset_id": asset1,
        "target_asset_id": asset2,
        "path_asset_ids": [asset1, asset2],
        "path_relationship_ids": [rel1],
        "attack_vector": "test-vector",
        "path_length": 1,
        "entry_confidence": 1.0,
        "exploitability_score": 1.0,
        "impact_score": 1.0,
        "risk_score": 1.0,
        "proof": {}
    }]), encoding="utf-8")

    (scan_dir / "findings.json").write_text("[]", encoding="utf-8")

    latest = scans / "latest"
    latest.write_text(scan_id, encoding="utf-8")
    return scan_id


def test_analyze_paths_error_envelope(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    with pytest.raises(typer.Exit) as exc:
        analyze_paths(scan_id=None, min_risk=0.0, limit=5, format="agent")
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert exc.value.exit_code == EXIT_CODE_MAP["usage"]
    assert payload["error_code"] == ErrorCode.SNAPSHOT_NOT_FOUND


def test_business_analysis_with_tags(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    scan_id = _write_snapshot(tmp_path)

    analyze_business(
        entrypoints=None,
        business_entrypoint=None,
        business_tags=["Environment=prod,Critical=true"],
        business_config=None,
        report=True,
        scan_id=scan_id,
        format="agent",
        cost_source="estimate",
    )
    payload = json.loads(capsys.readouterr().out)
    data = payload["data"]
    assert data["business_assets"]
    assert data["unknown_assets"] is not None
    assert data["entrypoints_found"]


@pytest.mark.skip(reason="Requires terraform binary which is not available in CI")
def test_remediate_terraform_plan(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    scan_id = _write_snapshot(tmp_path)

    tf_script = tmp_path / "terraform.cmd"
    tf_script.write_text(
        "@echo off\n"
        "set MODE=%3\n"
        "if \"%MODE%\"==\"init\" exit /B 0\n"
        "if \"%MODE%\"==\"plan\" (\n"
        "  echo Plan: 0 to add, 0 to change, 0 to destroy\n"
        "  exit /B 0\n"
        ")\n"
        "if \"%MODE%\"==\"apply\" exit /B 0\n"
        "exit /B 0\n",
        encoding="utf-8",
    )

    with pytest.raises(typer.Exit) as exc:
        remediate_cmd(
            max_cuts=3,
            dry_run=False,
            apply=False,
            terraform_plan=True,
            terraform_cmd=str(tf_script),
            enable_unsafe_write_mode=True,
            yes=True,
            snapshot_id=scan_id,
            format="agent",
        )
    payload = json.loads(capsys.readouterr().out)
    data = RemediateResponse.model_validate(payload["data"])
    assert data.apply is not None
    assert data.apply.plan_exit_code == 0
    assert data.apply.mode == "terraform-plan"
    assert exc.value.exit_code == 0


def test_manifest_includes_response_schemas(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    manifest_cmd(format="agent")
    payload = json.loads(capsys.readouterr().out)
    schemas = payload["data"]["schemas"]["responses"]
    assert "remediate" in schemas
    assert schemas["remediate"]["title"]
