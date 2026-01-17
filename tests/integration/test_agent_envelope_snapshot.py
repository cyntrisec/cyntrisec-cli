from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

from cyntrisec.cli.analyze import analyze_paths


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
        "tags": {},
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
        "tags": {},
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


def test_agent_envelope_with_artifacts(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    scan_id = _write_snapshot(tmp_path)

    analyze_paths.callback = analyze_paths  # appease pylance
    analyze_paths(scan_id=scan_id, min_risk=0.0, limit=10, format="agent")
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert payload["schema_version"]
    assert payload["status"] == "success"
    assert "artifact_paths" in payload and payload["artifact_paths"]
    assert "paths" in payload["data"]
