from __future__ import annotations

import json
from pathlib import Path
from decimal import Decimal
import uuid

from cyntrisec.cli.remediate import _apply_plan, _build_plan, _run_terraform
from cyntrisec.core.cuts import MinCutFinder
from cyntrisec.core.graph import GraphBuilder
from cyntrisec.core.schema import Asset, AttackPath, Relationship


def _make_asset(snapshot_id, name, asset_type="ec2:instance", is_internet_facing=False, is_sensitive=False):
    return Asset(
        id=uuid.uuid4(),
        snapshot_id=snapshot_id,
        asset_type=asset_type,
        aws_resource_id=name,
        name=name,
        is_internet_facing=is_internet_facing,
        is_sensitive_target=is_sensitive,
    )


def _make_rel(snapshot_id, source_id, target_id, rel_type="ALLOWS_TRAFFIC_TO"):
    return Relationship(
        id=uuid.uuid4(),
        snapshot_id=snapshot_id,
        source_asset_id=source_id,
        target_asset_id=target_id,
        relationship_type=rel_type,
    )


def _make_path(snapshot_id, source_id, target_id, rel_ids):
    return AttackPath(
        id=uuid.uuid4(),
        snapshot_id=snapshot_id,
        source_asset_id=source_id,
        target_asset_id=target_id,
        path_asset_ids=[source_id, target_id],
        path_relationship_ids=rel_ids,
        attack_vector="test-path",
        path_length=1,
        entry_confidence=Decimal("1.0"),
        exploitability_score=Decimal("1.0"),
        impact_score=Decimal("1.0"),
        risk_score=Decimal("1.0"),
        proof={},
    )


def test_apply_plan_writes_plan_and_terraform(tmp_path: Path):
    snapshot_id = uuid.uuid4()
    a1 = _make_asset(snapshot_id, "entry", is_internet_facing=True)
    a2 = _make_asset(snapshot_id, "db", asset_type="rds:db-instance", is_sensitive=True)
    rel = _make_rel(snapshot_id, a1.id, a2.id, "ALLOWS_TRAFFIC_TO")
    path = _make_path(snapshot_id, a1.id, a2.id, [rel.id])

    graph = GraphBuilder().build(assets=[a1, a2], relationships=[rel])
    result = MinCutFinder().find_cuts(graph, [path])
    plan = _build_plan(result, graph)

    plan_path = tmp_path / "plan.json"
    tf_dir = tmp_path / "tfmod"
    tf_main = tf_dir / "main.tf"

    actions, plan_result = _apply_plan(
        plan,
        snapshot=a1,
        plan_path=str(plan_path),
        tf_dir=str(tf_dir),
        tf_main_path=str(tf_main),
        dry_run=True,
        execute_terraform=False,
        terraform_plan=False,
        terraform_cmd="terraform",
    )

    # Files written
    assert plan_path.exists()
    assert tf_main.exists()

    # Plan contains remediation info
    data = json.loads(plan_path.read_text())
    assert "plan" in data and data["plan"]

    # Actions marked pending_dry_run with terraform path
    assert all(a["status"] == "pending_dry_run" for a in actions)
    assert all(a["terraform_path"] == str(tf_main) for a in actions)
    assert plan_result is None


def test_run_terraform_missing_binary(monkeypatch):
    # Force which to return None to simulate missing terraform
    monkeypatch.setattr("shutil.which", lambda _: None)
    result = _run_terraform("terraform", "dummy_tf_dir")
    assert result["ok"] is False
    assert "not found" in result["error"]
