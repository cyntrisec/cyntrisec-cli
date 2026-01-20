from __future__ import annotations

import uuid
from decimal import Decimal

from cyntrisec.cli.remediate import _build_plan, _terraform_snippet
from cyntrisec.core.cuts import MinCutFinder
from cyntrisec.core.graph import GraphBuilder
from cyntrisec.core.schema import Asset, AttackPath, Relationship


def make_asset(snapshot_id, name, asset_type="ec2:instance", is_internet_facing=False, is_sensitive=False):
    return Asset(
        id=uuid.uuid4(),
        snapshot_id=snapshot_id,
        asset_type=asset_type,
        aws_resource_id=name,
        name=name,
        is_internet_facing=is_internet_facing,
        is_sensitive_target=is_sensitive,
    )


def make_rel(snapshot_id, source_id, target_id, rel_type="ALLOWS_TRAFFIC_TO"):
    return Relationship(
        id=uuid.uuid4(),
        snapshot_id=snapshot_id,
        source_asset_id=source_id,
        target_asset_id=target_id,
        relationship_type=rel_type,
    )


def make_path(snapshot_id, source_id, target_id, rel_ids):
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


def test_build_plan_returns_actions_and_terraform_snippets():
    snapshot_id = uuid.uuid4()
    a1 = make_asset(snapshot_id, "entry", is_internet_facing=True)
    a2 = make_asset(snapshot_id, "db", asset_type="rds:db-instance", is_sensitive=True)
    rel = make_rel(snapshot_id, a1.id, a2.id, "ALLOWS_TRAFFIC_TO")
    path = make_path(snapshot_id, a1.id, a2.id, [rel.id])

    graph = GraphBuilder().build(assets=[a1, a2], relationships=[rel])
    result = MinCutFinder().find_cuts(graph, [path], max_cuts=3)
    plan = _build_plan(result, graph)

    assert plan, "Plan should not be empty"
    first = plan[0]
    assert first["terraform"], "Terraform snippet should be present"
    assert "Restrict" in first["terraform"]


def test_terraform_snippet_defaults_to_review():
    snippet = _terraform_snippet("review", "src", "tgt", "UNKNOWN")
    assert "Review" in snippet
