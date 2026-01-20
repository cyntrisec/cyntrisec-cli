"""
Regression tests for v0.1.4 bug fixes.
"""

from __future__ import annotations

import json
import re
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import typer
from typer.testing import CliRunner

from cyntrisec.aws.collectors.usage import RoleUsageReport, ServiceAccess
from cyntrisec.aws.normalizers.network import NetworkNormalizer
from cyntrisec.aws.normalizers.s3 import S3Normalizer
from cyntrisec.aws.relationship_builder import RelationshipBuilder
from cyntrisec.cli.ask import ask_cmd
from cyntrisec.cli.can import can_cmd
from cyntrisec.cli.comply import comply_cmd
from cyntrisec.cli.cuts import cuts_cmd
from cyntrisec.cli.diff import diff_cmd
from cyntrisec.cli.main import app
from cyntrisec.cli.remediate import _terraform_snippet, remediate_cmd
from cyntrisec.cli.schemas import ScanResponse
from cyntrisec.cli.setup import setup_iam
from cyntrisec.cli.waste import waste_cmd
from cyntrisec.core.compliance import ComplianceChecker
from cyntrisec.core.cost_estimator import CostEstimator
from cyntrisec.core.schema import Asset, Snapshot, SnapshotStatus
from cyntrisec.core.waste import WasteAnalyzer
from cyntrisec.mcp.server import SessionState


SCAN_ID_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{6}_\d{12}$")


def _asset_dict(
    snapshot_id: str,
    asset_type: str,
    name: str,
    *,
    aws_resource_id: str | None = None,
    arn: str | None = None,
    properties: dict | None = None,
    aws_region: str = "us-east-1",
    is_internet_facing: bool = False,
    is_sensitive_target: bool = False,
) -> tuple[str, dict]:
    asset_id = str(uuid.uuid4())
    return asset_id, {
        "id": asset_id,
        "snapshot_id": snapshot_id,
        "asset_type": asset_type,
        "aws_region": aws_region,
        "aws_resource_id": aws_resource_id or name,
        "arn": arn,
        "name": name,
        "properties": properties or {},
        "tags": {},
        "is_internet_facing": is_internet_facing,
        "is_sensitive_target": is_sensitive_target,
    }


def _relationship_dict(
    snapshot_id: str,
    source_id: str,
    target_id: str,
    relationship_type: str,
) -> tuple[str, dict]:
    rel_id = str(uuid.uuid4())
    return rel_id, {
        "id": rel_id,
        "snapshot_id": snapshot_id,
        "source_asset_id": source_id,
        "target_asset_id": target_id,
        "relationship_type": relationship_type,
        "properties": {},
        "traversal_cost": 1.0,
    }


def _path_dict(
    snapshot_id: str,
    source_id: str,
    target_id: str,
    rel_ids: list[str],
) -> tuple[str, dict]:
    path_id = str(uuid.uuid4())
    return path_id, {
        "id": path_id,
        "snapshot_id": snapshot_id,
        "source_asset_id": source_id,
        "target_asset_id": target_id,
        "path_asset_ids": [source_id, target_id],
        "path_relationship_ids": rel_ids,
        "attack_vector": "test-vector",
        "path_length": 1,
        "entry_confidence": 1.0,
        "exploitability_score": 1.0,
        "impact_score": 1.0,
        "risk_score": 0.8,
        "proof": {},
    }


def _write_scan(
    tmp_path: Path,
    *,
    scan_id: str | None = None,
    snapshot_id: str | None = None,
    assets: list[dict] | None = None,
    relationships: list[dict] | None = None,
    paths: list[dict] | None = None,
    findings: list[dict] | None = None,
    errors: list[dict] | None = None,
) -> tuple[str, str]:
    scan_id = scan_id or "2026-01-20_000000_123456789012"
    snapshot_id = snapshot_id or str(uuid.uuid4())
    assets = assets or []
    relationships = relationships or []
    paths = paths or []
    findings = findings or []

    scans_dir = tmp_path / ".cyntrisec" / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    scan_dir = scans_dir / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    snapshot = {
        "id": snapshot_id,
        "aws_account_id": "123456789012",
        "regions": ["us-east-1"],
        "status": "completed",
        "asset_count": len(assets),
        "relationship_count": len(relationships),
        "finding_count": len(findings),
        "path_count": len(paths),
        "scan_params": {},
        "started_at": datetime.utcnow().isoformat() + "Z",
        "completed_at": datetime.utcnow().isoformat() + "Z",
    }
    if errors is not None:
        snapshot["errors"] = errors

    (scan_dir / "snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")
    (scan_dir / "assets.json").write_text(json.dumps(assets), encoding="utf-8")
    (scan_dir / "relationships.json").write_text(json.dumps(relationships), encoding="utf-8")
    (scan_dir / "attack_paths.json").write_text(json.dumps(paths), encoding="utf-8")
    (scan_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

    latest = scans_dir / "latest"
    latest.write_text(scan_id, encoding="utf-8")
    return scan_id, snapshot_id


def _write_basic_scan(tmp_path: Path, *, scan_id: str | None = None, include_finding: bool = False):
    snapshot_id = str(uuid.uuid4())
    policy_docs = [{
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "rds:DescribeDBInstances"], "Resource": "*"}
        ]
    }]

    role_id, role_asset = _asset_dict(
        snapshot_id,
        "iam:role",
        "AppRole",
        aws_resource_id="arn:aws:iam::123456789012:role/AppRole",
        arn="arn:aws:iam::123456789012:role/AppRole",
        properties={"policy_documents": policy_docs},
    )
    bucket_id, bucket_asset = _asset_dict(
        snapshot_id,
        "s3:bucket",
        "data-bucket",
        aws_resource_id="arn:aws:s3:::data-bucket",
        arn="arn:aws:s3:::data-bucket",
    )
    entry_id, entry_asset = _asset_dict(
        snapshot_id,
        "ec2:instance",
        "entry",
        aws_resource_id="i-123",
        arn="arn:aws:ec2:us-east-1:123456789012:instance/i-123",
        is_internet_facing=True,
    )
    db_id, db_asset = _asset_dict(
        snapshot_id,
        "rds:db-instance",
        "db",
        aws_resource_id="db-123",
        arn="arn:aws:rds:us-east-1:123456789012:db:db-123",
        is_sensitive_target=True,
        properties={"db_instance_class": "db.t3.micro"},
    )

    rel_can_id, rel_can = _relationship_dict(snapshot_id, role_id, bucket_id, "MAY_ACCESS")
    rel_path_id, rel_path = _relationship_dict(
        snapshot_id, entry_id, db_id, "ALLOWS_TRAFFIC_TO"
    )
    _, path = _path_dict(snapshot_id, entry_id, db_id, [rel_path_id])

    findings = []
    if include_finding:
        findings.append(
            {
                "id": str(uuid.uuid4()),
                "snapshot_id": snapshot_id,
                "asset_id": bucket_id,
                "finding_type": "s3-bucket-public-acl",
                "severity": "high",
                "title": "Test Finding",
            }
        )

    scan_id, snapshot_id = _write_scan(
        tmp_path,
        scan_id=scan_id,
        snapshot_id=snapshot_id,
        assets=[role_asset, bucket_asset, entry_asset, db_asset],
        relationships=[rel_can, rel_path],
        paths=[path],
        findings=findings,
    )
    return scan_id, snapshot_id


def test_scan_json_output_validates_schema(monkeypatch, capsys):
    from cyntrisec.cli import scan as scan_mod

    snapshot = Snapshot(
        id=uuid.uuid4(),
        aws_account_id="123456789012",
        regions=["us-east-1"],
        status=SnapshotStatus.completed,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        asset_count=1,
        relationship_count=0,
        finding_count=0,
        path_count=0,
    )

    class DummyScanner:
        def __init__(self, storage):
            self.storage = storage

        def scan(self, **kwargs):
            return snapshot

    class DummyStorage:
        def resolve_scan_id(self, snapshot_id=None):
            return "2026-01-20_000000_123456789012"

    import cyntrisec.aws
    monkeypatch.setattr(cyntrisec.aws, "AwsScanner", DummyScanner)
    import cyntrisec.storage
    monkeypatch.setattr(cyntrisec.storage, "FileSystemStorage", DummyStorage)
    monkeypatch.setattr(scan_mod, "build_artifact_paths", lambda *args, **kwargs: None)

    with pytest.raises(typer.Exit):
        scan_mod.scan_cmd(format="json", regions="us-east-1")

    payload = json.loads(capsys.readouterr().out)
    ScanResponse.model_validate(payload["data"])


def test_json_mode_no_stdout_pollution(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    scan_id, _ = _write_basic_scan(tmp_path)

    with pytest.raises(typer.Exit):
        can_cmd(
            principal="AppRole",
            access="access",
            resource="arn:aws:s3:::data-bucket",
            action=None,
            live=False,
            role_arn=None,
            external_id=None,
            format="json",
            snapshot_id=scan_id,
        )
    json.loads(capsys.readouterr().out)

    waste_cmd(
        days=90,
        live=False,
        role_arn=None,
        external_id=None,
        format="json",
        cost_source="estimate",
        max_roles=20,
        snapshot_id=scan_id,
    )
    json.loads(capsys.readouterr().out)

    setup_iam(
        account_id="123456789012",
        role_name="CyntrisecReadOnly",
        external_id=None,
        format="policy",
        output=None,
        output_format="json",
    )
    json.loads(capsys.readouterr().out)

    with pytest.raises(typer.Exit):
        remediate_cmd(
            max_cuts=3,
            dry_run=False,
            apply=False,
            terraform_output=None,
            terraform_dir=None,
            execute_terraform=False,
            terraform_plan=False,
            terraform_cmd="terraform",
            enable_unsafe_write_mode=False,
            yes=False,
            output=None,
            snapshot_id=scan_id,
            format="json",
        )
    json.loads(capsys.readouterr().out)


def test_remediate_terraform_plan_skips_confirmation(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    scan_id, _ = _write_basic_scan(tmp_path)

    def fail_confirm(*args, **kwargs):
        raise AssertionError("confirm should not be called for terraform-plan")

    monkeypatch.setattr("cyntrisec.cli.remediate.typer.confirm", fail_confirm)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = b"Plan: 0 to add, 0 to change, 0 to destroy."
        result.stderr = b""
        return result

    monkeypatch.setattr("subprocess.run", mock_run)

    with pytest.raises(typer.Exit) as exc:
        remediate_cmd(
            max_cuts=3,
            dry_run=False,
            apply=False,
            terraform_output=str(tmp_path / "tf" / "main.tf"),
            terraform_dir=str(tmp_path / "tf"),
            execute_terraform=False,
            terraform_plan=True,
            terraform_cmd="terraform",
            enable_unsafe_write_mode=True,
            yes=False,
            output=str(tmp_path / "plan.json"),
            snapshot_id=scan_id,
            format="json",
        )
    assert exc.value.exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["apply"]["mode"] == "terraform-plan"


def test_terraform_snippets_are_basic_hcl():
    def assert_balanced(snippet: str):
        depth = 0
        for ch in snippet:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                assert depth >= 0
        assert depth == 0
        assert "<" not in snippet

    snippet = _terraform_snippet("restrict", "source", "target", "ALLOWS_TRAFFIC_TO")
    assert "aws_security_group_rule" in snippet
    assert_balanced(snippet)

    snippet = _terraform_snippet("restrict", "source", "target", "MAY_ACCESS")
    assert 'data "aws_iam_policy_document"' in snippet
    assert "resources" in snippet
    assert_balanced(snippet)

    snippet = _terraform_snippet("restrict", "source", "target", "CAN_ASSUME")
    assert "principals" in snippet
    assert "identifiers" in snippet
    assert_balanced(snippet)


def test_aws_managed_roles_filtered_from_waste():
    snapshot_id = uuid.uuid4()
    analyzer = WasteAnalyzer()
    assets = [
        Asset(
            snapshot_id=snapshot_id,
            asset_type="iam:role",
            aws_resource_id="arn:aws:iam::123456789012:role/AWSServiceRoleForEC2",
            arn="arn:aws:iam::123456789012:role/AWSServiceRoleForEC2",
            name="AWSServiceRoleForEC2",
            properties={},
        ),
        Asset(
            snapshot_id=snapshot_id,
            asset_type="iam:role",
            aws_resource_id="arn:aws:iam::123456789012:role/AWSReservedSSO_ReadOnly",
            arn="arn:aws:iam::123456789012:role/AWSReservedSSO_ReadOnly",
            name="AWSReservedSSO_ReadOnly",
            properties={},
        ),
        Asset(
            snapshot_id=snapshot_id,
            asset_type="iam:role",
            aws_resource_id="arn:aws:iam::123456789012:role/AppRole",
            arn="arn:aws:iam::123456789012:role/AppRole",
            name="AppRole",
            properties={
                "policy_documents": [
                    {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
                ]
            },
        ),
    ]

    report = analyzer.analyze_from_assets(assets)
    assert len(report.role_reports) == 1
    assert report.role_reports[0].role_name == "AppRole"


def test_offline_waste_counts_services():
    snapshot_id = uuid.uuid4()
    analyzer = WasteAnalyzer()
    assets = [
        Asset(
            snapshot_id=snapshot_id,
            asset_type="iam:role",
            aws_resource_id="arn:aws:iam::123456789012:role/AppRole",
            arn="arn:aws:iam::123456789012:role/AppRole",
            name="AppRole",
            properties={
                "policy_documents": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:GetObject", "ec2:DescribeInstances"],
                                "Resource": "*",
                            }
                        ]
                    }
                ]
            },
        )
    ]

    report = analyzer.analyze_from_assets(assets)
    assert report.role_reports
    role_report = report.role_reports[0]
    assert role_report.total_services == 2
    assert role_report.unused_capabilities
    assert role_report.unused_capabilities[0].recommendation


def test_ask_access_check_returns_graph_results(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    scan_id, _ = _write_basic_scan(tmp_path)

    with pytest.raises(typer.Exit):
        ask_cmd(
            query="can AppRole access arn:aws:rds:us-east-1:123456789012:db:db-123",
            snapshot_id=scan_id,
            format="json",
        )
    payload = json.loads(capsys.readouterr().out)
    results = payload["data"]["results"]
    assert results["paths_to_target"] == 1
    assert results["target"] == "arn:aws:rds:us-east-1:123456789012:db:db-123"


def test_suggested_actions_use_correct_identifiers(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    scan_id, snapshot_id = _write_basic_scan(tmp_path, include_finding=True)
    scan_id_new, _ = _write_basic_scan(
        tmp_path, scan_id="2026-01-21_000000_123456789012"
    )

    def assert_identifier_formats(actions):
        for action in actions:
            cmd = action.get("command", "")
            parts = cmd.split()
            for idx, part in enumerate(parts):
                if part == "--scan" and idx + 1 < len(parts):
                    assert SCAN_ID_PATTERN.match(parts[idx + 1])
                if part == "--snapshot" and idx + 1 < len(parts):
                    uuid.UUID(parts[idx + 1])

    with pytest.raises(typer.Exit):
        can_cmd(
            principal="AppRole",
            access="access",
            resource="arn:aws:s3:::data-bucket",
            action=None,
            live=False,
            role_arn=None,
            external_id=None,
            format="json",
            snapshot_id=scan_id,
        )
    payload = json.loads(capsys.readouterr().out)
    assert_identifier_formats(payload.get("suggested_actions", []))

    with pytest.raises(typer.Exit):
        can_cmd(
            principal="AppRole",
            access="access",
            resource="arn:aws:s3:::missing-bucket",
            action=None,
            live=False,
            role_arn=None,
            external_id=None,
            format="json",
            snapshot_id=scan_id,
        )
    payload = json.loads(capsys.readouterr().out)
    assert_identifier_formats(payload.get("suggested_actions", []))

    cuts_cmd(
        max_cuts=3,
        format="json",
        snapshot_id=scan_id,
        cost_source="estimate",
    )
    payload = json.loads(capsys.readouterr().out)
    assert_identifier_formats(payload.get("suggested_actions", []))

    with pytest.raises(typer.Exit):
        comply_cmd(
            framework="cis-aws",
            format="json",
            show_passing=False,
            snapshot_id=scan_id,
        )
    payload = json.loads(capsys.readouterr().out)
    assert_identifier_formats(payload.get("suggested_actions", []))

    with pytest.raises(typer.Exit):
        diff_cmd(
            old_snapshot=scan_id,
            new_snapshot=scan_id_new,
            format="json",
            show_all=False,
        )
    payload = json.loads(capsys.readouterr().out)
    assert_identifier_formats(payload.get("suggested_actions", []))


def test_scan_help_includes_role_session_name():
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--role-session-name" in result.stdout


def test_offline_can_payload_has_disclaimer_and_no_action(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    scan_id, _ = _write_basic_scan(tmp_path)

    with pytest.raises(typer.Exit):
        can_cmd(
            principal="AppRole",
            access="access",
            resource="arn:aws:s3:::data-bucket",
            action=None,
            live=False,
            role_arn=None,
            external_id=None,
            format="json",
            snapshot_id=scan_id,
        )
    payload = json.loads(capsys.readouterr().out)
    data = payload["data"]
    assert data["mode"] == "offline"
    assert "--live" in data["disclaimer"]
    assert data["action"] is None


def test_compliance_missing_data_and_gaps():
    checker = ComplianceChecker()
    snapshot_id = uuid.uuid4()
    assets = [
        Asset(snapshot_id=snapshot_id, asset_type="iam:user", aws_resource_id="user-1", name="user-1"),
        Asset(snapshot_id=snapshot_id, asset_type="iam:role", aws_resource_id="role-1", name="role-1"),
    ]
    report = checker.check([], assets)
    assert report.unknown > 0
    assert "CIS-AWS:2.1.1" in report.data_gaps

    s3_assets = assets + [
        Asset(
            snapshot_id=snapshot_id,
            asset_type="s3:bucket",
            aws_resource_id="arn:aws:s3:::bucket",
            name="bucket",
        )
    ]
    report = checker.check([], s3_assets, collection_errors=[{"service": "s3"}])
    assert report.data_gaps
    assert any(gap["reason"] == "collection_error" for gap in report.data_gaps.values())


def test_compliance_mapping_coverage():
    from cyntrisec.core.compliance import FINDING_TO_CONTROLS

    for finding_type in [
        "ec2-imdsv1-enabled",
        "s3-bucket-no-public-access-block",
        "s3-bucket-public-acl",
        "s3-bucket-authenticated-users-acl",
        "iam-role-trust-any-principal",
    ]:
        assert finding_type in FINDING_TO_CONTROLS


def test_s3_bucket_policy_public_detection():
    snapshot_id = uuid.uuid4()
    normalizer = S3Normalizer(snapshot_id)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-bucket/*",
            }
        ],
    }
    assets, _, findings = normalizer.normalize({"buckets": [{"Name": "public-bucket", "Policy": policy}]})
    assert any(f.finding_type == "s3-bucket-public-policy" for f in findings)


def test_security_group_ipv6_open_detection():
    snapshot_id = uuid.uuid4()
    normalizer = NetworkNormalizer(snapshot_id, "us-east-1", "123456789012")
    _, _, findings = normalizer.normalize(
        {
            "security_groups": [
                {
                    "GroupId": "sg-123",
                    "GroupName": "test-sg",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpProtocol": "tcp",
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        }
                    ],
                }
            ]
        }
    )
    assert any(f.finding_type == "security-group-open-to-world" for f in findings)


def test_instance_profile_relationship_uses_arn():
    snapshot_id = uuid.uuid4()
    instance = Asset(
        snapshot_id=snapshot_id,
        asset_type="ec2:instance",
        aws_resource_id="i-123",
        arn="arn:aws:ec2:us-east-1:123456789012:instance/i-123",
        name="web",
        properties={"iam_instance_profile": "arn:aws:iam::123456789012:instance-profile/WebProfile"},
    )
    profile = Asset(
        snapshot_id=snapshot_id,
        asset_type="iam:instance-profile",
        aws_resource_id="arn:aws:iam::123456789012:instance-profile/WebProfile",
        arn="arn:aws:iam::123456789012:instance-profile/WebProfile",
        name="WebProfile",
        properties={
            "role_arns": ["arn:aws:iam::123456789012:role/WebRole"],
        },
    )
    role = Asset(
        snapshot_id=snapshot_id,
        asset_type="iam:role",
        aws_resource_id="arn:aws:iam::123456789012:role/WebRole",
        arn="arn:aws:iam::123456789012:role/WebRole",
        name="WebRole",
        properties={},
    )
    unrelated_role = Asset(
        snapshot_id=snapshot_id,
        asset_type="iam:role",
        aws_resource_id="arn:aws:iam::123456789012:role/WebProfileAdmin",
        arn="arn:aws:iam::123456789012:role/WebProfileAdmin",
        name="WebProfileAdmin",
        properties={},
    )

    builder = RelationshipBuilder(snapshot_id)
    relationships = builder.build([instance, profile, role, unrelated_role])
    targets = {r.target_asset_id for r in relationships if r.relationship_type == "CAN_ASSUME"}
    assert role.id in targets
    assert unrelated_role.id not in targets


def test_may_access_edges_require_policy_evidence():
    snapshot_id = uuid.uuid4()
    role = Asset(
        snapshot_id=snapshot_id,
        asset_type="iam:role",
        aws_resource_id="arn:aws:iam::123456789012:role/AppRole",
        arn="arn:aws:iam::123456789012:role/AppRole",
        name="AppRole",
        properties={
            "policy_documents": [
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::sensitive-bucket",
                        }
                    ]
                }
            ]
        },
    )
    instance_profile = Asset(
        snapshot_id=snapshot_id,
        asset_type="iam:instance-profile",
        aws_resource_id="arn:aws:iam::123456789012:instance-profile/AppProfile",
        arn="arn:aws:iam::123456789012:instance-profile/AppProfile",
        name="AppProfile",
        properties={"role_arns": [role.arn]},
    )
    instance = Asset(
        snapshot_id=snapshot_id,
        asset_type="ec2:instance",
        aws_resource_id="i-123",
        arn="arn:aws:ec2:us-east-1:123456789012:instance/i-123",
        name="app",
        properties={"iam_instance_profile": instance_profile.arn},
    )
    target = Asset(
        snapshot_id=snapshot_id,
        asset_type="s3:bucket",
        aws_resource_id="arn:aws:s3:::sensitive-bucket",
        arn="arn:aws:s3:::sensitive-bucket",
        name="sensitive-bucket",
        is_sensitive_target=True,
    )

    builder = RelationshipBuilder(snapshot_id)
    rels = builder.build([role, instance_profile, instance, target])
    assert any(r.relationship_type == "MAY_ACCESS" for r in rels)

    role.properties["policy_documents"] = []
    rels = RelationshipBuilder(snapshot_id).build([role, instance_profile, instance, target])
    assert not any(r.relationship_type == "MAY_ACCESS" for r in rels)


def test_cost_estimator_region_fallback_note():
    snapshot_id = uuid.uuid4()
    asset = Asset(
        snapshot_id=snapshot_id,
        asset_type="ec2:nat-gateway",
        aws_resource_id="nat-123",
        name="nat-123",
        aws_region="eu-west-3",
    )
    estimator = CostEstimator(source="estimate")
    estimate = estimator.estimate(asset)
    assert estimate is not None
    assert any("Pricing fallback: us-east-1" in a for a in estimate.assumptions)


def test_unknown_rds_class_returns_estimate():
    snapshot_id = uuid.uuid4()
    asset = Asset(
        snapshot_id=snapshot_id,
        asset_type="rds:db-instance",
        aws_resource_id="db-123",
        name="db-123",
        properties={"db_instance_class": "db.m8.unknown"},
    )
    estimator = CostEstimator(source="estimate")
    estimate = estimator.estimate(asset)
    assert estimate is not None
    assert estimate.monthly_cost_usd_estimate > 0
    assert estimate.confidence == "unknown"


def test_waste_cost_source_behavior(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    snapshot_id = str(uuid.uuid4())

    _, rds_asset = _asset_dict(
        snapshot_id,
        "rds:db-instance",
        "db-1",
        aws_resource_id="db-1",
        arn="arn:aws:rds:us-east-1:123456789012:db:db-1",
        properties={"db_instance_class": "db.t3.micro"},
    )
    scan_id, _ = _write_scan(tmp_path, snapshot_id=snapshot_id, assets=[rds_asset])

    usage = RoleUsageReport(
        role_arn="arn:aws:iam::123456789012:role/AppRole",
        role_name="AppRole",
        services=[
            ServiceAccess(service_name="Amazon RDS", service_namespace="rds", last_authenticated=None)
        ],
    )

    monkeypatch.setattr("cyntrisec.cli.waste._collect_live_usage", lambda *a, **k: [usage])

    waste_cmd(
        days=90,
        live=True,
        role_arn=None,
        external_id=None,
        format="json",
        cost_source="estimate",
        max_roles=20,
        snapshot_id=scan_id,
    )
    payload = json.loads(capsys.readouterr().out)
    capability = payload["data"]["roles"][0]["unused_capabilities"][0]
    assert capability["cost_source"] == "estimate"
    assert capability["monthly_cost_usd_estimate"] > 0


def test_remediate_guardrails_mark_failure(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    scan_id, _ = _write_basic_scan(tmp_path)

    def mock_run(cmd, **kwargs):
        if "apply" in cmd:
            raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output=b"", stderr=b"")
        result = MagicMock()
        result.returncode = 0
        result.stdout = b"ok"
        result.stderr = b""
        return result

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
    monkeypatch.setattr("subprocess.run", mock_run)

    with pytest.raises(typer.Exit):
        remediate_cmd(
            max_cuts=3,
            dry_run=False,
            apply=True,
            terraform_output=str(tmp_path / "tf" / "main.tf"),
            terraform_dir=str(tmp_path / "tf"),
            execute_terraform=True,
            terraform_plan=False,
            terraform_cmd="terraform",
            enable_unsafe_write_mode=True,
            yes=True,
            output=str(tmp_path / "plan.json"),
            snapshot_id=scan_id,
            format="json",
        )
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "terraform_failed"
    assert payload["data"]["applied"] is False


def test_mcp_snapshot_resolution_accepts_uuid(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    scan_id, snapshot_id = _write_basic_scan(tmp_path)

    session = SessionState()
    resolved = session.set_snapshot(snapshot_id)
    assert resolved == scan_id
    snap = session.get_snapshot(snapshot_id)
    assert snap is not None
    assert str(snap.id) == snapshot_id
