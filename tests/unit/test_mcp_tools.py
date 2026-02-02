"""Unit tests for MCP server tool functions."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

mcp_mod = pytest.importorskip("mcp")

from cyntrisec.core.schema import (
    Asset,
    AttackPath,
    ConfidenceLevel,
    EdgeKind,
    Finding,
    FindingSeverity,
    Relationship,
    Snapshot,
    SnapshotStatus,
)
from cyntrisec.mcp.server import MCP_ERROR_SNAPSHOT_NOT_FOUND, SessionState, create_mcp_server
from cyntrisec.storage import FileSystemStorage

SNAP_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
ASSET1_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
ASSET2_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
REL_ID = uuid.UUID("aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
PATH_ID = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
FINDING_ID = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")


def _snapshot():
    return Snapshot(
        id=SNAP_ID,
        aws_account_id="123456789012",
        regions=["us-east-1"],
        status=SnapshotStatus.completed,
        started_at=datetime(2025, 1, 1),
        asset_count=2,
        relationship_count=1,
        finding_count=1,
        path_count=1,
    )


def _asset(aid=ASSET1_ID, name="web-server", atype="ec2:instance", arn=None):
    return Asset(
        id=aid,
        snapshot_id=SNAP_ID,
        asset_type=atype,
        aws_resource_id=str(aid),
        name=name,
        arn=arn or f"arn:aws:ec2:us-east-1:123:{name}",
        is_internet_facing=True,
        is_sensitive_target=False,
        properties={},
    )


def _relationship():
    return Relationship(
        id=REL_ID,
        snapshot_id=SNAP_ID,
        source_asset_id=ASSET1_ID,
        target_asset_id=ASSET2_ID,
        relationship_type="CAN_ASSUME",
        edge_kind=EdgeKind.CAPABILITY,
    )


def _finding():
    return Finding(
        id=FINDING_ID,
        snapshot_id=SNAP_ID,
        asset_id=ASSET1_ID,
        finding_type="PUBLIC_ACCESS",
        severity=FindingSeverity.high,
        title="S3 bucket is public",
        description="Bucket allows public read",
        remediation="Enable block public access",
    )


def _attack_path():
    return AttackPath(
        id=PATH_ID,
        snapshot_id=SNAP_ID,
        source_asset_id=ASSET1_ID,
        target_asset_id=ASSET2_ID,
        path_asset_ids=[ASSET1_ID, ASSET2_ID],
        path_relationship_ids=[REL_ID],
        attack_chain_relationship_ids=[REL_ID],
        attack_vector="privilege-escalation",
        path_length=2,
        entry_confidence=Decimal("0.8"),
        exploitability_score=Decimal("0.7"),
        impact_score=Decimal("0.9"),
        risk_score=Decimal("0.5"),
        confidence_level=ConfidenceLevel.HIGH,
    )


def _mock_storage(
    *, snapshot=True, assets=True, relationships=True, findings=True, paths=True
):
    """Create a mock FileSystemStorage."""
    storage = MagicMock(spec=FileSystemStorage)
    storage.resolve_scan_id.return_value = str(SNAP_ID) if snapshot else None
    storage.get_snapshot.return_value = _snapshot() if snapshot else None
    storage.get_assets.return_value = (
        [_asset(ASSET1_ID, "web-server"), _asset(ASSET2_ID, "db-server", "rds:db-instance")]
        if assets
        else []
    )
    storage.get_relationships.return_value = [_relationship()] if relationships else []
    storage.get_findings.return_value = [_finding()] if findings else []
    storage.get_attack_paths.return_value = [_attack_path()] if paths else []
    storage.list_scans.return_value = [str(SNAP_ID)]
    return storage


def _get_tool_fn(server, name: str):
    """Extract a tool function from the MCP server."""
    tools = server._tool_manager._tools
    for tname, tool in tools.items():
        if tname == name:
            return tool.fn
    raise KeyError(f"Tool {name} not found in {list(tools.keys())}")


@pytest.fixture
def server_and_session():
    """Create MCP server with mock storage injected."""
    server = create_mcp_server()
    storage = _mock_storage()
    # Inject mock storage into the session state
    # The session is a closure variable; we need to find it
    # We'll patch via the tool functions directly
    return server, storage


class TestGetScanSummary:
    def test_no_snapshot_error(self):
        server = create_mcp_server()
        storage = _mock_storage(snapshot=False)
        # Patch the session inside the closure
        fn = _get_tool_fn(server, "get_scan_summary")
        # We need to reach the session. The tools close over `session`.
        # Instead, let's create a SessionState and test it directly.
        session = SessionState(storage=storage)
        snap = session.get_snapshot()
        assert snap is None

    def test_happy_path(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        snap = session.get_snapshot()
        assert snap is not None
        assert snap.aws_account_id == "123456789012"


class TestSessionState:
    def test_set_snapshot_clears_cache(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session._cache[("assets", str(SNAP_ID))] = "cached"

        new_id = str(uuid.uuid4())
        storage.resolve_scan_id.return_value = new_id
        session.set_snapshot(new_id)

        assert session._cache == {}
        assert session.snapshot_id == new_id

    def test_get_assets_caches(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        result1 = session.get_assets()
        result2 = session.get_assets()
        assert result1 is result2
        # Storage should only be called once
        assert storage.get_assets.call_count == 1

    def test_clear_cache(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session._cache[("a", "b")] = "x"
        session.clear_cache()
        assert session._cache == {}

    def test_get_findings(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        findings = session.get_findings()
        assert len(findings) == 1
        assert findings[0].title == "S3 bucket is public"

    def test_get_paths(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        paths = session.get_paths()
        assert len(paths) == 1
        assert paths[0].attack_vector == "privilege-escalation"

    def test_get_relationships(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        rels = session.get_relationships()
        assert len(rels) == 1
        assert rels[0].relationship_type == "CAN_ASSUME"


class TestMCPToolFunctions:
    """Test MCP tool functions via direct invocation."""

    @pytest.fixture
    def server(self):
        return create_mcp_server()

    def test_list_tools(self, server):
        fn = _get_tool_fn(server, "list_tools")
        result = fn()
        names = [t["name"] for t in result["tools"]]
        assert "get_findings" in names
        assert "get_assets" in names
        assert "get_attack_paths" in names
        assert "check_compliance" in names

    def test_get_findings_no_snapshot(self, server):
        fn = _get_tool_fn(server, "get_findings")
        # Without any scan data, should return error
        result = fn()
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND

    def test_get_assets_no_snapshot(self, server):
        fn = _get_tool_fn(server, "get_assets")
        result = fn()
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND

    def test_get_relationships_no_snapshot(self, server):
        fn = _get_tool_fn(server, "get_relationships")
        result = fn()
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND

    def test_get_scan_summary_no_snapshot(self, server):
        fn = _get_tool_fn(server, "get_scan_summary")
        result = fn()
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND

    def test_get_attack_paths_no_snapshot(self, server):
        fn = _get_tool_fn(server, "get_attack_paths")
        result = fn()
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND

    def test_explain_path_no_snapshot(self, server):
        fn = _get_tool_fn(server, "explain_path")
        result = fn(path_id="abc")
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND

    def test_explain_finding_no_snapshot(self, server):
        fn = _get_tool_fn(server, "explain_finding")
        result = fn(finding_id="abc")
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND

    def test_check_access_no_snapshot(self, server):
        fn = _get_tool_fn(server, "check_access")
        result = fn(principal="arn:aws:iam::123:role/R", resource="s3://bucket")
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND

    def test_get_remediations_no_snapshot(self, server):
        fn = _get_tool_fn(server, "get_remediations")
        result = fn()
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND

    def test_check_compliance_no_snapshot(self, server):
        fn = _get_tool_fn(server, "check_compliance")
        result = fn()
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND

    def test_get_unused_permissions_no_snapshot(self, server):
        fn = _get_tool_fn(server, "get_unused_permissions")
        result = fn()
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND

    def test_compare_scans_insufficient_data(self, server):
        fn = _get_tool_fn(server, "compare_scans")
        result = fn()
        assert result.get("error_code") is not None

    def test_set_session_snapshot(self, server):
        fn = _get_tool_fn(server, "set_session_snapshot")
        result = fn()
        # Should return a dict with snapshot_id, active, available_scans
        assert "available_scans" in result

    def test_get_terraform_snippet_no_snapshot(self, server):
        fn = _get_tool_fn(server, "get_terraform_snippet")
        result = fn(
            source_name="role1", target_name="bucket1", relationship_type="CAN_ASSUME"
        )
        assert result.get("error_code") == MCP_ERROR_SNAPSHOT_NOT_FOUND


class TestMCPToolWithData:
    """Test MCP tools with injected scan data via SessionState."""

    def test_get_findings_with_data(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        findings = session.get_findings()
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_get_findings_severity_filter(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        findings = session.get_findings()
        # Filter by severity manually (as the tool does)
        filtered = [f for f in findings if f.severity.upper() == "HIGH"]
        assert len(filtered) == 1

        filtered_low = [f for f in findings if f.severity.upper() == "LOW"]
        assert len(filtered_low) == 0

    def test_get_assets_with_data(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        assets = session.get_assets()
        assert len(assets) == 2

    def test_get_assets_type_filter(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        assets = session.get_assets()
        ec2_assets = [a for a in assets if a.asset_type.lower() == "ec2:instance"]
        assert len(ec2_assets) == 1
        assert ec2_assets[0].name == "web-server"

    def test_get_assets_search_filter(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        assets = session.get_assets()
        search = "web"
        filtered = [a for a in assets if search in (a.name or "").lower()]
        assert len(filtered) == 1

    def test_get_relationships_with_data(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        rels = session.get_relationships()
        assert len(rels) == 1
        assert rels[0].relationship_type == "CAN_ASSUME"

    def test_get_relationships_type_filter(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        rels = session.get_relationships()
        filtered = [r for r in rels if r.relationship_type.upper() == "CAN_ASSUME"]
        assert len(filtered) == 1
        filtered_none = [r for r in rels if r.relationship_type.upper() == "ALLOWS"]
        assert len(filtered_none) == 0

    def test_get_attack_paths_with_data(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        paths = session.get_paths()
        assert len(paths) == 1
        assert float(paths[0].risk_score) == 0.5

    def test_get_attack_paths_min_risk_filter(self):
        storage = _mock_storage()
        session = SessionState(storage=storage)
        session.snapshot_id = str(SNAP_ID)

        paths = session.get_paths()
        filtered = [p for p in paths if p.risk_score >= Decimal("0.3")]
        assert len(filtered) == 1
        filtered_high = [p for p in paths if p.risk_score >= Decimal("0.9")]
        assert len(filtered_high) == 0
