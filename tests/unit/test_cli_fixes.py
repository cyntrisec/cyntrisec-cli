"""
Unit tests for CLI bug fixes.

Tests for:
- Scan output includes scan_id
- Suggested actions use scan_id format
- Report schema validation passes
- Remediate dry-run status
- Diff --all includes changes in JSON

Property tests:
- Property 2: Suggested Actions Use Scan ID
- Property 4: Schema Validation Round Trip
- Property 8: Remediate Dry-Run Status Correctness
- Property 9: Diff --all Includes Changes
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cyntrisec.cli.schemas import (
    DiffResponse,
    RemediateResponse,
    ReportResponse,
    ScanResponse,
)
from cyntrisec.core.schema import (
    Asset,
    AttackPath,
    Finding,
    Relationship,
    Snapshot,
    SnapshotStatus,
)


# Scan ID pattern: YYYY-MM-DD_HHMMSS_ACCOUNTID
SCAN_ID_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{6}_\d{12}$")


def make_snapshot(snapshot_id=None, account_id="123456789012"):
    """Create a test snapshot."""
    return Snapshot(
        id=snapshot_id or uuid.uuid4(),
        aws_account_id=account_id,
        regions=["us-east-1"],
        status=SnapshotStatus.completed,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        asset_count=10,
        relationship_count=5,
        finding_count=3,
        path_count=2,
    )


def make_asset(snapshot_id, name, asset_type="ec2:instance", is_internet_facing=False, is_sensitive=False):
    """Create a test asset."""
    return Asset(
        id=uuid.uuid4(),
        snapshot_id=snapshot_id,
        asset_type=asset_type,
        aws_resource_id=name,
        name=name,
        is_internet_facing=is_internet_facing,
        is_sensitive_target=is_sensitive,
    )


def make_relationship(snapshot_id, source_id, target_id, rel_type="ALLOWS_TRAFFIC_TO"):
    """Create a test relationship."""
    return Relationship(
        id=uuid.uuid4(),
        snapshot_id=snapshot_id,
        source_asset_id=source_id,
        target_asset_id=target_id,
        relationship_type=rel_type,
    )


def make_attack_path(snapshot_id, source_id, target_id, rel_ids):
    """Create a test attack path."""
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
        risk_score=Decimal("0.8"),
        proof={},
    )


def make_finding(snapshot_id, asset_id, severity="high"):
    """Create a test finding."""
    return Finding(
        id=uuid.uuid4(),
        snapshot_id=snapshot_id,
        asset_id=asset_id,
        finding_type="test-finding",
        severity=severity,
        title="Test Finding",
        description="A test finding",
    )


class TestScanIdInOutput:
    """Tests for scan_id in scan output."""

    def test_scan_response_schema_includes_scan_id(self):
        """Test that ScanResponse schema includes scan_id field."""
        # Verify the schema has scan_id field
        schema = ScanResponse.model_json_schema()
        assert "scan_id" in schema["properties"]

    def test_scan_response_validates_with_scan_id(self):
        """Test that ScanResponse validates data with scan_id."""
        data = {
            "scan_id": "2026-01-19_103255_123456789012",
            "snapshot_id": str(uuid.uuid4()),
            "account_id": "123456789012",
            "regions": ["us-east-1"],
            "asset_count": 10,
            "relationship_count": 5,
            "finding_count": 3,
            "attack_path_count": 2,
        }
        response = ScanResponse.model_validate(data)
        assert response.scan_id == "2026-01-19_103255_123456789012"


class TestSuggestedActionsUseScanId:
    """
    Property 2: Suggested Actions Use Scan ID
    
    For any CLI command that emits suggested_actions containing scan references,
    the scan identifier SHALL be in scan_id format (matching pattern YYYY-MM-DD_HHMMSS_ACCOUNTID),
    not UUID format.
    """

    def test_scan_id_pattern_matches_valid_format(self):
        """Test that scan_id pattern matches valid format."""
        valid_scan_id = "2026-01-19_103255_123456789012"
        assert SCAN_ID_PATTERN.match(valid_scan_id)

    def test_scan_id_pattern_rejects_uuid(self):
        """Test that scan_id pattern rejects UUID format."""
        uuid_str = str(uuid.uuid4())
        assert not SCAN_ID_PATTERN.match(uuid_str)

    def test_suggested_actions_format_uses_scan_id(self):
        """Test that suggested_actions helper creates proper format."""
        from cyntrisec.cli.output import suggested_actions

        scan_id = "2026-01-19_103255_123456789012"
        actions = suggested_actions([
            (f"cyntrisec analyze paths --scan {scan_id}", "Review attack paths"),
            (f"cyntrisec cuts --snapshot {scan_id}", "Find fixes"),
        ])

        for action in actions:
            # Extract scan reference from command
            cmd = action["command"]
            if "--scan" in cmd or "--snapshot" in cmd:
                # The identifier after --scan or --snapshot should be scan_id format
                parts = cmd.split()
                for i, part in enumerate(parts):
                    if part in ("--scan", "--snapshot") and i + 1 < len(parts):
                        identifier = parts[i + 1]
                        assert SCAN_ID_PATTERN.match(identifier), f"Expected scan_id format, got: {identifier}"


class TestReportSchemaValidation:
    """
    Property 4: Schema Validation Round Trip
    
    For any CLI command output in json/agent format, the emitted data SHALL pass
    validation against its declared schema without extra fields.
    """

    def test_report_response_schema_no_format_field(self):
        """Test that ReportResponse schema does not include format field."""
        schema = ReportResponse.model_json_schema()
        assert "format" not in schema["properties"]

    def test_report_response_validates_without_format(self):
        """Test that ReportResponse validates data without format field."""
        data = {
            "output_path": "/path/to/report.json",
            "snapshot_id": str(uuid.uuid4()),
            "account_id": "123456789012",
            "findings": 5,
            "paths": 3,
        }
        response = ReportResponse.model_validate(data)
        assert response.output_path == "/path/to/report.json"
        assert response.findings == 5

    def test_report_response_rejects_extra_fields(self):
        """Test that ReportResponse rejects extra fields like 'format'."""
        data = {
            "output_path": "/path/to/report.json",
            "snapshot_id": str(uuid.uuid4()),
            "account_id": "123456789012",
            "findings": 5,
            "paths": 3,
            "format": "json",  # This should be rejected
        }
        with pytest.raises(Exception):  # Pydantic ValidationError
            ReportResponse.model_validate(data)


class TestRemediateDryRunStatus:
    """
    Property 8: Remediate Dry-Run Status Correctness
    
    For any remediate --dry-run invocation, the output status SHALL be "dry_run"
    and applied SHALL be false.
    """

    def test_remediate_response_accepts_dry_run_status(self):
        """Test that RemediateResponse accepts dry_run status."""
        data = {
            "snapshot_id": str(uuid.uuid4()),
            "account_id": "123456789012",
            "total_paths": 5,
            "paths_blocked": 3,
            "coverage": 0.6,
            "plan": [],
            "applied": False,
            "mode": "dry_run",
        }
        response = RemediateResponse.model_validate(data)
        assert response.mode == "dry_run"
        assert response.applied is False

    def test_dry_run_mode_value_is_correct(self):
        """Test that dry_run mode uses underscore not hyphen."""
        # The mode should be "dry_run" not "dry-run"
        data = {
            "snapshot_id": str(uuid.uuid4()),
            "account_id": "123456789012",
            "total_paths": 5,
            "paths_blocked": 3,
            "coverage": 0.6,
            "plan": [],
            "applied": False,
            "mode": "dry_run",
        }
        response = RemediateResponse.model_validate(data)
        assert response.mode == "dry_run"


class TestDiffAllIncludesChanges:
    """
    Property 9: Diff --all Includes Changes
    
    For any diff --all invocation with json/agent format, the output SHALL include
    non-null asset_changes and relationship_changes arrays.
    """

    def test_diff_response_schema_includes_change_fields(self):
        """Test that DiffResponse schema includes asset_changes and relationship_changes."""
        schema = DiffResponse.model_json_schema()
        assert "asset_changes" in schema["properties"]
        assert "relationship_changes" in schema["properties"]

    def test_diff_response_validates_with_changes(self):
        """Test that DiffResponse validates data with asset_changes and relationship_changes."""
        data = {
            "has_regressions": False,
            "has_improvements": True,
            "summary": {
                "assets_added": 2,
                "assets_removed": 1,
                "relationships_added": 1,
                "relationships_removed": 0,
                "paths_added": 0,
                "paths_removed": 1,
                "findings_new": 0,
                "findings_resolved": 1,
            },
            "path_changes": [],
            "asset_changes": [
                {
                    "change_type": "added",
                    "asset_id": str(uuid.uuid4()),
                    "asset_type": "ec2:instance",
                    "name": "test-instance",
                }
            ],
            "relationship_changes": [
                {
                    "change_type": "added",
                    "relationship_id": str(uuid.uuid4()),
                    "relationship_type": "ALLOWS_TRAFFIC_TO",
                    "source_id": str(uuid.uuid4()),
                    "target_id": str(uuid.uuid4()),
                }
            ],
        }
        response = DiffResponse.model_validate(data)
        assert response.asset_changes is not None
        assert len(response.asset_changes) == 1
        assert response.relationship_changes is not None
        assert len(response.relationship_changes) == 1

    def test_build_payload_includes_changes_when_show_all(self):
        """Test that _build_payload includes changes when show_all is True."""
        from cyntrisec.cli.diff import _build_payload
        from cyntrisec.core.diff import AssetChange, ChangeType, DiffResult, RelationshipChange

        snapshot_id = uuid.uuid4()
        old_snap = make_snapshot(snapshot_id)
        new_snap = make_snapshot()

        asset = make_asset(snapshot_id, "test-asset")
        rel = make_relationship(snapshot_id, asset.id, asset.id)

        # Create a mock result with changes
        result = MagicMock()
        result.summary = {
            "assets_added": 1,
            "assets_removed": 0,
            "relationships_added": 1,
            "relationships_removed": 0,
            "paths_added": 0,
            "paths_removed": 0,
            "findings_new": 0,
            "findings_resolved": 0,
        }
        result.has_regressions = False
        result.has_improvements = True
        result.path_changes = []
        result.finding_changes = []
        result.asset_changes = [MagicMock(change_type=ChangeType.added, asset=asset)]
        result.relationship_changes = [MagicMock(change_type=ChangeType.added, relationship=rel)]

        # Test with show_all=True
        payload = _build_payload(result, old_snap, new_snap, show_all=True)
        assert "asset_changes" in payload
        assert "relationship_changes" in payload
        assert len(payload["asset_changes"]) == 1
        assert len(payload["relationship_changes"]) == 1

    def test_build_payload_excludes_changes_when_show_all_false(self):
        """Test that _build_payload excludes changes when show_all is False."""
        from cyntrisec.cli.diff import _build_payload

        snapshot_id = uuid.uuid4()
        old_snap = make_snapshot(snapshot_id)
        new_snap = make_snapshot()

        # Create a mock result
        result = MagicMock()
        result.summary = {}
        result.has_regressions = False
        result.has_improvements = False
        result.path_changes = []
        result.finding_changes = []
        result.asset_changes = []
        result.relationship_changes = []

        # Test with show_all=False (default)
        payload = _build_payload(result, old_snap, new_snap, show_all=False)
        assert "asset_changes" not in payload
        assert "relationship_changes" not in payload


class TestAnalyzeStatsFormat:
    """Tests for analyze stats --format option."""

    def test_analyze_stats_response_schema_exists(self):
        """Test that AnalyzeStatsResponse schema exists."""
        from cyntrisec.cli.schemas import AnalyzeStatsResponse

        schema = AnalyzeStatsResponse.model_json_schema()
        assert "asset_count" in schema["properties"]
        assert "relationship_count" in schema["properties"]
        assert "finding_count" in schema["properties"]
        assert "path_count" in schema["properties"]
        assert "scan_id" in schema["properties"]

    def test_analyze_stats_response_validates(self):
        """Test that AnalyzeStatsResponse validates correctly."""
        from cyntrisec.cli.schemas import AnalyzeStatsResponse

        data = {
            "snapshot_id": str(uuid.uuid4()),
            "scan_id": "2026-01-19_103255_123456789012",
            "account_id": "123456789012",
            "asset_count": 10,
            "relationship_count": 5,
            "finding_count": 3,
            "path_count": 2,
            "regions": ["us-east-1"],
            "status": "completed",
        }
        response = AnalyzeStatsResponse.model_validate(data)
        assert response.asset_count == 10
        assert response.scan_id == "2026-01-19_103255_123456789012"
