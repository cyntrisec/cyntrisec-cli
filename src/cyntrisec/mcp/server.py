"""
MCP Server - Model Context Protocol server for AI agent integration.

Exposes Cyntrisec capabilities as MCP tools that AI agents can invoke directly.

Usage:
    cyntrisec serve            # Start MCP server (stdio transport)
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from typing import Any

# MCP support - optional dependency
try:
    from mcp.server.fastmcp import FastMCP

    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    FastMCP = None

from cyntrisec.core.compliance import ComplianceChecker, Framework
from cyntrisec.core.cuts import MinCutFinder
from cyntrisec.core.diff import SnapshotDiff
from cyntrisec.core.graph import GraphBuilder
from cyntrisec.core.simulator import OfflineSimulator
from cyntrisec.core.waste import WasteAnalyzer
from cyntrisec.storage import FileSystemStorage

log = logging.getLogger(__name__)


# Error codes for MCP responses (mirrors CLI error taxonomy)
MCP_ERROR_SNAPSHOT_NOT_FOUND = "SNAPSHOT_NOT_FOUND"
MCP_ERROR_INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


def mcp_error(error_code: str, message: str) -> dict[str, Any]:
    """Return a consistent error envelope for MCP tool responses."""
    return {
        "status": "error",
        "error_code": error_code,
        "message": message,
        "data": None,
    }


@dataclass
class SessionState:
    """
    Lightweight session cache for MCP server calls.

    Caches scan data for the current snapshot to avoid repeated disk reads
    and keeps track of the active snapshot id for successive tool calls.
    """

    storage: FileSystemStorage = field(default_factory=FileSystemStorage)
    snapshot_id: str | None = None
    _cache: dict[tuple[str, str | None], object] = field(default_factory=dict)

    def set_snapshot(self, snapshot_id: str | None) -> str | None:
        """Set or update the active snapshot id and clear cache if changed."""
        if snapshot_id and snapshot_id != self.snapshot_id:
            self._cache.clear()
            self.snapshot_id = snapshot_id
        elif snapshot_id is None and self.snapshot_id is None:
            # Try to seed from latest snapshot if present
            snap = self.storage.get_snapshot()
            if snap:
                self.snapshot_id = str(snap.id)
        return self.snapshot_id

    def _key(self, kind: str, snapshot_id: str | None) -> tuple[str, str | None]:
        return (kind, snapshot_id or self.snapshot_id)

    def get_snapshot(self, snapshot_id: str | None = None):
        snap = self.storage.get_snapshot(snapshot_id or self.snapshot_id)
        if snap and not self.snapshot_id:
            self.snapshot_id = snapshot_id or str(snap.id)
        return snap

    def get_assets(self, snapshot_id: str | None = None):
        key = self._key("assets", snapshot_id)
        if key not in self._cache:
            self._cache[key] = self.storage.get_assets(snapshot_id or self.snapshot_id)
        return self._cache[key]

    def get_relationships(self, snapshot_id: str | None = None):
        key = self._key("relationships", snapshot_id)
        if key not in self._cache:
            self._cache[key] = self.storage.get_relationships(snapshot_id or self.snapshot_id)
        return self._cache[key]

    def get_paths(self, snapshot_id: str | None = None):
        key = self._key("paths", snapshot_id)
        if key not in self._cache:
            self._cache[key] = self.storage.get_attack_paths(snapshot_id or self.snapshot_id)
        return self._cache[key]

    def get_findings(self, snapshot_id: str | None = None):
        key = self._key("findings", snapshot_id)
        if key not in self._cache:
            self._cache[key] = self.storage.get_findings(snapshot_id or self.snapshot_id)
        return self._cache[key]

    def clear_cache(self) -> None:
        self._cache.clear()


def create_mcp_server() -> FastMCP:
    """
    Create and configure the MCP server with all tools.

    Returns:
        Configured FastMCP instance
    """
    if not HAS_MCP:
        raise ImportError("MCP SDK not installed. Run: pip install mcp")

    mcp = FastMCP(
        name="cyntrisec", instructions="AWS capability graph analysis and attack path discovery"
    )
    session = SessionState()

    _register_session_tools(mcp, session)
    _register_graph_tools(mcp, session)
    _register_insight_tools(mcp, session)

    return mcp


def _register_session_tools(mcp, session):
    """Register session and summary tools."""

    @mcp.tool()
    def get_scan_summary(snapshot_id: str | None = None) -> dict[str, Any]:
        """
        Get summary of the latest AWS scan.

        Returns asset counts, finding counts, and attack path counts.
        """
        snapshot = session.get_snapshot(snapshot_id)
        session.set_snapshot(snapshot_id or (snapshot and str(snapshot.id)))

        if not snapshot:
            return mcp_error(
                MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found. Run 'cyntrisec scan' first."
            )

        return {
            "snapshot_id": str(snapshot.id),
            "account_id": snapshot.aws_account_id,
            "regions": snapshot.regions,
            "status": snapshot.status,
            "started_at": snapshot.started_at.isoformat(),
            "asset_count": snapshot.asset_count,
            "relationship_count": snapshot.relationship_count,
            "finding_count": snapshot.finding_count,
            "attack_path_count": snapshot.path_count,
        }

    @mcp.tool()
    def set_session_snapshot(snapshot_id: str | None = None) -> dict[str, Any]:
        """
        Set or retrieve the active snapshot id used for subsequent calls.

        Args:
            snapshot_id: Optional scan id/directory name. If omitted, returns current/ latest.
        """
        sid = session.set_snapshot(snapshot_id)
        snap = session.get_snapshot(sid)
        return {
            "snapshot_id": str(snap.id) if snap else sid,
            "active": sid,
            "available_scans": session.storage.list_scans(),
        }

    @mcp.tool()
    def list_tools() -> dict[str, Any]:
        """
        List all available Cyntrisec tools.

        Returns:
            List of tools with descriptions.
        """
        return {
            "tools": [
                {"name": "get_scan_summary", "description": "Get summary of latest AWS scan"},
                {"name": "get_attack_paths", "description": "Get discovered attack paths"},
                {"name": "get_remediations", "description": "Find optimal fixes for attack paths"},
                {"name": "check_access", "description": "Test if principal can access resource"},
                {"name": "get_unused_permissions", "description": "Find unused IAM permissions"},
                {"name": "check_compliance", "description": "Check CIS AWS or SOC 2 compliance"},
                {"name": "compare_scans", "description": "Compare latest scan to previous"},
            ]
        }


def _register_graph_tools(mcp, session):
    """Register graph analysis tools."""

    @mcp.tool()
    def get_attack_paths(max_paths: int = 10, snapshot_id: str | None = None) -> dict[str, Any]:
        """
        Get discovered attack paths from the latest scan.

        Args:
            max_paths: Maximum number of paths to return (default: 10)

        Returns:
            List of attack paths with risk scores and vectors.
        """
        paths = session.get_paths(snapshot_id)
        session.set_snapshot(snapshot_id)

        return {
            "total": len(paths),
            "paths": [
                {
                    "id": str(p.id),
                    "attack_vector": p.attack_vector,
                    "risk_score": float(p.risk_score),
                    "source": p.source_asset_id and str(p.source_asset_id),
                    "target": p.target_asset_id and str(p.target_asset_id),
                }
                for p in paths[:max_paths]
            ],
        }

    @mcp.tool()
    def check_access(
        principal: str, resource: str, snapshot_id: str | None = None
    ) -> dict[str, Any]:
        """
        Test if a principal can access a resource.

        Args:
            principal: IAM role or user name (e.g., "ECforS")
            resource: Target resource (e.g., "s3://prod-bucket")

        Returns:
            Whether access is allowed and via which relationship.
        """
        snapshot = session.get_snapshot(snapshot_id)
        assets = session.get_assets(snapshot_id)
        relationships = session.get_relationships(snapshot_id)
        session.set_snapshot(snapshot_id or (snapshot and str(snapshot.id)))

        if not snapshot:
            return mcp_error(MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found.")

        graph = GraphBuilder().build(assets, relationships)
        simulator = OfflineSimulator(graph)
        result = simulator.simulate(principal, resource)

        return {
            "principal": result.principal_arn,
            "resource": result.resource_arn,
            "can_access": result.allowed,
            "via": result.via,
        }


def _register_insight_tools(mcp, session):
    """Register insight and remediation tools."""

    @mcp.tool()
    def get_remediations(max_cuts: int = 5, snapshot_id: str | None = None) -> dict[str, Any]:
        """
        Find optimal remediations that block attack paths.

        Uses min-cut algorithm to find smallest set of changes
        that block all attack paths.

        Args:
            max_cuts: Maximum number of remediations (default: 5)

        Returns:
            List of remediations with coverage percentages.
        """
        assets = session.get_assets(snapshot_id)
        relationships = session.get_relationships(snapshot_id)
        paths = session.get_paths(snapshot_id)
        session.set_snapshot(snapshot_id)

        if not paths:
            return {"total_paths": 0, "remediations": []}

        graph = GraphBuilder().build(assets, relationships)
        finder = MinCutFinder()
        result = finder.find_cuts(graph, paths, max_cuts=max_cuts)

        return {
            "total_paths": result.total_paths,
            "paths_blocked": result.paths_blocked,
            "coverage": float(result.coverage),
            "remediations": [
                {
                    "source": r.source_name,
                    "target": r.target_name,
                    "relationship_type": r.relationship_type,
                    "paths_blocked": r.paths_blocked,
                    "recommendation": r.recommendation,
                }
                for r in result.remediations
            ],
        }

    @mcp.tool()
    def get_unused_permissions(
        days_threshold: int = 90, snapshot_id: str | None = None
    ) -> dict[str, Any]:
        """
        Find unused IAM permissions (blast radius reduction opportunities).

        Args:
            days_threshold: Days of inactivity to consider unused

        Returns:
            Unused permissions grouped by role with reduction percentages.
        """
        assets = session.get_assets(snapshot_id)
        relationships = session.get_relationships(snapshot_id)
        session.set_snapshot(snapshot_id)

        graph = GraphBuilder().build(assets, relationships)
        analyzer = WasteAnalyzer(graph, days_threshold=days_threshold)
        results = analyzer.analyze_offline()

        return {
            "total_unused": sum(r.unused_count for r in results),
            "total_reduction": (
                sum(r.blast_radius_reduction for r in results) / len(results) if results else 0
            ),
            "roles": [
                {
                    "role_name": r.role_name,
                    "unused_count": r.unused_count,
                    "blast_radius_reduction": float(r.blast_radius_reduction),
                }
                for r in results[:10]
            ],
        }

    @mcp.tool()
    def check_compliance(
        framework: str = "cis-aws", snapshot_id: str | None = None
    ) -> dict[str, Any]:
        """
        Check compliance against CIS AWS or SOC 2 framework.

        Args:
            framework: "cis-aws" or "soc2"

        Returns:
            Compliance score and failing controls.
        """
        findings = session.get_findings(snapshot_id)
        assets = session.get_assets(snapshot_id)
        session.set_snapshot(snapshot_id)

        fw = Framework.CIS_AWS if "cis" in framework.lower() else Framework.SOC2
        checker = ComplianceChecker()
        report = checker.check(findings, assets, framework=fw)
        summary = checker.summary(report)

        return {
            "framework": fw.value,
            "compliance_score": summary["compliance_score"],
            "passing": summary["passing"],
            "failing": summary["failing"],
            "failing_controls": [
                {"id": r.control.id, "title": r.control.title}
                for r in report.results
                if not r.is_passing
            ],
        }

    @mcp.tool()
    def compare_scans() -> dict[str, Any]:
        """
        Compare latest scan to previous scan.

        Returns:
            Changes in assets, relationships, and attack paths.
        """
        scan_ids = session.storage.list_scans()

        if len(scan_ids) < 2:
            return mcp_error(MCP_ERROR_INSUFFICIENT_DATA, "Need at least 2 scans to compare.")

        new_id, old_id = scan_ids[0], scan_ids[1]

        differ = SnapshotDiff()
        result = differ.diff(
            old_assets=session.storage.get_assets(old_id),
            old_relationships=session.storage.get_relationships(old_id),
            old_paths=session.storage.get_attack_paths(old_id),
            old_findings=session.storage.get_findings(old_id),
            new_assets=session.storage.get_assets(new_id),
            new_relationships=session.storage.get_relationships(new_id),
            new_paths=session.storage.get_attack_paths(new_id),
            new_findings=session.storage.get_findings(new_id),
            old_snapshot_id=session.storage.get_snapshot(old_id).id,
            new_snapshot_id=session.storage.get_snapshot(new_id).id,
        )

        return {
            "has_regressions": result.has_regressions,
            "has_improvements": result.has_improvements,
            "summary": result.summary,
        }


def run_mcp_server():
    """Run the MCP server with stdio transport."""
    if not HAS_MCP:
        print("Error: MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
        sys.exit(1)

    # Configure logging to stderr to avoid corrupting stdio
    logging.basicConfig(
        level=logging.WARNING, stream=sys.stderr, format="%(levelname)s: %(message)s"
    )

    mcp = create_mcp_server()
    mcp.run(transport="stdio")
