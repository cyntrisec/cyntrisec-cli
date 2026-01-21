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

from cyntrisec.cli.remediate import _terraform_snippet
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
        # Resolve the identifier to a scan_id (directory name)
        resolved_id = self.storage.resolve_scan_id(snapshot_id)
        if resolved_id and resolved_id != self.snapshot_id:
            self._cache.clear()
            self.snapshot_id = resolved_id
        elif resolved_id is None and self.snapshot_id is None:
            # Try to seed from latest snapshot if present
            snap = self.storage.get_snapshot()
            if snap:
                self.snapshot_id = self.storage.resolve_scan_id(None)
        return self.snapshot_id

    def _key(self, kind: str, snapshot_id: str | None) -> tuple[str, str | None]:
        resolved_id = self.storage.resolve_scan_id(snapshot_id) if snapshot_id else self.snapshot_id
        return (kind, resolved_id or self.snapshot_id)

    def get_snapshot(self, snapshot_id: str | None = None):
        resolved_id = self.storage.resolve_scan_id(snapshot_id or self.snapshot_id)
        snap = self.storage.get_snapshot(resolved_id)
        if snap and not self.snapshot_id:
            self.snapshot_id = resolved_id or self.storage.resolve_scan_id(None)
        return snap

    def get_assets(self, snapshot_id: str | None = None):
        resolved_id = self.storage.resolve_scan_id(snapshot_id or self.snapshot_id)
        key = self._key("assets", resolved_id)
        if key not in self._cache:
            self._cache[key] = self.storage.get_assets(resolved_id)
        return self._cache[key]

    def get_relationships(self, snapshot_id: str | None = None):
        resolved_id = self.storage.resolve_scan_id(snapshot_id or self.snapshot_id)
        key = self._key("relationships", resolved_id)
        if key not in self._cache:
            self._cache[key] = self.storage.get_relationships(resolved_id)
        return self._cache[key]

    def get_paths(self, snapshot_id: str | None = None):
        resolved_id = self.storage.resolve_scan_id(snapshot_id or self.snapshot_id)
        key = self._key("paths", resolved_id)
        if key not in self._cache:
            self._cache[key] = self.storage.get_attack_paths(resolved_id)
        return self._cache[key]

    def get_findings(self, snapshot_id: str | None = None):
        resolved_id = self.storage.resolve_scan_id(snapshot_id or self.snapshot_id)
        key = self._key("findings", resolved_id)
        if key not in self._cache:
            self._cache[key] = self.storage.get_findings(resolved_id)
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
    def get_findings(
        severity: str | None = None,
        max_findings: int = 20,
        snapshot_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Get security findings from the scan.

        Args:
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            max_findings: Maximum number of findings to return (default: 20)
            snapshot_id: Optional snapshot ID (default: latest)

        Returns:
            List of security findings with severity and descriptions.
        """
        snapshot = session.get_snapshot(snapshot_id)
        if not snapshot:
            return mcp_error(
                MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found. Run 'cyntrisec scan' first."
            )

        findings = session.get_findings(snapshot_id)
        session.set_snapshot(snapshot_id)

        # Filter by severity if specified
        if severity:
            severity_upper = severity.upper()
            findings = [f for f in findings if f.severity.upper() == severity_upper]

        return {
            "total": len(findings),
            "findings": [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "severity": f.severity,
                    "resource_type": f.resource_type,
                    "resource_name": f.resource_name,
                    "description": f.description,
                    "recommendation": f.recommendation,
                }
                for f in findings[:max_findings]
            ],
        }

    @mcp.tool()
    def get_assets(
        asset_type: str | None = None,
        search: str | None = None,
        max_assets: int = 50,
        snapshot_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Get assets from the scan with optional filtering.

        Args:
            asset_type: Filter by type (e.g., "iam:role", "ec2:instance", "s3:bucket")
            search: Search by name or ARN (case-insensitive)
            max_assets: Maximum number of assets to return (default: 50)
            snapshot_id: Optional snapshot ID (default: latest)

        Returns:
            List of assets with their properties.
        """
        snapshot = session.get_snapshot(snapshot_id)
        if not snapshot:
            return mcp_error(
                MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found. Run 'cyntrisec scan' first."
            )

        assets = session.get_assets(snapshot_id)
        session.set_snapshot(snapshot_id)

        # Filter by type if specified
        if asset_type:
            assets = [a for a in assets if a.asset_type.lower() == asset_type.lower()]

        # Search by name or ARN
        if search:
            search_lower = search.lower()
            assets = [
                a for a in assets
                if search_lower in (a.name or "").lower()
                or search_lower in (a.arn or "").lower()
            ]

        return {
            "total": len(assets),
            "assets": [
                {
                    "id": str(a.id),
                    "type": a.asset_type,
                    "name": a.name,
                    "arn": a.arn,
                    "region": a.region,
                    "is_entry_point": a.is_entry_point,
                    "is_sensitive_target": a.is_sensitive_target,
                }
                for a in assets[:max_assets]
            ],
        }

    @mcp.tool()
    def get_relationships(
        relationship_type: str | None = None,
        source_name: str | None = None,
        target_name: str | None = None,
        max_relationships: int = 50,
        snapshot_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Get relationships between assets with optional filtering.

        Args:
            relationship_type: Filter by type (e.g., "CAN_ASSUME", "CAN_REACH", "MAY_ACCESS")
            source_name: Filter by source asset name
            target_name: Filter by target asset name
            max_relationships: Maximum number to return (default: 50)
            snapshot_id: Optional snapshot ID (default: latest)

        Returns:
            List of relationships with source, target, and type.
        """
        snapshot = session.get_snapshot(snapshot_id)
        if not snapshot:
            return mcp_error(
                MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found. Run 'cyntrisec scan' first."
            )

        relationships = session.get_relationships(snapshot_id)
        assets = session.get_assets(snapshot_id)
        session.set_snapshot(snapshot_id)

        # Build asset lookup for names
        asset_map = {str(a.id): a for a in assets}

        # Filter by relationship type
        if relationship_type:
            relationships = [
                r for r in relationships
                if r.relationship_type.upper() == relationship_type.upper()
            ]

        # Filter by source name
        if source_name:
            source_lower = source_name.lower()
            relationships = [
                r for r in relationships
                if source_lower in (asset_map.get(str(r.source_asset_id), None) and
                                    asset_map[str(r.source_asset_id)].name or "").lower()
            ]

        # Filter by target name
        if target_name:
            target_lower = target_name.lower()
            relationships = [
                r for r in relationships
                if target_lower in (asset_map.get(str(r.target_asset_id), None) and
                                    asset_map[str(r.target_asset_id)].name or "").lower()
            ]

        return {
            "total": len(relationships),
            "relationships": [
                {
                    "id": str(r.id),
                    "type": r.relationship_type,
                    "source_id": str(r.source_asset_id),
                    "source_name": asset_map.get(str(r.source_asset_id), None) and
                                   asset_map[str(r.source_asset_id)].name,
                    "target_id": str(r.target_asset_id),
                    "target_name": asset_map.get(str(r.target_asset_id), None) and
                                   asset_map[str(r.target_asset_id)].name,
                    "edge_kind": r.edge_kind.value if r.edge_kind else None,
                }
                for r in relationships[:max_relationships]
            ],
        }

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
                # Discovery & Session
                {"name": "list_tools", "description": "List all available Cyntrisec tools"},
                {"name": "set_session_snapshot", "description": "Set active snapshot for session"},
                {"name": "get_scan_summary", "description": "Get summary of latest AWS scan"},
                # Assets & Relationships
                {"name": "get_assets", "description": "Get assets with optional type/name filtering"},
                {"name": "get_relationships", "description": "Get relationships between assets"},
                {"name": "get_findings", "description": "Get security findings with severity filtering"},
                # Attack Paths
                {"name": "get_attack_paths", "description": "Get discovered attack paths with risk scores"},
                {"name": "explain_path", "description": "Get detailed breakdown of an attack path"},
                {"name": "explain_finding", "description": "Get detailed explanation of a security finding"},
                # Remediation
                {"name": "get_remediations", "description": "Find optimal fixes for attack paths"},
                {"name": "get_terraform_snippet", "description": "Get Terraform code for a remediation"},
                # Access & Permissions
                {"name": "check_access", "description": "Test if principal can access resource"},
                {"name": "get_unused_permissions", "description": "Find unused IAM permissions"},
                # Compliance & Diff
                {"name": "check_compliance", "description": "Check CIS AWS or SOC 2 compliance"},
                {"name": "compare_scans", "description": "Compare latest scan to previous"},
            ]
        }


def _register_graph_tools(mcp, session):
    """Register graph analysis tools."""

    @mcp.tool()
    def get_attack_paths(
        max_paths: int = 10,
        min_risk: float = 0.0,
        snapshot_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Get discovered attack paths from the latest scan.

        Args:
            max_paths: Maximum number of paths to return (default: 10)
            min_risk: Minimum risk score filter (0.0-1.0, default: 0.0)
            snapshot_id: Optional snapshot ID (default: latest)

        Returns:
            List of attack paths with risk scores, confidence, and traversed assets.
        """
        snapshot = session.get_snapshot(snapshot_id)
        if not snapshot:
            return mcp_error(
                MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found. Run 'cyntrisec scan' first."
            )

        paths = session.get_paths(snapshot_id)
        assets = session.get_assets(snapshot_id)
        session.set_snapshot(snapshot_id)

        # Build asset lookup
        asset_map = {str(a.id): a for a in assets}

        # Filter by min risk
        if min_risk > 0:
            paths = [p for p in paths if p.risk_score >= min_risk]

        def get_asset_name(asset_id):
            if not asset_id:
                return None
            asset = asset_map.get(str(asset_id))
            return asset.name if asset else str(asset_id)

        return {
            "total": len(paths),
            "paths": [
                {
                    "id": str(p.id),
                    "attack_vector": p.attack_vector,
                    "risk_score": float(p.risk_score),
                    "confidence_level": p.confidence_level.value if p.confidence_level else None,
                    "source_name": get_asset_name(p.source_asset_id),
                    "target_name": get_asset_name(p.target_asset_id),
                    "path_length": len(p.path_asset_ids) if p.path_asset_ids else 0,
                    "path_assets": [get_asset_name(aid) for aid in (p.path_asset_ids or [])],
                }
                for p in paths[:max_paths]
            ],
        }

    @mcp.tool()
    def explain_path(path_id: str, snapshot_id: str | None = None) -> dict[str, Any]:
        """
        Get detailed explanation of an attack path.

        Args:
            path_id: The attack path ID to explain
            snapshot_id: Optional snapshot ID (default: latest)

        Returns:
            Detailed breakdown of the attack path with each hop explained.
        """
        snapshot = session.get_snapshot(snapshot_id)
        if not snapshot:
            return mcp_error(
                MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found. Run 'cyntrisec scan' first."
            )

        paths = session.get_paths(snapshot_id)
        assets = session.get_assets(snapshot_id)
        relationships = session.get_relationships(snapshot_id)
        session.set_snapshot(snapshot_id)

        # Find the path
        target_path = None
        for p in paths:
            if str(p.id) == path_id:
                target_path = p
                break

        if not target_path:
            return mcp_error("PATH_NOT_FOUND", f"Attack path {path_id} not found.")

        # Build lookups
        asset_map = {str(a.id): a for a in assets}
        rel_map = {str(r.id): r for r in relationships}

        # Build path explanation
        hops = []
        path_asset_ids = target_path.path_asset_ids or []
        path_rel_ids = target_path.attack_chain_relationship_ids or []

        for i, asset_id in enumerate(path_asset_ids):
            asset = asset_map.get(str(asset_id))
            hop = {
                "step": i + 1,
                "asset_name": asset.name if asset else str(asset_id),
                "asset_type": asset.asset_type if asset else None,
                "asset_arn": asset.arn if asset else None,
            }

            # Add relationship to next hop if exists
            if i < len(path_rel_ids):
                rel = rel_map.get(str(path_rel_ids[i]))
                if rel:
                    hop["next_via"] = rel.relationship_type
                    if rel.evidence and rel.evidence.permission:
                        hop["permission"] = rel.evidence.permission

            hops.append(hop)

        return {
            "path_id": path_id,
            "attack_vector": target_path.attack_vector,
            "risk_score": float(target_path.risk_score),
            "confidence_level": target_path.confidence_level.value if target_path.confidence_level else None,
            "summary": f"Attack path from {hops[0]['asset_name'] if hops else 'unknown'} to {hops[-1]['asset_name'] if hops else 'unknown'} via {len(hops)} hops",
            "hops": hops,
        }

    @mcp.tool()
    def explain_finding(finding_id: str, snapshot_id: str | None = None) -> dict[str, Any]:
        """
        Get detailed explanation of a security finding.

        Args:
            finding_id: The finding ID to explain
            snapshot_id: Optional snapshot ID (default: latest)

        Returns:
            Detailed explanation with context, impact, and remediation steps.
        """
        snapshot = session.get_snapshot(snapshot_id)
        if not snapshot:
            return mcp_error(
                MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found. Run 'cyntrisec scan' first."
            )

        findings = session.get_findings(snapshot_id)
        session.set_snapshot(snapshot_id)

        # Find the finding
        target_finding = None
        for f in findings:
            if str(f.id) == finding_id:
                target_finding = f
                break

        if not target_finding:
            return mcp_error("FINDING_NOT_FOUND", f"Finding {finding_id} not found.")

        return {
            "finding_id": finding_id,
            "title": target_finding.title,
            "severity": target_finding.severity,
            "resource_type": target_finding.resource_type,
            "resource_name": target_finding.resource_name,
            "resource_arn": target_finding.resource_arn,
            "description": target_finding.description,
            "impact": f"This {target_finding.severity} severity finding affects {target_finding.resource_name}",
            "recommendation": target_finding.recommendation,
            "compliance_frameworks": target_finding.compliance_frameworks if hasattr(target_finding, 'compliance_frameworks') else [],
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

        # OfflineSimulator takes assets and relationships, not a graph
        simulator = OfflineSimulator(assets=assets, relationships=relationships)
        result = simulator.can_access(principal, resource)

        return {
            "principal": result.principal_arn,
            "resource": result.target_resource,
            "can_access": result.can_access,
            "via": result.proof.get("relationship_type", None),
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
        snapshot = session.get_snapshot(snapshot_id)
        if not snapshot:
            return mcp_error(
                MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found. Run 'cyntrisec scan' first."
            )

        assets = session.get_assets(snapshot_id)
        relationships = session.get_relationships(snapshot_id)
        paths = session.get_paths(snapshot_id)
        session.set_snapshot(snapshot_id)

        if not paths:
            return {"total_paths": 0, "remediations": []}

        graph = GraphBuilder().build(assets=assets, relationships=relationships)
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
                    "paths_blocked": len(r.paths_blocked),
                    "recommendation": r.description,
                    "estimated_savings": float(r.cost_savings),
                    "roi_score": float(r.roi_score),
                }
                for r in result.remediations
            ],
        }

    @mcp.tool()
    def get_terraform_snippet(
        source_name: str,
        target_name: str,
        relationship_type: str,
        snapshot_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Get Terraform code snippet for a specific remediation.

        Args:
            source_name: Name of the source asset
            target_name: Name of the target asset
            relationship_type: Type of relationship (e.g., "CAN_ASSUME", "ALLOWS_TRAFFIC_TO")
            snapshot_id: Optional snapshot ID (default: latest)

        Returns:
            Terraform HCL code snippet for the remediation.
        """
        snapshot = session.get_snapshot(snapshot_id)
        if not snapshot:
            return mcp_error(
                MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found. Run 'cyntrisec scan' first."
            )

        assets = session.get_assets(snapshot_id)
        session.set_snapshot(snapshot_id)

        # Find source and target assets to get ARNs
        source_asset = None
        target_asset = None
        for a in assets:
            if a.name and source_name.lower() in a.name.lower():
                source_asset = a
            if a.name and target_name.lower() in a.name.lower():
                target_asset = a

        terraform_code = _terraform_snippet(
            action="restrict",
            source=source_name,
            target=target_name,
            relationship_type=relationship_type.upper(),
            source_arn=source_asset.arn if source_asset else None,
            target_arn=target_asset.arn if target_asset else None,
        )

        return {
            "source": source_name,
            "target": target_name,
            "relationship_type": relationship_type,
            "terraform": terraform_code,
            "note": "Review and customize this snippet before applying. This is a starting point.",
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
        snapshot = session.get_snapshot(snapshot_id)
        if not snapshot:
            return mcp_error(
                MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found. Run 'cyntrisec scan' first."
            )

        assets = session.get_assets(snapshot_id)
        session.set_snapshot(snapshot_id)

        # WasteAnalyzer takes only days_threshold, then analyze_from_assets takes assets
        analyzer = WasteAnalyzer(days_threshold=days_threshold)
        report = analyzer.analyze_from_assets(assets=assets)

        return {
            "total_unused": report.total_unused,
            "total_reduction": float(report.blast_radius_reduction),
            "roles": [
                {
                    "role_name": r.role_name,
                    "unused_count": r.unused_services,
                    "blast_radius_reduction": float(r.blast_radius_reduction),
                }
                for r in report.role_reports[:10]
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
        snapshot = session.get_snapshot(snapshot_id)
        if not snapshot:
            return mcp_error(
                MCP_ERROR_SNAPSHOT_NOT_FOUND, "No scan data found. Run 'cyntrisec scan' first."
            )

        findings = session.get_findings(snapshot_id)
        assets = session.get_assets(snapshot_id)
        session.set_snapshot(snapshot_id)

        fw = Framework.CIS_AWS if "cis" in framework.lower() else Framework.SOC2
        checker = ComplianceChecker()
        report = checker.check(findings, assets, framework=fw, collection_errors=snapshot.errors)
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
