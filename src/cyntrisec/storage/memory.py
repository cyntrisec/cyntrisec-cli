"""
In-Memory Storage - Keep scan results in memory.

Useful for testing and single-run analysis without persistence.
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from cyntrisec.core.schema import (
    Asset,
    AttackPath,
    Finding,
    Relationship,
    Snapshot,
)
from cyntrisec.storage.protocol import StorageBackend


class InMemoryStorage(StorageBackend):
    """
    Keep scan results in memory.
    
    Data is lost when the process exits.
    Useful for testing and ephemeral analysis.
    """

    def __init__(self):
        self._scans: Dict[str, Dict] = {}
        self._current_id: Optional[str] = None

    def new_scan(self, account_id: str) -> str:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
        scan_id = f"{timestamp}_{account_id}"
        self._current_id = scan_id
        self._scans[scan_id] = {
            "snapshot": None,
            "assets": [],
            "relationships": [],
            "findings": [],
            "attack_paths": [],
        }
        return scan_id

    def _get_scan(self, scan_id: Optional[str] = None) -> Dict:
        sid = scan_id or self._current_id
        if not sid or sid not in self._scans:
            raise ValueError(f"Scan not found: {sid}")
        return self._scans[sid]

    def save_snapshot(self, snapshot: Snapshot) -> None:
        self._get_scan()["snapshot"] = snapshot

    def save_assets(self, assets: List[Asset]) -> None:
        self._get_scan()["assets"] = assets

    def save_relationships(self, relationships: List[Relationship]) -> None:
        self._get_scan()["relationships"] = relationships

    def save_findings(self, findings: List[Finding]) -> None:
        self._get_scan()["findings"] = findings

    def save_attack_paths(self, paths: List[AttackPath]) -> None:
        self._get_scan()["attack_paths"] = paths

    def get_snapshot(self, scan_id: Optional[str] = None) -> Optional[Snapshot]:
        try:
            return self._get_scan(scan_id)["snapshot"]
        except ValueError:
            return None

    def get_assets(self, scan_id: Optional[str] = None) -> List[Asset]:
        try:
            return self._get_scan(scan_id)["assets"]
        except ValueError:
            return []

    def get_relationships(self, scan_id: Optional[str] = None) -> List[Relationship]:
        try:
            return self._get_scan(scan_id)["relationships"]
        except ValueError:
            return []

    def get_findings(self, scan_id: Optional[str] = None) -> List[Finding]:
        try:
            return self._get_scan(scan_id)["findings"]
        except ValueError:
            return []

    def get_attack_paths(self, scan_id: Optional[str] = None) -> List[AttackPath]:
        try:
            return self._get_scan(scan_id)["attack_paths"]
        except ValueError:
            return []

    def export_all(self, scan_id: Optional[str] = None) -> Dict:
        scan = self._get_scan(scan_id)
        snapshot = scan["snapshot"]
        return {
            "snapshot": snapshot.model_dump(mode="json") if snapshot else None,
            "assets": [a.model_dump(mode="json") for a in scan["assets"]],
            "relationships": [r.model_dump(mode="json") for r in scan["relationships"]],
            "findings": [f.model_dump(mode="json") for f in scan["findings"]],
            "attack_paths": [p.model_dump(mode="json") for p in scan["attack_paths"]],
            "metadata": {
                "exported_at": datetime.utcnow().isoformat() + "Z",
                "scan_id": scan_id or self._current_id,
            },
        }

    def list_scans(self) -> List[str]:
        return sorted(self._scans.keys(), reverse=True)
