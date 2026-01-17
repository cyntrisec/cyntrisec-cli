"""
Filesystem Storage - Persist scan results to JSON files.

Directory structure:
    ~/.cyntrisec/scans/
    ├── 2026-01-16_123456_123456789012/
    │   ├── snapshot.json
    │   ├── assets.json
    │   ├── relationships.json
    │   ├── findings.json
    │   └── attack_paths.json
    └── latest -> 2026-01-16_123456_123456789012
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from cyntrisec.core.schema import (
    Asset,
    AttackPath,
    Finding,
    Relationship,
    Snapshot,
)
from cyntrisec.storage.protocol import StorageBackend


class FileSystemStorage(StorageBackend):
    """
    Persist scan results to JSON files.
    
    Default location: ~/.cyntrisec/scans/
    Each scan gets a timestamped directory.
    A 'latest' symlink points to the most recent scan.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        home_dir = Path(os.environ.get("HOME") or os.environ.get("USERPROFILE") or Path.home())
        self._base = base_dir or home_dir / ".cyntrisec" / "scans"
        self._base.mkdir(parents=True, exist_ok=True)
        self._current_dir: Optional[Path] = None
        self._current_id: Optional[str] = None

    def new_scan(self, account_id: str) -> str:
        """Create a new scan directory."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
        scan_id = f"{timestamp}_{account_id}"
        self._current_id = scan_id
        self._current_dir = self._base / scan_id
        self._current_dir.mkdir(parents=True, exist_ok=True)
        
        # Update 'latest' symlink
        latest_link = self._base / "latest"
        if latest_link.is_symlink():
            latest_link.unlink()
        elif latest_link.exists():
            # It's a file or directory, remove it
            if latest_link.is_dir():
                import shutil
                shutil.rmtree(latest_link)
            else:
                latest_link.unlink()
        
        # Create symlink (Windows needs special handling)
        try:
            latest_link.symlink_to(self._current_dir.name)
        except OSError:
            # On Windows without dev mode, just write the name to a file
            latest_link.write_text(self._current_dir.name)
        
        return scan_id

    def _get_scan_dir(self, scan_id: Optional[str] = None) -> Path:
        """Get the directory for a scan ID."""
        if scan_id:
            return self._base / scan_id
        if self._current_dir:
            return self._current_dir
        
        # Try to get latest
        latest_link = self._base / "latest"
        if latest_link.is_symlink():
            return self._base / os.readlink(latest_link)
        elif latest_link.exists() and latest_link.is_file():
            # Windows fallback: file contains directory name
            return self._base / latest_link.read_text().strip()
        
        raise ValueError("No scan specified and no latest scan found")

    def _write_json(self, path: Path, data: any) -> None:
        """Write data to JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def _read_json(self, path: Path) -> any:
        """Read data from JSON file."""
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_snapshot(self, snapshot: Snapshot) -> None:
        scan_dir = self._get_scan_dir()
        self._write_json(scan_dir / "snapshot.json", snapshot.model_dump(mode="json"))

    def save_assets(self, assets: List[Asset]) -> None:
        scan_dir = self._get_scan_dir()
        # Sort by id for deterministic output
        sorted_assets = sorted(assets, key=lambda a: str(a.id))
        data = [a.model_dump(mode="json") for a in sorted_assets]
        self._write_json(scan_dir / "assets.json", data)

    def save_relationships(self, relationships: List[Relationship]) -> None:
        scan_dir = self._get_scan_dir()
        # Sort by id for deterministic output
        sorted_rels = sorted(relationships, key=lambda r: str(r.id))
        data = [r.model_dump(mode="json") for r in sorted_rels]
        self._write_json(scan_dir / "relationships.json", data)

    def save_findings(self, findings: List[Finding]) -> None:
        scan_dir = self._get_scan_dir()
        # Sort by id for deterministic output
        sorted_findings = sorted(findings, key=lambda f: str(f.id))
        data = [f.model_dump(mode="json") for f in sorted_findings]
        self._write_json(scan_dir / "findings.json", data)

    def save_attack_paths(self, paths: List[AttackPath]) -> None:
        scan_dir = self._get_scan_dir()
        # Sort by risk_score (desc), then id for deterministic output
        sorted_paths = sorted(paths, key=lambda p: (-float(p.risk_score), str(p.id)))
        data = [p.model_dump(mode="json") for p in sorted_paths]
        self._write_json(scan_dir / "attack_paths.json", data)

    def get_snapshot(self, scan_id: Optional[str] = None) -> Optional[Snapshot]:
        try:
            scan_dir = self._get_scan_dir(scan_id)
        except ValueError:
            return None
        data = self._read_json(scan_dir / "snapshot.json")
        return Snapshot.model_validate(data) if data else None

    def get_assets(self, scan_id: Optional[str] = None) -> List[Asset]:
        try:
            scan_dir = self._get_scan_dir(scan_id)
        except ValueError:
            return []
        data = self._read_json(scan_dir / "assets.json")
        return [Asset.model_validate(a) for a in (data or [])]

    def get_relationships(self, scan_id: Optional[str] = None) -> List[Relationship]:
        try:
            scan_dir = self._get_scan_dir(scan_id)
        except ValueError:
            return []
        data = self._read_json(scan_dir / "relationships.json")
        return [Relationship.model_validate(r) for r in (data or [])]

    def get_findings(self, scan_id: Optional[str] = None) -> List[Finding]:
        try:
            scan_dir = self._get_scan_dir(scan_id)
        except ValueError:
            return []
        data = self._read_json(scan_dir / "findings.json")
        return [Finding.model_validate(f) for f in (data or [])]

    def get_attack_paths(self, scan_id: Optional[str] = None) -> List[AttackPath]:
        try:
            scan_dir = self._get_scan_dir(scan_id)
        except ValueError:
            return []
        data = self._read_json(scan_dir / "attack_paths.json")
        return [AttackPath.model_validate(p) for p in (data or [])]

    def export_all(self, scan_id: Optional[str] = None) -> Dict:
        """Export all scan data as a dictionary."""
        snapshot = self.get_snapshot(scan_id)
        return {
            "snapshot": snapshot.model_dump(mode="json") if snapshot else None,
            "assets": [a.model_dump(mode="json") for a in self.get_assets(scan_id)],
            "relationships": [r.model_dump(mode="json") for r in self.get_relationships(scan_id)],
            "findings": [f.model_dump(mode="json") for f in self.get_findings(scan_id)],
            "attack_paths": [p.model_dump(mode="json") for p in self.get_attack_paths(scan_id)],
            "metadata": {
                "exported_at": datetime.utcnow().isoformat() + "Z",
                "scan_id": scan_id or self._current_id,
            },
        }

    def list_scans(self) -> List[str]:
        """List all available scan directories."""
        scans = []
        for item in self._base.iterdir():
            if item.is_dir() and item.name != "latest":
                scans.append(item.name)
        return sorted(scans, reverse=True)  # Most recent first

    def list_snapshots(self) -> List[Snapshot]:
        """List all available snapshots, sorted by date (most recent first)."""
        snapshots = []
        for scan_id in self.list_scans():
            snapshot = self.get_snapshot(scan_id)
            if snapshot:
                snapshots.append(snapshot)
        # Sort by started_at descending
        return sorted(snapshots, key=lambda s: s.started_at, reverse=True)

    def get_scan_path(self, scan_id: Optional[str] = None) -> Path:
        """Get the filesystem path for a scan directory."""
        return self._get_scan_dir(scan_id)

