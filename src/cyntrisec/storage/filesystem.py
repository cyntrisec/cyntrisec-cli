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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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

    def __init__(self, base_dir: Path | str | None = None):
        home_dir = Path(os.environ.get("HOME") or os.environ.get("USERPROFILE") or Path.home())
        if base_dir is None:
            self._base = home_dir / ".cyntrisec" / "scans"
        else:
            self._base = Path(base_dir)  # Convert string to Path if needed
        self._base.mkdir(parents=True, exist_ok=True)
        self._current_dir: Path | None = None
        self._current_id: str | None = None

    def new_scan(self, account_id: str) -> str:
        """Create a new scan directory."""
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d_%H%M%S")
        scan_id = f"{timestamp}_{account_id}"
        self._validate_scan_id(scan_id)
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
            latest_link.write_text(self._current_dir.name, encoding="utf-8")

        return scan_id

    def _validate_scan_id(self, scan_id: str) -> str:
        """
        Validate that scan_id is a safe directory name.
        Reject: empty, .., path separators.
        """
        scan_id = (scan_id or "").strip()
        if not scan_id:
            raise ValueError("Invalid scan id: empty")
        if scan_id in {".", "..", "latest"}:
            raise ValueError(f"Invalid scan id: {scan_id}")
        if any(ord(ch) < 32 or ch == "\x7f" for ch in scan_id):
            raise ValueError(f"Invalid scan id: {scan_id}")
        if len(scan_id) > 200:
            raise ValueError(f"Invalid scan id: too long ({len(scan_id)})")
        if "\x00" in scan_id or any(x in scan_id for x in ("..", "/", "\\", ":")):
            raise ValueError(f"Invalid scan id: {scan_id}")
        return scan_id

    def _safe_join_scan_dir(self, scan_id: str) -> Path:
        """
        Safely resolve scan directory ensuring it stays within base.
        """
        self._validate_scan_id(scan_id)
        base = self._base.resolve()
        # Resolve the candidate path
        # Note: on Windows resolving a non-existent path might be tricky if we don't catch errors,
        # but here we generally expect to create or read it.
        # We construct it simply first.
        candidate = (base / scan_id).resolve()

        # Security check: must be inside base
        # python 3.9+ has is_relative_to
        if not candidate.is_relative_to(base) or candidate == base:
            raise ValueError(f"Scan dir escapes base dir: {scan_id}")

        return candidate

    def _get_scan_dir(self, scan_id: str | None = None) -> Path:
        """Get the directory for a scan ID."""
        if scan_id:
            return self._safe_join_scan_dir(scan_id)

        if self._current_dir:
            return self._current_dir

        # Try to get latest
        latest_link = self._base / "latest"
        target_id = None

        if latest_link.is_symlink():
            target_id = os.readlink(latest_link)
        elif latest_link.exists() and latest_link.is_file():
            # Windows fallback: file contains directory name
            target_id = latest_link.read_text().strip()

        if target_id:
            return self._safe_join_scan_dir(target_id)

        raise ValueError("No scan specified and no latest scan found")

    def _write_json(self, path: Path, data: Any) -> None:
        """Write data to JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def _read_json(self, path: Path) -> Any:
        """Read data from JSON file."""
        if not path.exists():
            return None
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def save_snapshot(self, snapshot: Snapshot) -> None:
        scan_dir = self._get_scan_dir()
        self._write_json(scan_dir / "snapshot.json", snapshot.model_dump(mode="json"))

    def save_assets(self, assets: list[Asset]) -> None:
        scan_dir = self._get_scan_dir()
        # Sort by id for deterministic output
        sorted_assets = sorted(assets, key=lambda a: str(a.id))
        data = [a.model_dump(mode="json") for a in sorted_assets]
        self._write_json(scan_dir / "assets.json", data)

    def save_relationships(self, relationships: list[Relationship]) -> None:
        scan_dir = self._get_scan_dir()
        # Sort by id for deterministic output
        sorted_rels = sorted(relationships, key=lambda r: str(r.id))
        data = [r.model_dump(mode="json") for r in sorted_rels]
        self._write_json(scan_dir / "relationships.json", data)

    def save_findings(self, findings: list[Finding]) -> None:
        scan_dir = self._get_scan_dir()
        # Sort by id for deterministic output
        sorted_findings = sorted(findings, key=lambda f: str(f.id))
        data = [f.model_dump(mode="json") for f in sorted_findings]
        self._write_json(scan_dir / "findings.json", data)

    def save_attack_paths(self, paths: list[AttackPath]) -> None:
        scan_dir = self._get_scan_dir()
        # Sort by risk_score (desc), then id for deterministic output
        sorted_paths = sorted(paths, key=lambda p: (-float(p.risk_score), str(p.id)))
        data = [p.model_dump(mode="json") for p in sorted_paths]
        self._write_json(scan_dir / "attack_paths.json", data)

    def get_snapshot(self, scan_id: str | None = None) -> Snapshot | None:
        resolved_id = self.resolve_scan_id(scan_id)
        if resolved_id is None:
            return None
        try:
            scan_dir = self._get_scan_dir(resolved_id)
        except ValueError:
            return None
        data = self._read_json(scan_dir / "snapshot.json")
        return Snapshot.model_validate(data) if data else None

    def get_assets(self, scan_id: str | None = None) -> list[Asset]:
        resolved_id = self.resolve_scan_id(scan_id)
        if resolved_id is None:
            return []
        try:
            scan_dir = self._get_scan_dir(resolved_id)
        except ValueError:
            return []
        data = self._read_json(scan_dir / "assets.json")
        return [Asset.model_validate(a) for a in (data or [])]

    def get_relationships(self, scan_id: str | None = None) -> list[Relationship]:
        resolved_id = self.resolve_scan_id(scan_id)
        if resolved_id is None:
            return []
        try:
            scan_dir = self._get_scan_dir(resolved_id)
        except ValueError:
            return []
        data = self._read_json(scan_dir / "relationships.json")
        return [Relationship.model_validate(r) for r in (data or [])]

    def get_findings(self, scan_id: str | None = None) -> list[Finding]:
        resolved_id = self.resolve_scan_id(scan_id)
        if resolved_id is None:
            return []
        try:
            scan_dir = self._get_scan_dir(resolved_id)
        except ValueError:
            return []
        data = self._read_json(scan_dir / "findings.json")
        return [Finding.model_validate(f) for f in (data or [])]

    def get_attack_paths(self, scan_id: str | None = None) -> list[AttackPath]:
        resolved_id = self.resolve_scan_id(scan_id)
        if resolved_id is None:
            return []
        try:
            scan_dir = self._get_scan_dir(resolved_id)
        except ValueError:
            return []
        data = self._read_json(scan_dir / "attack_paths.json")
        return [AttackPath.model_validate(p) for p in (data or [])]

    def export_all(self, scan_id: str | None = None) -> dict:
        """Export all scan data as a dictionary."""
        snapshot = self.get_snapshot(scan_id)
        return {
            "snapshot": snapshot.model_dump(mode="json") if snapshot else None,
            "assets": [a.model_dump(mode="json") for a in self.get_assets(scan_id)],
            "relationships": [r.model_dump(mode="json") for r in self.get_relationships(scan_id)],
            "findings": [f.model_dump(mode="json") for f in self.get_findings(scan_id)],
            "attack_paths": [p.model_dump(mode="json") for p in self.get_attack_paths(scan_id)],
            "metadata": {
                "exported_at": datetime.now(UTC).isoformat() + "Z",
                "scan_id": scan_id or self._current_id,
            },
        }

    def list_scans(self) -> list[str]:
        """List all available scan directories."""
        scans = []
        for item in self._base.iterdir():
            if item.is_dir() and item.name != "latest":
                try:
                    scans.append(self._validate_scan_id(item.name))
                except ValueError:
                    continue
        return sorted(scans, reverse=True)  # Most recent first

    def resolve_scan_id(self, identifier: str | None) -> str | None:
        """
        Resolve an identifier to a scan_id (directory name).

        Accepts:
        - scan_id (directory name): returned as-is if valid (and safe!)
        - snapshot UUID: looks up the scan directory containing that snapshot
        - None: returns latest scan_id

        Returns:
            scan_id (directory name) or None if not found
        """
        if identifier is None:
            # Return latest scan_id
            latest_link = self._base / "latest"
            target = None
            if latest_link.is_symlink():
                target = os.readlink(latest_link)
            elif latest_link.exists() and latest_link.is_file():
                # Windows fallback: file contains directory name
                target = latest_link.read_text().strip()

            if target:
                try:
                    # Validate that the latest target is a safe ID
                    return self._validate_scan_id(target)
                except ValueError:
                    # If latest is corrupt/malicious, ignore it and fall back to listing
                    pass

            # No latest, try to get most recent scan
            scans = self.list_scans()
            return scans[0] if scans else None

        # Check if it's already a valid scan directory
        try:
            # Use safe join to verify it is a valid scan directory under base.
            scan_dir = self._safe_join_scan_dir(identifier)
            if scan_dir.exists() and scan_dir.is_dir():
                return identifier
        except (ValueError, OSError):
            # Not a simple scan dir, proceed to check if it's a UUID
            pass

        # Try to find by UUID - iterate through scans and check snapshot.id
        for scan_id in self.list_scans():
            # We trust list_scans() to return safe directory names from self._base
            try:
                scan_dir = self._safe_join_scan_dir(scan_id)
            except ValueError:
                continue
            snapshot_path = scan_dir / "snapshot.json"
            if snapshot_path.exists():
                data = self._read_json(snapshot_path)
                if data and str(data.get("id", "")) == identifier:
                    return scan_id

        return None

    def list_snapshots(self) -> list[Snapshot]:
        """List all available snapshots, sorted by date (most recent first)."""
        snapshots = []
        for scan_id in self.list_scans():
            # list_scans returns directory names, so they should be safe,
            # but using get_snapshot calls resolve_scan_id again which is safe.
            snapshot = self.get_snapshot(scan_id)
            if snapshot:
                snapshots.append(snapshot)
        # Sort by started_at descending
        return sorted(snapshots, key=lambda s: s.started_at, reverse=True)

    def get_scan_path(self, scan_id: str | None = None) -> Path:
        """Get the filesystem path for a scan directory."""
        resolved_id = self.resolve_scan_id(scan_id)
        if resolved_id is None:
            raise ValueError("No scan specified and no latest scan found")
        return self._get_scan_dir(resolved_id)
