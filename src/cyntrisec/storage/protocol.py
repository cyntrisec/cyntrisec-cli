"""
Storage Backend Protocol - Abstract interface for scan storage.

Implementations:
- FileSystemStorage: Persist to JSON files (default)
- InMemoryStorage: Keep in memory (for testing)
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from cyntrisec.core.schema import (
    Asset,
    AttackPath,
    Finding,
    Relationship,
    Snapshot,
)


class StorageBackend(ABC):
    """
    Abstract storage interface.
    
    All methods are synchronous. No database required.
    """

    @abstractmethod
    def new_scan(self, account_id: str) -> str:
        """Initialize storage for a new scan. Returns scan directory/ID."""
        ...

    @abstractmethod
    def save_snapshot(self, snapshot: Snapshot) -> None:
        """Save snapshot metadata."""
        ...

    @abstractmethod
    def save_assets(self, assets: List[Asset]) -> None:
        """Save assets."""
        ...

    @abstractmethod
    def save_relationships(self, relationships: List[Relationship]) -> None:
        """Save relationships."""
        ...

    @abstractmethod
    def save_findings(self, findings: List[Finding]) -> None:
        """Save findings."""
        ...

    @abstractmethod
    def save_attack_paths(self, paths: List[AttackPath]) -> None:
        """Save attack paths."""
        ...

    @abstractmethod
    def get_snapshot(self, scan_id: Optional[str] = None) -> Optional[Snapshot]:
        """Get snapshot for a scan (or latest if not specified)."""
        ...

    @abstractmethod
    def get_assets(self, scan_id: Optional[str] = None) -> List[Asset]:
        """Get all assets for a scan."""
        ...

    @abstractmethod
    def get_relationships(self, scan_id: Optional[str] = None) -> List[Relationship]:
        """Get all relationships for a scan."""
        ...

    @abstractmethod
    def get_findings(self, scan_id: Optional[str] = None) -> List[Finding]:
        """Get all findings for a scan."""
        ...

    @abstractmethod
    def get_attack_paths(self, scan_id: Optional[str] = None) -> List[AttackPath]:
        """Get all attack paths for a scan."""
        ...

    @abstractmethod
    def export_all(self, scan_id: Optional[str] = None) -> Dict:
        """Export all data for a scan as a dictionary."""
        ...

    @abstractmethod
    def list_scans(self) -> List[str]:
        """List all available scan IDs."""
        ...
