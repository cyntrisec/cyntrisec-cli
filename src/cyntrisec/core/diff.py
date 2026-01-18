"""
Snapshot Diff - Compare two scan snapshots to detect changes.

Identifies:
- New assets (added since previous scan)
- Removed assets (gone since previous scan)
- Changed relationships (new connections, removed connections)
- Security regressions (new attack paths, new findings)
- Security improvements (fixed attack paths, resolved findings)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum

from cyntrisec.core.schema import Asset, AttackPath, Finding, Relationship


class ChangeType(str, Enum):
    """Type of change detected."""

    added = "added"
    removed = "removed"
    modified = "modified"


@dataclass
class AssetChange:
    """A change to an asset between snapshots."""

    change_type: ChangeType
    asset: Asset
    previous_asset: Asset | None = None

    @property
    def key(self) -> str:
        """Unique key for the asset (ARN or resource ID)."""
        return self.asset.arn or self.asset.aws_resource_id


@dataclass
class RelationshipChange:
    """A change to a relationship between snapshots."""

    change_type: ChangeType
    relationship: Relationship
    source_name: str = ""
    target_name: str = ""


@dataclass
class PathChange:
    """A change to an attack path between snapshots."""

    change_type: ChangeType
    path: AttackPath
    is_regression: bool = False  # True if this is a NEW attack path (bad)
    is_improvement: bool = False  # True if this is a REMOVED attack path (good)


@dataclass
class FindingChange:
    """A change to a security finding between snapshots."""

    change_type: ChangeType
    finding: Finding
    is_regression: bool = False
    is_improvement: bool = False


@dataclass
class DiffResult:
    """
    Result of comparing two snapshots.

    Attributes:
        old_snapshot_id: ID of the baseline snapshot
        new_snapshot_id: ID of the current snapshot
        asset_changes: New/removed/modified assets
        relationship_changes: New/removed relationships
        path_changes: New/removed attack paths
        finding_changes: New/resolved findings
        summary: High-level summary stats
    """

    old_snapshot_id: uuid.UUID
    new_snapshot_id: uuid.UUID
    asset_changes: list[AssetChange] = field(default_factory=list)
    relationship_changes: list[RelationshipChange] = field(default_factory=list)
    path_changes: list[PathChange] = field(default_factory=list)
    finding_changes: list[FindingChange] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        """Summary statistics of changes."""
        return {
            "assets_added": sum(1 for c in self.asset_changes if c.change_type == ChangeType.added),
            "assets_removed": sum(
                1 for c in self.asset_changes if c.change_type == ChangeType.removed
            ),
            "relationships_added": sum(
                1 for c in self.relationship_changes if c.change_type == ChangeType.added
            ),
            "relationships_removed": sum(
                1 for c in self.relationship_changes if c.change_type == ChangeType.removed
            ),
            "paths_added": sum(1 for c in self.path_changes if c.change_type == ChangeType.added),
            "paths_removed": sum(
                1 for c in self.path_changes if c.change_type == ChangeType.removed
            ),
            "findings_new": sum(
                1 for c in self.finding_changes if c.change_type == ChangeType.added
            ),
            "findings_resolved": sum(
                1 for c in self.finding_changes if c.change_type == ChangeType.removed
            ),
        }

    @property
    def has_regressions(self) -> bool:
        """Check if there are security regressions."""
        return any(c.is_regression for c in self.path_changes) or any(
            c.is_regression for c in self.finding_changes
        )

    @property
    def has_improvements(self) -> bool:
        """Check if there are security improvements."""
        return any(c.is_improvement for c in self.path_changes) or any(
            c.is_improvement for c in self.finding_changes
        )


class SnapshotDiff:
    """
    Compare two scan snapshots to detect changes.

    Useful for:
    - Configuration drift detection
    - Security regression testing
    - Change auditing
    """

    def diff(
        self,
        *,
        old_assets: list[Asset],
        old_relationships: list[Relationship],
        old_paths: list[AttackPath],
        old_findings: list[Finding],
        new_assets: list[Asset],
        new_relationships: list[Relationship],
        new_paths: list[AttackPath],
        new_findings: list[Finding],
        old_snapshot_id: uuid.UUID,
        new_snapshot_id: uuid.UUID,
    ) -> DiffResult:
        """
        Compare two snapshots and return all changes.

        Args:
            old_*: Data from baseline snapshot
            new_*: Data from current snapshot

        Returns:
            DiffResult with all detected changes
        """
        result = DiffResult(
            old_snapshot_id=old_snapshot_id,
            new_snapshot_id=new_snapshot_id,
        )

        # Diff assets by ARN/resource ID
        result.asset_changes = self._diff_assets(old_assets, new_assets)

        # Build asset name lookup for relationship display
        asset_names = {a.id: a.name for a in new_assets}
        asset_names.update({a.id: a.name for a in old_assets})

        # Diff relationships by source+target+type
        result.relationship_changes = self._diff_relationships(
            old_relationships, new_relationships, asset_names
        )

        # Diff attack paths by source+target
        result.path_changes = self._diff_paths(old_paths, new_paths)

        # Diff findings by asset+type
        result.finding_changes = self._diff_findings(old_findings, new_findings)

        return result

    def _diff_assets(
        self,
        old: list[Asset],
        new: list[Asset],
    ) -> list[AssetChange]:
        """Diff assets between snapshots."""
        changes = []

        # Key by ARN or resource ID
        old_by_key = {(a.arn or a.aws_resource_id): a for a in old}
        new_by_key = {(a.arn or a.aws_resource_id): a for a in new}

        old_keys = set(old_by_key.keys())
        new_keys = set(new_by_key.keys())

        # Added assets
        for key in new_keys - old_keys:
            changes.append(
                AssetChange(
                    change_type=ChangeType.added,
                    asset=new_by_key[key],
                )
            )

        # Removed assets
        for key in old_keys - new_keys:
            changes.append(
                AssetChange(
                    change_type=ChangeType.removed,
                    asset=old_by_key[key],
                )
            )

        return changes

    def _diff_relationships(
        self,
        old: list[Relationship],
        new: list[Relationship],
        asset_names: dict[uuid.UUID, str],
    ) -> list[RelationshipChange]:
        """Diff relationships between snapshots."""
        changes = []

        # Key by source ARN + target ARN + type (since IDs change between snapshots)
        def rel_key(r: Relationship) -> tuple[str, str, str]:
            return (
                asset_names.get(r.source_asset_id, str(r.source_asset_id)),
                asset_names.get(r.target_asset_id, str(r.target_asset_id)),
                r.relationship_type,
            )

        old_by_key = {rel_key(r): r for r in old}
        new_by_key = {rel_key(r): r for r in new}

        old_keys = set(old_by_key.keys())
        new_keys = set(new_by_key.keys())

        # Added relationships
        for key in new_keys - old_keys:
            rel = new_by_key[key]
            changes.append(
                RelationshipChange(
                    change_type=ChangeType.added,
                    relationship=rel,
                    source_name=key[0],
                    target_name=key[1],
                )
            )

        # Removed relationships
        for key in old_keys - new_keys:
            rel = old_by_key[key]
            changes.append(
                RelationshipChange(
                    change_type=ChangeType.removed,
                    relationship=rel,
                    source_name=key[0],
                    target_name=key[1],
                )
            )

        return changes

    def _diff_paths(
        self,
        old: list[AttackPath],
        new: list[AttackPath],
    ) -> list[PathChange]:
        """Diff attack paths between snapshots."""
        changes = []

        # Key by attack vector + source/target names (from proof)
        def path_key(p: AttackPath) -> tuple[str, str, str]:
            proof = p.proof or {}
            steps = proof.get("steps", [])
            source_name = steps[0].get("name", "") if steps else ""
            target_name = steps[-1].get("name", "") if steps else ""
            return (p.attack_vector, source_name, target_name)

        old_by_key = {path_key(p): p for p in old}
        new_by_key = {path_key(p): p for p in new}

        old_keys = set(old_by_key.keys())
        new_keys = set(new_by_key.keys())

        # New attack paths (regressions!)
        for key in new_keys - old_keys:
            changes.append(
                PathChange(
                    change_type=ChangeType.added,
                    path=new_by_key[key],
                    is_regression=True,
                )
            )

        # Removed attack paths (improvements!)
        for key in old_keys - new_keys:
            changes.append(
                PathChange(
                    change_type=ChangeType.removed,
                    path=old_by_key[key],
                    is_improvement=True,
                )
            )

        return changes

    def _diff_findings(
        self,
        old: list[Finding],
        new: list[Finding],
    ) -> list[FindingChange]:
        """Diff findings between snapshots."""
        changes = []

        # Key by finding type + title (normalized)
        def finding_key(f: Finding) -> tuple[str, str]:
            return (f.finding_type, f.title.lower())

        old_by_key = {finding_key(f): f for f in old}
        new_by_key = {finding_key(f): f for f in new}

        old_keys = set(old_by_key.keys())
        new_keys = set(new_by_key.keys())

        # New findings (regressions)
        for key in new_keys - old_keys:
            changes.append(
                FindingChange(
                    change_type=ChangeType.added,
                    finding=new_by_key[key],
                    is_regression=True,
                )
            )

        # Removed findings (improvements)
        for key in old_keys - new_keys:
            changes.append(
                FindingChange(
                    change_type=ChangeType.removed,
                    finding=old_by_key[key],
                    is_improvement=True,
                )
            )

        return changes
