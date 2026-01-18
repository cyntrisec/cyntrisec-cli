"""
Capability Graph - In-memory graph representation.

The graph models AWS infrastructure as:
- Nodes: Assets (resources, logical groupings)
- Edges: Relationships (capabilities, permissions, connectivity)
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from cyntrisec.core.schema import Asset, Relationship


@dataclass(frozen=True)
class AwsGraph:
    """
    In-memory capability graph for AWS infrastructure.

    Provides efficient lookups for:
    - Asset by ID
    - Neighbors (outgoing edges)
    - Predecessors (incoming edges)
    - Assets by type

    This is an immutable snapshot of the graph at scan time.
    """

    assets_by_id: dict[uuid.UUID, Asset]
    outgoing: dict[uuid.UUID, list[Relationship]]
    incoming: dict[uuid.UUID, list[Relationship]]

    def asset(self, asset_id: uuid.UUID) -> Asset | None:
        """Get an asset by ID."""
        return self.assets_by_id.get(asset_id)

    def neighbors(self, asset_id: uuid.UUID) -> list[uuid.UUID]:
        """Get IDs of all assets this asset can reach (outgoing edges)."""
        return [rel.target_asset_id for rel in self.outgoing.get(asset_id, [])]

    def predecessors(self, asset_id: uuid.UUID) -> list[uuid.UUID]:
        """Get IDs of all assets that can reach this asset (incoming edges)."""
        return [rel.source_asset_id for rel in self.incoming.get(asset_id, [])]

    def edges_from(self, asset_id: uuid.UUID) -> list[Relationship]:
        """Get all outgoing relationships from an asset."""
        return list(self.outgoing.get(asset_id, []))

    def edges_to(self, asset_id: uuid.UUID) -> list[Relationship]:
        """Get all incoming relationships to an asset."""
        return list(self.incoming.get(asset_id, []))

    def all_assets(self) -> list[Asset]:
        """Get all assets in the graph."""
        return list(self.assets_by_id.values())

    def all_relationships(self) -> list[Relationship]:
        """Get all relationships in the graph."""
        all_rels = []
        for rels in self.outgoing.values():
            all_rels.extend(rels)
        return all_rels

    def asset_count(self) -> int:
        """Get the number of assets."""
        return len(self.assets_by_id)

    def relationship_count(self) -> int:
        """Get the number of relationships."""
        return sum(len(rels) for rels in self.outgoing.values())

    def assets_by_type(self, asset_type: str) -> list[Asset]:
        """Get all assets of a specific type."""
        return [a for a in self.assets_by_id.values() if a.asset_type == asset_type]

    def entry_points(self) -> list[Asset]:
        """
        Get all internet-facing entry points.

        Entry points are assets marked as internet_facing or
        have specific types (public IPs, load balancers, etc.)
        """
        entries = []
        for asset in self.assets_by_id.values():
            if asset.is_internet_facing:
                entries.append(asset)
            elif asset.asset_type in [
                "ec2:elastic-ip",
                "elbv2:load-balancer",
                "elb:load-balancer",
                "cloudfront:distribution",
                "apigateway:rest-api",
            ]:
                if asset.properties.get("scheme") == "internet-facing":
                    entries.append(asset)
                elif asset.properties.get("public_ip"):
                    entries.append(asset)
        return entries

    def sensitive_targets(self) -> list[Asset]:
        """
        Get all sensitive target assets.

        Targets are assets marked as sensitive or have specific types
        (databases, secrets, admin roles).
        """
        targets = []
        for asset in self.assets_by_id.values():
            if asset.is_sensitive_target:
                targets.append(asset)
            elif asset.asset_type in [
                "rds:db-instance",
                "dynamodb:table",
                "secretsmanager:secret",
                "ssm:parameter",
            ]:
                targets.append(asset)
            elif asset.asset_type == "iam:role":
                name_lower = asset.name.lower()
                if any(kw in name_lower for kw in ["admin", "root", "power"]):
                    targets.append(asset)
            elif asset.asset_type == "s3:bucket":
                name_lower = asset.name.lower()
                if any(kw in name_lower for kw in ["secret", "credential", "backup"]):
                    targets.append(asset)
        return targets


class GraphBuilder:
    """
    Builds an AwsGraph from assets and relationships.

    Example:
        builder = GraphBuilder()
        graph = builder.build(assets=assets, relationships=relationships)
    """

    def build(
        self,
        *,
        assets: Sequence[Asset],
        relationships: Sequence[Relationship],
    ) -> AwsGraph:
        """
        Build a graph from assets and relationships.

        Only includes relationships where both endpoints exist
        in the provided asset list.
        """
        assets_by_id: dict[uuid.UUID, Asset] = {asset.id: asset for asset in assets}
        outgoing: dict[uuid.UUID, list[Relationship]] = {}
        incoming: dict[uuid.UUID, list[Relationship]] = {}

        for rel in relationships:
            # Skip relationships with missing endpoints
            if rel.source_asset_id not in assets_by_id:
                continue
            if rel.target_asset_id not in assets_by_id:
                continue

            outgoing.setdefault(rel.source_asset_id, []).append(rel)
            incoming.setdefault(rel.target_asset_id, []).append(rel)

        return AwsGraph(
            assets_by_id=assets_by_id,
            outgoing=outgoing,
            incoming=incoming,
        )
