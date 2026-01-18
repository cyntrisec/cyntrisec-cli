"""
Attack Path Finder - BFS-based attack path discovery.

Finds paths from internet-facing entry points to sensitive targets
through the capability graph.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import deque
from dataclasses import dataclass
from decimal import Decimal

from cyntrisec.core.graph import AwsGraph
from cyntrisec.core.schema import Asset, AttackPath


@dataclass
class PathFinderConfig:
    """Configuration for attack path discovery."""

    max_depth: int = 8
    max_paths: int = 200
    min_risk_score: float = 0.0


class PathFinder:
    """
    Discovers attack paths through the capability graph.

    Uses BFS from entry points to find all paths to sensitive targets.
    Calculates risk scores based on:
    - Entry confidence: How accessible is the entry point
    - Exploitability: How easy is the path to traverse
    - Impact: How valuable is the target

    Example:
        finder = PathFinder()
        paths = finder.find_paths(graph, snapshot_id)
    """

    def __init__(self, config: PathFinderConfig | None = None):
        self._config = config or PathFinderConfig()

    def find_paths(
        self,
        graph: AwsGraph,
        snapshot_id: uuid.UUID,
    ) -> list[AttackPath]:
        """
        Find all attack paths in the graph.

        Args:
            graph: The capability graph to analyze
            snapshot_id: ID of the current scan snapshot

        Returns:
            List of AttackPath objects sorted by risk score
        """
        entry_points = graph.entry_points()
        targets = {t.id for t in graph.sensitive_targets()}

        if not entry_points or not targets:
            return []

        all_paths: list[AttackPath] = []
        visited_hashes: set[str] = set()
        remaining = self._config.max_paths

        for entry in entry_points:
            if remaining <= 0:
                break

            paths = self._bfs_from_entry(
                graph=graph,
                snapshot_id=snapshot_id,
                entry=entry,
                targets=targets,
                max_paths=remaining,
                visited_hashes=visited_hashes,
            )
            all_paths.extend(paths)
            remaining -= len(paths)

        # Sort by risk score descending
        all_paths.sort(key=lambda p: float(p.risk_score), reverse=True)

        # Apply min risk filter
        if self._config.min_risk_score > 0:
            all_paths = [p for p in all_paths if float(p.risk_score) >= self._config.min_risk_score]

        return all_paths[: self._config.max_paths]

    def _bfs_from_entry(
        self,
        *,
        graph: AwsGraph,
        snapshot_id: uuid.UUID,
        entry: Asset,
        targets: set[uuid.UUID],
        max_paths: int,
        visited_hashes: set[str],
    ) -> list[AttackPath]:
        """BFS from a single entry point to find paths to targets."""
        paths: list[AttackPath] = []

        # Queue: (current_id, path_assets, path_rels)
        queue: deque[tuple[uuid.UUID, list[uuid.UUID], list[uuid.UUID]]] = deque()
        queue.append((entry.id, [entry.id], []))

        while queue and len(paths) < max_paths:
            current_id, path_assets, path_rels = queue.popleft()

            # Check depth limit
            if len(path_rels) >= self._config.max_depth:
                continue

            # Explore neighbors
            for rel in graph.edges_from(current_id):
                next_id = rel.target_asset_id

                # Avoid cycles
                if next_id in path_assets:
                    continue

                new_path_assets = path_assets + [next_id]
                new_path_rels = path_rels + [rel.id]

                # Deduplicate paths
                path_hash = self._hash_path(new_path_assets)
                if path_hash in visited_hashes:
                    continue
                visited_hashes.add(path_hash)

                # If we reached a target, create attack path
                if next_id in targets:
                    attack_path = self._create_path(
                        graph=graph,
                        snapshot_id=snapshot_id,
                        path_assets=new_path_assets,
                        path_rels=new_path_rels,
                    )
                    paths.append(attack_path)

                    if len(paths) >= max_paths:
                        break

                # Continue exploring
                queue.append((next_id, new_path_assets, new_path_rels))

        return paths

    def _hash_path(self, path_assets: list[uuid.UUID]) -> str:
        """Create a unique hash for a path."""
        path_str = "|".join(str(a) for a in path_assets)
        return hashlib.sha256(path_str.encode()).hexdigest()

    def _create_path(
        self,
        *,
        graph: AwsGraph,
        snapshot_id: uuid.UUID,
        path_assets: list[uuid.UUID],
        path_rels: list[uuid.UUID],
    ) -> AttackPath:
        """Create an AttackPath from discovered path."""
        entry = graph.asset(path_assets[0])
        target = graph.asset(path_assets[-1])

        # Calculate scores
        entry_confidence = self._entry_confidence(entry)
        exploitability = self._exploitability(len(path_rels))
        impact = self._impact_score(target)
        risk = entry_confidence * exploitability * impact

        # Determine attack vector
        vector = self._attack_vector(graph, path_assets)

        # Build proof chain
        proof = self._build_proof(graph, path_assets, path_rels)

        return AttackPath(
            snapshot_id=snapshot_id,
            source_asset_id=path_assets[0],
            target_asset_id=path_assets[-1],
            path_asset_ids=path_assets,
            path_relationship_ids=path_rels,
            attack_vector=vector,
            path_length=len(path_rels),
            entry_confidence=Decimal(str(round(entry_confidence, 4))),
            exploitability_score=Decimal(str(round(exploitability, 4))),
            impact_score=Decimal(str(round(impact, 4))),
            risk_score=Decimal(str(round(risk, 4))),
            proof=proof,
        )

    def _entry_confidence(self, asset: Asset | None) -> float:
        """Calculate entry point accessibility (0-1)."""
        if not asset:
            return 0.5

        # Higher confidence for clearly public resources
        if asset.asset_type == "ec2:instance":
            if asset.properties.get("public_ip"):
                return 0.9
        elif asset.asset_type in ["elbv2:load-balancer", "elb:load-balancer"]:
            if asset.properties.get("scheme") == "internet-facing":
                return 0.85
        elif asset.asset_type == "cloudfront:distribution":
            return 0.8
        elif asset.asset_type == "apigateway:rest-api":
            return 0.75

        return 0.5

    def _exploitability(self, path_length: int) -> float:
        """Calculate exploitability based on path length."""
        # Longer paths are harder to exploit
        return max(0.1, 1.0 - (path_length * 0.1))

    def _impact_score(self, asset: Asset | None) -> float:
        """Calculate impact score of reaching the target (0-1)."""
        if not asset:
            return 0.5

        # High-value targets
        if asset.asset_type in ["rds:db-instance", "dynamodb:table"]:
            return 0.9
        elif asset.asset_type in ["secretsmanager:secret", "ssm:parameter"]:
            name_lower = asset.name.lower()
            if any(kw in name_lower for kw in ["prod", "secret", "key", "password"]):
                return 1.0
            return 0.85
        elif asset.asset_type == "iam:role":
            name_lower = asset.name.lower()
            if any(kw in name_lower for kw in ["admin", "root"]):
                return 0.95
            return 0.6
        elif asset.asset_type == "s3:bucket":
            name_lower = asset.name.lower()
            if any(kw in name_lower for kw in ["backup", "secret", "credential"]):
                return 0.9
            return 0.5

        return 0.5

    def _attack_vector(
        self,
        graph: AwsGraph,
        path_assets: list[uuid.UUID],
    ) -> str:
        """Determine attack vector classification."""
        if not path_assets:
            return "unknown"

        entry = graph.asset(path_assets[0])
        target = graph.asset(path_assets[-1])

        if not entry or not target:
            return "network"

        # Classify based on entry and target types
        if entry.asset_type in ["elbv2:load-balancer", "elb:load-balancer"]:
            return "web-to-infrastructure"
        elif entry.asset_type == "cloudfront:distribution":
            return "cdn-pivot"
        elif entry.asset_type == "apigateway:rest-api":
            return "api-exploitation"
        elif entry.asset_type == "ec2:instance":
            return "instance-compromise"
        elif "iam" in entry.asset_type:
            return "privilege-escalation"

        return "lateral-movement"

    def _build_proof(
        self,
        graph: AwsGraph,
        path_assets: list[uuid.UUID],
        path_rels: list[uuid.UUID],
    ) -> dict:
        """Build proof chain showing why path exists."""
        steps = []

        for i, asset_id in enumerate(path_assets):
            asset = graph.asset(asset_id)
            if not asset:
                continue

            step = {
                "index": i,
                "asset_id": str(asset_id),
                "asset_type": asset.asset_type,
                "name": asset.name,
            }

            # Add relationship info for non-first steps
            if i > 0 and i - 1 < len(path_rels):
                rels = graph.edges_from(path_assets[i - 1])
                for rel in rels:
                    if rel.target_asset_id == asset_id:
                        step["via_relationship"] = {
                            "type": rel.relationship_type,
                            "properties": rel.properties,
                        }
                        break

            steps.append(step)

        return {
            "path_length": len(path_rels),
            "steps": steps,
        }
