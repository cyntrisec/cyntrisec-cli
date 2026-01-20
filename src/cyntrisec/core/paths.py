"""
Attack Path Finder - Heuristic-based attack path discovery.

Finds paths from internet-facing entry points to sensitive targets
through the capability graph. Uses a priority queue (best-first search)
to prioritize highest-risk paths.
"""

from __future__ import annotations

import hashlib
import heapq
import uuid
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

    Uses Best-First Search (Priority Queue) to find highest-risk paths first.
    
    Risk Heuristic:
    - Prioritizes paths starting from high-confidence entry points.
    - Penalizes length (shorter paths = higher exploitability).
    """

    def __init__(self, config: PathFinderConfig | None = None):
        self._config = config or PathFinderConfig()

    def find_paths(
        self,
        graph: AwsGraph,
        snapshot_id: uuid.UUID,
    ) -> list[AttackPath]:
        """
        Find all attack paths in the graph using k-best search.
        """
        entry_points = graph.entry_points()
        targets = {t.id: t for t in graph.sensitive_targets()}

        if not entry_points or not targets:
            return []

        # Priority Queue: (-heuristic_score, path_len, current_id, path_assets, path_rels)
        queue = []
        for entry in entry_points:
            # Initial score based on entry confidence alone (length=1)
            score = self._calculate_heuristic(entry, 1)
            # Use negative score for max-heap behavior
            heapq.heappush(queue, (-score, 1, entry.id, [entry.id], []))

        found_paths: list[AttackPath] = []
        visited_path_hashes: set[str] = set()
        
        # Limit visits per node to prevent explosion while finding alternative paths
        # (asset_id -> visit_count)
        node_visits: dict[uuid.UUID, int] = {}
        MAX_VISITS_PER_NODE = 5

        while queue and len(found_paths) < self._config.max_paths:
            neg_score, length, current_id, path_assets, path_rels = heapq.heappop(queue)
            
            # Pruning
            if length >= self._config.max_depth:
                continue
            
            # Count visits
            node_visits[current_id] = node_visits.get(current_id, 0) + 1
            if node_visits[current_id] > MAX_VISITS_PER_NODE:
                 # Prun if we've processed this node too many times via different paths
                 continue

            # Check if we reached a target
            if current_id in targets:
                # We found a path!
                # Since we pulled from PQ, this is the "next best" path available.
                
                # Check duplication
                path_hash = self._hash_path(path_assets)
                if path_hash in visited_path_hashes:
                    continue
                visited_path_hashes.add(path_hash)

                attack_path = self._create_path(
                    graph=graph,
                    snapshot_id=snapshot_id,
                    path_assets=path_assets,
                    path_rels=path_rels,
                )
                
                # Filter low risk
                if float(attack_path.risk_score) >= self._config.min_risk_score:
                    found_paths.append(attack_path)
                    
                # We don't stop exploring from targets (pivoting through DBs?)
                # But usually targets are endpoints. Let's continue exploring.

            # Expand neighbors
            for rel in graph.edges_from(current_id):
                next_id = rel.target_asset_id

                # Cycle prevention
                if next_id in path_assets:
                    continue

                new_assets = path_assets + [next_id]
                new_rels = path_rels + [rel.id]
                new_len = length + 1
                
                # Heuristic: EntryConf * (1 - 0.1 * new_len)
                # We base heuristic on the Entry Asset (path_assets[0])
                entry_asset = graph.asset(path_assets[0])
                new_score = self._calculate_heuristic(entry_asset, new_len)
                
                heapq.heappush(queue, (-new_score, new_len, next_id, new_assets, new_rels))

        return found_paths

    def find_paths_between(
        self,
        graph: AwsGraph,
        source_id: uuid.UUID,
        target_id: uuid.UUID,
        max_depth: int = 5,
    ) -> list[list[uuid.UUID]]:
        """
        Find paths between two specific assets (for Business Logic).
        Returns list of asset_id lists.
        """
        # Simple BFS is usually fine for connectivity checks
        paths = []
        queue = deque([(source_id, [source_id])])
        visited_hashes = set()
        
        while queue and len(paths) < 10:
             curr, path = queue.popleft()
             if curr == target_id:
                 paths.append(path)
                 continue
             
             if len(path) >= max_depth:
                 continue
                 
             for rel in graph.edges_from(curr):
                 nxt = rel.target_asset_id
                 if nxt not in path:
                     new_path = path + [nxt]
                     ph = self._hash_path(new_path)
                     if ph not in visited_hashes:
                         visited_hashes.add(ph)
                         queue.append((nxt, new_path))
        return paths

    def _calculate_heuristic(self, entry_asset: Asset | None, length: int) -> float:
        """
        Calculate heuristic score for best-first search.
        Higher is better (higher risk).
        """
        entry_conf = self._entry_confidence(entry_asset)
        exploitability = self._exploitability(length)
        # We assume potential impact is 1.0 (unknown) during traversal
        return entry_conf * exploitability

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
            # Roles can be impacts if they are Admin
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
