"""
Minimal Cut Finder - Find optimal remediations that block attack paths.

Uses a vertex-cover approximation approach to find the minimum set of
edges (relationships) whose removal disconnects all entry points from
all sensitive targets.

The algorithm works by:
1. Building a flow network from entry points to targets
2. Finding edges that appear on multiple attack paths
3. Selecting edges that block the most paths with fewest changes
"""
from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Dict, List, Optional, Set, Tuple

from cyntrisec.core.graph import AwsGraph
from cyntrisec.core.schema import AttackPath, CostCutCandidate, Relationship


@dataclass
class Remediation:
    """
    A proposed remediation action that blocks attack paths.
    
    Attributes:
        relationship: The edge to remove/modify
        action: Type of remediation (remove, restrict, isolate)
        description: Human-readable description
        paths_blocked: List of attack path IDs this blocks
        priority: Higher = blocks more paths with less effort
    """
    relationship: Relationship
    action: str
    description: str
    paths_blocked: List[uuid.UUID] = field(default_factory=list)
    priority: float = 0.0
    
    # Metadata for display
    source_name: str = ""
    target_name: str = ""
    relationship_type: str = ""


@dataclass 
class CutResult:
    """
    Result of the minimal cut analysis.
    
    Attributes:
        remediations: Ordered list of recommended fixes (highest impact first)
        total_paths: Total attack paths in the graph
        paths_blocked: Number of paths blocked by all remediations
        coverage: Percentage of paths blocked (0-1)
    """
    remediations: List[Remediation]
    total_paths: int
    paths_blocked: int
    coverage: float


class MinCutFinder:
    """
    Finds minimal set of edge removals to block all attack paths.
    
    Uses a greedy set-cover approximation:
    1. Count how many attack paths each edge appears on
    2. Select edge that appears on most paths
    3. Remove those paths from consideration
    4. Repeat until all paths covered or budget exhausted
    
    This is O(E * P) where E = edges, P = paths. The greedy approach
    gives a ln(n) approximation to the optimal min-cut.
    """

    def find_cuts(
        self,
        graph: AwsGraph,
        paths: List[AttackPath],
        *,
        max_cuts: int = 10,
        relationship_types: Optional[Set[str]] = None,
    ) -> CutResult:
        """
        Find minimal set of edges to remove that blocks all attack paths.
        
        Args:
            graph: The capability graph
            paths: Attack paths discovered by PathFinder
            max_cuts: Maximum number of remediations to return
            relationship_types: If provided, only consider these edge types
            
        Returns:
            CutResult with ordered list of remediations
        """
        if not paths:
            return CutResult(
                remediations=[],
                total_paths=0,
                paths_blocked=0,
                coverage=1.0,
            )

        # Build indexes
        edge_to_paths, relationship_lookup = self._build_indexes(graph, paths)

        # Greedy set cover
        remediations: List[Remediation] = []
        remaining_paths: Set[uuid.UUID] = {p.id for p in paths}
        used_edges: Set[uuid.UUID] = set()

        while remaining_paths and len(remediations) < max_cuts:
            best_edge_id, best_coverage = self._find_best_edge(
                edge_to_paths, relationship_lookup, used_edges, 
                remaining_paths, relationship_types
            )

            if not best_edge_id or not best_coverage:
                break

            # Add remediation
            used_edges.add(best_edge_id)
            remaining_paths -= best_coverage
            
            remediation = self._create_remediation(
                graph, relationship_lookup[best_edge_id], best_coverage
            )
            remediations.append(remediation)

        total_paths = len(paths)
        blocked = total_paths - len(remaining_paths)

        return CutResult(
            remediations=remediations,
            total_paths=total_paths,
            paths_blocked=blocked,
            coverage=blocked / total_paths if total_paths > 0 else 1.0,
        )

    def _build_indexes(
        self, graph: AwsGraph, paths: List[AttackPath]
    ) -> Tuple[Dict[uuid.UUID, Set[uuid.UUID]], Dict[uuid.UUID, Relationship]]:
        """Build lookup indexes for edges and relationships."""
        edge_to_paths: Dict[uuid.UUID, Set[uuid.UUID]] = defaultdict(set)
        relationship_lookup: Dict[uuid.UUID, Relationship] = {}
        
        for path in paths:
            for rel_id in path.path_relationship_ids:
                edge_to_paths[rel_id].add(path.id)
                
        for rel in graph.all_relationships():
            relationship_lookup[rel.id] = rel
            
        return edge_to_paths, relationship_lookup

    def _find_best_edge(
        self,
        edge_to_paths: Dict[uuid.UUID, Set[uuid.UUID]],
        relationship_lookup: Dict[uuid.UUID, Relationship],
        used_edges: Set[uuid.UUID],
        remaining_paths: Set[uuid.UUID],
        relationship_types: Optional[Set[str]],
    ) -> Tuple[Optional[uuid.UUID], Set[uuid.UUID]]:
        """Find the edge that covers the most remaining paths."""
        best_edge_id: Optional[uuid.UUID] = None
        best_coverage: Set[uuid.UUID] = set()

        for edge_id, covered_paths in edge_to_paths.items():
            if edge_id in used_edges or edge_id not in relationship_lookup:
                continue
                
            rel = relationship_lookup[edge_id]
            
            if relationship_types and rel.relationship_type not in relationship_types:
                continue

            coverage = covered_paths & remaining_paths
            if len(coverage) > len(best_coverage):
                best_edge_id = edge_id
                best_coverage = coverage

        return best_edge_id, best_coverage

    def _create_remediation(
        self, graph: AwsGraph, rel: Relationship, paths_blocked: Set[uuid.UUID]
    ) -> Remediation:
        """Create a Remediation object from a relationship."""
        source = graph.asset(rel.source_asset_id)
        target = graph.asset(rel.target_asset_id)
        
        return Remediation(
            relationship=rel,
            action=self._determine_action(rel),
            description=self._build_description(rel, source, target),
            paths_blocked=list(paths_blocked),
            priority=len(paths_blocked),
            source_name=source.name if source else "unknown",
            target_name=target.name if target else "unknown",
            relationship_type=rel.relationship_type,
        )

    def _determine_action(self, rel: Relationship) -> str:
        """Determine the remediation action based on relationship type."""
        action_map = {
            "ALLOWS_TRAFFIC_TO": "restrict",
            "MAY_ACCESS": "restrict_policy",
            "CAN_ASSUME": "remove_trust",
            "CONTAINS": "isolate",
            "USES": "remove",
        }
        return action_map.get(rel.relationship_type, "review")

    def _build_description(
        self,
        rel: Relationship,
        source: Optional[object],
        target: Optional[object],
    ) -> str:
        """Build human-readable remediation description."""
        source_name = getattr(source, 'name', 'unknown') if source else 'unknown'
        target_name = getattr(target, 'name', 'unknown') if target else 'unknown'
        getattr(source, 'asset_type', 'unknown') if source else 'unknown'
        
        if rel.relationship_type == "ALLOWS_TRAFFIC_TO":
            # Check if it's 0.0.0.0/0
            if rel.properties.get("open_to_world"):
                return f"Remove 0.0.0.0/0 ingress from {source_name}"
            return f"Restrict traffic from {source_name} to {target_name}"
            
        elif rel.relationship_type == "MAY_ACCESS":
            return f"Restrict {source_name} access to {target_name}"
            
        elif rel.relationship_type == "CAN_ASSUME":
            via = rel.properties.get("via", "")
            if via == "instance_profile":
                return f"Remove instance profile from {source_name} or restrict role {target_name}"
            return f"Remove trust relationship: {source_name} → {target_name}"
            
        elif rel.relationship_type == "CONTAINS":
            return f"Isolate {target_name} from {source_name}"
            
        else:
            return f"Review {rel.relationship_type}: {source_name} → {target_name}"

    def to_cost_cut_candidates(
        self,
        cut_result: CutResult,
        snapshot_id: uuid.UUID,
        graph: AwsGraph,
    ) -> List[CostCutCandidate]:
        """
        Convert CutResult to CostCutCandidate models for storage.
        """
        candidates: List[CostCutCandidate] = []
        
        for rem in cut_result.remediations:
            # Get the target asset for the candidate
            target_asset = graph.asset(rem.relationship.target_asset_id)
            if not target_asset:
                continue
                
            # Calculate risk reduction based on paths blocked
            risk_reduction = Decimal(str(
                len(rem.paths_blocked) / cut_result.total_paths
            )) if cut_result.total_paths > 0 else Decimal("0")

            candidate = CostCutCandidate(
                snapshot_id=snapshot_id,
                asset_id=rem.relationship.target_asset_id,
                reason=rem.description,
                action=rem.action,
                confidence=Decimal("0.8"),  # Greedy algorithm confidence
                paths_blocked=len(rem.paths_blocked),
                risk_reduction=risk_reduction,
                proof={
                    "relationship_id": str(rem.relationship.id),
                    "relationship_type": rem.relationship_type,
                    "source": rem.source_name,
                    "target": rem.target_name,
                    "paths_blocked": [str(p) for p in rem.paths_blocked],
                },
            )
            candidates.append(candidate)

        return candidates
