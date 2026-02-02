"""
Attack Path Finder - Heuristic-based attack path discovery.

Finds paths from internet-facing entry points to sensitive targets
through the capability graph. Uses a priority queue (best-first search)
to prioritize highest-risk paths.
"""

from __future__ import annotations

import heapq
import uuid
from collections import deque
from dataclasses import dataclass, field
from decimal import Decimal

from cyntrisec.core.graph import AwsGraph
from cyntrisec.core.schema import (
    INTERNET_ASSET_ID,
    Asset,
    AttackPath,
    ConfidenceLevel,
    EdgeKind,
    Relationship,
)


@dataclass
class PathFinderConfig:
    """Configuration for attack path discovery."""

    max_depth: int = 8
    max_paths: int = 200
    min_risk_score: float = 0.0
    include_unknown: bool = False  # Task 11.2: Check UNKNOWN edges


@dataclass(frozen=True)
class NetworkIdentity:
    """Represents the attacker's network vantage point."""

    security_group_ids: tuple[str, ...] = field(default_factory=tuple)
    vpc_id: str | None = None
    subnet_id: str | None = None

    def __hash__(self):
        return hash((self.security_group_ids, self.vpc_id, self.subnet_id))


@dataclass(frozen=True)
class AttackerState:
    """
    Represents the attacker's state during graph traversal.

    Includes:
    - Current origin (where they are)
    - Compromised assets (what they own)
    - Active principals (what roles they can assume)
    - Network identity (security groups, VPC context)
    """

    origin: str  # "internet" or asset ID
    compromised_assets: frozenset[str] = field(default_factory=frozenset)
    active_principals: frozenset[str] = field(default_factory=frozenset)
    network_identity: NetworkIdentity = field(default_factory=NetworkIdentity)

    def state_key(self) -> int:
        """Return a hashable key for visited set tracking."""
        # We track visited states by (current_node, state_key)
        # State key includes principally the identity and capabilities
        return hash((self.active_principals, self.network_identity))


@dataclass
class CandidatePath:
    """
    A raw discovered path from Phase A (Discovery).
    """

    snapshot_id: uuid.UUID
    path_asset_ids: list[uuid.UUID]
    path_relationship_ids: list[uuid.UUID]
    attacker_state: AttackerState
    heuristic_score: float
    context_relationship_ids: list[uuid.UUID] = field(default_factory=list)


class PathValidator:
    """
    Phase B: Validates candidate paths and assigns confidence.
    """

    def validate_path_metadata(
        self, graph: AwsGraph, candidate: CandidatePath
    ) -> tuple[ConfidenceLevel, str]:
        """Return confidence level and reason."""
        # 1. Network
        net_conf, net_reason = self._check_network_preconditions(graph, candidate)

        # 2. PassRole
        pass_conf, pass_reason = self._check_passrole_motif(graph, candidate)

        # Merge
        level = ConfidenceLevel.HIGH
        if net_conf == ConfidenceLevel.LOW or pass_conf == ConfidenceLevel.LOW:
            level = ConfidenceLevel.LOW
        elif net_conf == ConfidenceLevel.MED or pass_conf == ConfidenceLevel.MED:
            level = ConfidenceLevel.MED

        reasons = []
        if net_reason:
            reasons.append(net_reason)
        if pass_reason:
            reasons.append(pass_reason)
        reason_str = "; ".join(reasons)

        return level, reason_str

    def _check_network_preconditions(
        self, graph: AwsGraph, candidate: CandidatePath
    ) -> tuple[ConfidenceLevel, str]:
        """
        Verify CAN_REACH edges in the path.
        """
        reasons = []
        confidence = ConfidenceLevel.HIGH

        # Iterate through path edges
        for i, rel_id in enumerate(candidate.path_relationship_ids):
            # Access edge data from graph (using ID is slow if we don't have direct lookup, but CandidatePath keeps order)
            # We need to find the edge object.
            # Helper: we know source/target from path_asset_ids[i], [i+1]
            src_id = candidate.path_asset_ids[i]
            tgt_id = candidate.path_asset_ids[i + 1]

            # Find the relationship
            rel = None
            for e in graph.edges_from(src_id):
                if e.id == rel_id:
                    rel = e
                    break

            if not rel:
                continue

            if rel.relationship_type == "CAN_REACH":
                target_asset = graph.asset(tgt_id)
                if not target_asset:
                    continue

                port_range = rel.properties.get("port_range", "")

                # Check 1: DB Exposure on Web Ports
                # If target is RDS/DB and port is strictly Web (80/443), unlikely to work directly
                is_db = target_asset.asset_type in [
                    "rds:db-instance",
                    "dynamodb:table",
                    "redshift:cluster",
                ]
                is_web_port = port_range in ["80-80", "443-443"]

                if is_db and is_web_port:
                    confidence = ConfidenceLevel.LOW
                    reasons.append(
                        f"Unlikely database access via web ports ({port_range}) to {target_asset.name}"
                    )

        reason_str = "; ".join(reasons)
        return confidence, reason_str

    def _check_passrole_motif(
        self, graph: AwsGraph, candidate: CandidatePath
    ) -> tuple[ConfidenceLevel, str]:
        """
        Verify iam:PassRole usage.
        """
        reasons = []
        confidence = ConfidenceLevel.HIGH  # Start high, downgrade if PassRole found without trigger

        for i, rel_id in enumerate(candidate.path_relationship_ids):
            src_id = candidate.path_asset_ids[i]

            # Find the relationship
            rel = None
            for e in graph.edges_from(src_id):
                if e.id == rel_id:
                    rel = e
                    break

            if not rel:
                continue

            if rel.relationship_type == "CAN_PASS_TO":
                # Motif found: Source -> (PassRole) -> TargetRole
                # Check for execution permission (trigger) at Source
                source_asset = graph.asset(src_id)
                if not source_asset:
                    continue

                # If Source is Admin/Power user, assume they have trigger
                # Using name heuristic or is_sensitive_target (if accurate)
                is_admin = False
                name_lower = source_asset.name.lower()
                if "admin" in name_lower or "root" in name_lower:
                    is_admin = True

                if not is_admin:
                    # Downgrade to MED as we can't verify trigger (e.g. lambda:CreateFunction)
                    # We don't have edges for it, and properties parsing is complex here.
                    if confidence == ConfidenceLevel.HIGH:
                        confidence = ConfidenceLevel.MED
                    reasons.append(
                        f"PassRole found at {source_asset.name}, but execution permission (e.g. CreateFunction) unverified"
                    )

        reason_str = "; ".join(reasons)
        return confidence, reason_str


class PathScorer:
    """
    Scores attack paths based on edge weights and confidence modifiers.

    Risk Score = Entry Confidence * Exploitability * Impact

    Where:
    - Entry Confidence: Likelihood of attacker reaching start (0-1)
    - Exploitability: Difficulty of traversing path (0-1)
        - Derived from Path Weight (sum of edge weights)
        - Longer/Harder paths = Lower exploitability
    - Impact: Value of target (0-1)
    """

    # Base weights: Lower is easier to traverse
    EDGE_WEIGHTS = {
        # IAM Privilege Escalation (Very Easy)
        "CAN_ASSUME": 0.1,
        "CAN_PASS_TO": 0.2,  # Requires trigger
        # IAM Data Access (Easy)
        "MAY_READ": 0.3,
        "MAY_WRITE": 0.3,
        "MAY_READ_S3_OBJECT": 0.3,
        # Network Reachability (Medium - requires exploit/creds)
        "CAN_REACH": 0.5,
        # Default
        "default": 1.0,
    }

    CONFIDENCE_MULTIPLIERS = {
        ConfidenceLevel.HIGH: 1.0,
        ConfidenceLevel.MED: 0.6,
        ConfidenceLevel.LOW: 0.2,
    }

    def score_path(
        self,
        graph: AwsGraph,
        path_assets: list[uuid.UUID],
        path_rels: list[uuid.UUID],
        entry_confidence: float,
        target_impact: float,
        confidence_level: ConfidenceLevel = ConfidenceLevel.HIGH,
    ) -> tuple[float, float]:
        """
        Calculate (risk_score, exploitability_score).
        """
        # Calculate total path weight based on edges
        total_weight = 0.0

        for i, rel_id in enumerate(path_rels):
            src_id = path_assets[i]
            # Find edge
            rel = None
            for e in graph.edges_from(src_id):
                if e.id == rel_id:
                    rel = e
                    break

            weight = 1.0
            if rel:
                weight = self.EDGE_WEIGHTS.get(rel.relationship_type, self.EDGE_WEIGHTS["default"])

            total_weight += weight

        # Exploitability formula: Decay based on difficulty
        # e.g. 1.0 / (1.0 + weight) or similar sigmoid.
        # Let's use linear decay with floor.
        # Max reasonable weight ~ 5.0 (10 hops of 0.5).
        exploitability = max(0.01, 1.0 - (total_weight * 0.15))

        # Apply Confidence Penalty to Exploitability?
        # No, confidence penalizes the final Risk Score directly (uncertainty).
        conf_mult = self.CONFIDENCE_MULTIPLIERS.get(confidence_level, 0.2)

        risk_score = entry_confidence * exploitability * target_impact * conf_mult

        return float(risk_score), float(exploitability)

    def score_edge(self, relationship_type: str) -> float:
        """Get weight for a single edge type."""
        return self.EDGE_WEIGHTS.get(relationship_type, self.EDGE_WEIGHTS["default"])


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
        self._scorer = PathScorer()

    def find_paths(
        self,
        graph: AwsGraph,
        snapshot_id: uuid.UUID,
    ) -> list[AttackPath]:
        """
        Find all attack paths in the graph using Two-Phase Discovery.
        """
        # Phase A: Discovery
        candidates = self._discover_candidate_paths(graph, snapshot_id)

        # Phase B: Validation
        validator = PathValidator()
        results = []

        for candidate in candidates:
            # Validate
            confidence, reason = validator.validate_path_metadata(graph, candidate)

            # Build final object
            attack_path = self._create_path(
                graph=graph,
                snapshot_id=snapshot_id,
                path_assets=candidate.path_asset_ids,
                path_rels=candidate.path_relationship_ids,
                context_rels=candidate.context_relationship_ids,
                confidence_level=confidence,
                confidence_reason=reason,
            )

            # Filter low risk (already done in discovery mostly, but good to re-check if scoring changes)
            if float(attack_path.risk_score) >= self._config.min_risk_score:
                results.append(attack_path)

        # Sort by Risk Score Descending (Task 10.3)
        results.sort(key=lambda p: p.risk_score, reverse=True)

        return results

    def _discover_candidate_paths(
        self,
        graph: AwsGraph,
        snapshot_id: uuid.UUID,
    ) -> list[CandidatePath]:
        """
        Phase A: Discover potential attack paths using k-best search.
        """
        entry_points = graph.entry_points()
        targets = {t.id: t for t in graph.sensitive_targets()}

        if not entry_points or not targets:
            return []

        # Priority Queue: (-heuristic_score, path_len, current_id, path_assets, path_rels, attacker_state)
        queue: list[
            tuple[float, int, uuid.UUID, list[uuid.UUID], list[uuid.UUID], AttackerState]
        ] = []
        for entry in entry_points:
            # Initial state
            # If entering via 0.0.0.0/0, origin is internet
            initial_state = self._initialize_state_for_entry_point(graph, entry)

            # Initial score based on entry confidence alone (length=1)
            score = self._calculate_heuristic(graph, entry, 1)

            # Use negative score for max-heap behavior
            heapq.heappush(queue, (-score, 1, entry.id, [entry.id], [], initial_state))

        found_candidates: list[CandidatePath] = []
        visited_states: set[tuple[uuid.UUID, int]] = set()

        # Limit visits per node to prevent explosion while finding alternative paths
        # (asset_id -> visit_count)
        node_visits: dict[uuid.UUID, int] = {}
        MAX_VISITS_PER_NODE = 10

        while queue and len(found_candidates) < self._config.max_paths:
            neg_score, length, current_id, path_assets, path_rels, state = heapq.heappop(queue)

            # Pruning
            if length >= self._config.max_depth:
                continue

            # State-aware visited check
            state_key = state.state_key()
            if (current_id, state_key) in visited_states:
                continue
            visited_states.add((current_id, state_key))

            # Count visits (soft limit to prevent infinite variations)
            node_visits[current_id] = node_visits.get(current_id, 0) + 1
            if node_visits[current_id] > MAX_VISITS_PER_NODE:
                continue

            # Check if we reached a target
            if current_id in targets:
                # We found a path!

                # Context edges (structural)
                context_rels = self._collect_context_edges(graph, path_assets)

                candidate = CandidatePath(
                    snapshot_id=snapshot_id,
                    path_asset_ids=path_assets,
                    path_relationship_ids=path_rels,
                    attacker_state=state,
                    heuristic_score=-neg_score,
                    context_relationship_ids=context_rels,
                )
                found_candidates.append(candidate)

            # Expand neighbors
            for rel in graph.edges_from(current_id):
                # 7.2 Filter by edge_kind (Capability + Unknown if flag set)
                # Task 11.2: Handle UNKNOWN edges
                is_capability = rel.edge_kind == EdgeKind.CAPABILITY
                is_unknown = rel.edge_kind == EdgeKind.UNKNOWN

                allow_unknown = self._config.include_unknown

                if not (is_capability or (is_unknown and allow_unknown)):
                    continue

                next_id = rel.target_asset_id

                # Cycle prevention
                if next_id in path_assets:
                    continue

                # 7.5 Precondition checking
                if not self._check_preconditions(graph, rel, state):
                    continue

                # 7.3 Update attacker state
                next_state = self._update_attacker_state(graph, rel, next_id, state)

                new_assets = path_assets + [next_id]
                new_rels = path_rels + [rel.id]
                new_len = length + 1

                # Heuristic
                entry_asset = graph.asset(path_assets[0])
                new_score = self._calculate_heuristic(graph, entry_asset, new_len)

                heapq.heappush(
                    queue, (-new_score, new_len, next_id, new_assets, new_rels, next_state)
                )

        return found_candidates

    def _initialize_state_for_entry_point(self, graph: AwsGraph, entry: Asset) -> AttackerState:
        """Initialize state for an entry point."""
        # Check if we have network identity from the entry point
        identity = self._get_network_identity(entry)

        return AttackerState(
            origin="internet",
            compromised_assets=frozenset([str(entry.id)]),
            network_identity=identity,
        )

    def _get_network_identity(self, asset: Asset) -> NetworkIdentity:
        """Extract network identity from an asset."""
        sg_ids = tuple(sorted(asset.properties.get("security_groups", [])))
        vpc_id = asset.properties.get("vpc_id")
        subnet_id = asset.properties.get("subnet_id")
        return NetworkIdentity(security_group_ids=sg_ids, vpc_id=vpc_id, subnet_id=subnet_id)

    def _update_attacker_state(
        self, graph: AwsGraph, rel: Relationship, next_id: uuid.UUID, current_state: AttackerState
    ) -> AttackerState:
        """
        Update attacker state after traversing an edge.

        Updates:
        - Compromised assets (adds new asset)
        - Active principals (if assuming role)
        - Network identity (if moving to compute resource)
        """
        next_asset = graph.asset(next_id)
        if not next_asset:
            return current_state

        new_compromised = set(current_state.compromised_assets)
        new_compromised.add(str(next_id))

        new_principals = set(current_state.active_principals)
        # If we assumed a role, add it to active principals
        if rel.relationship_type == "CAN_ASSUME":
            new_principals.add(str(next_id))

        # If we moved to a compute resource, update network identity
        # (e.g. pivoting to an EC2 instance or Lambda)
        new_identity = current_state.network_identity
        if next_asset.asset_type in ["ec2:instance", "lambda:function"]:
            new_identity = self._get_network_identity(next_asset)

        return AttackerState(
            origin=current_state.origin,
            compromised_assets=frozenset(new_compromised),
            active_principals=frozenset(new_principals),
            network_identity=new_identity,
        )

    def _check_preconditions(
        self, graph: AwsGraph, rel: Relationship, state: AttackerState
    ) -> bool:
        """
        Check if edge can be traversed given current state.

        Enforces:
        - Network reachability (CAN_REACH source must match current identity)
        """
        if rel.relationship_type == "CAN_REACH":
            # For CAN_REACH edges, the source property specifies allowed origin.
            # But the edge is typically SourceSG -> TargetInstance.
            # If we are traversing this edge, we are at SourceSG (logical) or we match it?

            # The edge is Source -> Target.
            # If Source is a Security Group, we must "have" that SG in our identity.
            source_asset = graph.asset(rel.source_asset_id)
            if not source_asset:
                return False

            if source_asset.asset_type == "ec2:security-group":
                # We can only traverse this edge if we originate from this SG
                if source_asset.aws_resource_id not in state.network_identity.security_group_ids:
                    return False

            elif source_asset.asset_type == "ec2:subnet":
                # Only traverse if we are in this subnet
                if state.network_identity.subnet_id != source_asset.aws_resource_id:
                    return False

        return True

    def _collect_context_edges(
        self, graph: AwsGraph, path_assets: list[uuid.UUID]
    ) -> list[uuid.UUID]:
        """Collect structural edges relevant to the path."""
        context_ids = []
        for asset_id in path_assets:
            # Get Structural edges from/to this asset
            for rel in graph.edges_to(asset_id):
                if rel.edge_kind == EdgeKind.STRUCTURAL:
                    context_ids.append(rel.id)
            for rel in graph.edges_from(asset_id):
                if rel.edge_kind == EdgeKind.STRUCTURAL:
                    context_ids.append(rel.id)
        return list(set(context_ids))

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
        paths: list[list[uuid.UUID]] = []
        queue = deque([(source_id, [source_id])])
        visited_paths: set[tuple[uuid.UUID, ...]] = set()

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
                    path_key = tuple(new_path)
                    if path_key not in visited_paths:
                        visited_paths.add(path_key)
                        queue.append((nxt, new_path))
        return paths

    def _calculate_heuristic(
        self, graph: AwsGraph, entry_asset: Asset | None, length: int
    ) -> float:
        """
        Calculate heuristic score for best-first search.
        Higher is better (higher risk).
        """
        entry_conf = self._entry_confidence(graph, entry_asset)
        exploitability = self._exploitability(length)
        # We assume potential impact is 1.0 (unknown) during traversal
        return entry_conf * exploitability

    def _create_path(
        self,
        *,
        graph: AwsGraph,
        snapshot_id: uuid.UUID,
        path_assets: list[uuid.UUID],
        path_rels: list[uuid.UUID],
        context_rels: list[uuid.UUID] | None = None,
        confidence_level: ConfidenceLevel = ConfidenceLevel.HIGH,
        confidence_reason: str = "",
    ) -> AttackPath:
        """Create an AttackPath from discovered path."""
        entry = graph.asset(path_assets[0])
        target = graph.asset(path_assets[-1])

        # Calculate scores using PathScorer (Task 10)
        entry_confidence = self._entry_confidence(graph, entry)
        impact = self._impact_score(target)

        risk, exploitability = self._scorer.score_path(
            graph=graph,
            path_assets=path_assets,
            path_rels=path_rels,
            entry_confidence=entry_confidence,
            target_impact=impact,
            confidence_level=confidence_level,
        )

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
            attack_chain_relationship_ids=path_rels,  # During discovery, all are capability
            context_relationship_ids=context_rels or [],
            attack_vector=vector,
            path_length=len(path_rels),
            entry_confidence=Decimal(str(round(entry_confidence, 4))),
            exploitability_score=Decimal(str(round(exploitability, 4))),
            impact_score=Decimal(str(round(impact, 4))),
            risk_score=Decimal(str(round(risk, 4))),
            confidence_level=confidence_level,
            confidence_reason=confidence_reason,
            proof=proof,
        )

    def _entry_confidence(self, graph: AwsGraph, asset: Asset | None) -> float:
        """Calculate entry point accessibility (0-1)."""
        if not asset:
            return 0.5

        base_score = 0.5

        # Check CAN_REACH edges from Internet
        internet_edges = []
        if INTERNET_ASSET_ID in graph.outgoing:
            for rel in graph.outgoing[INTERNET_ASSET_ID]:
                if rel.target_asset_id == asset.id and rel.relationship_type == "CAN_REACH":
                    internet_edges.append(rel)

        if internet_edges:
            # Task 6.4: Set entry_confidence based on port category
            best_edge_score = 0.0

            for edge in internet_edges:
                port_range = edge.properties.get("port_range", "")

                # Determine port category score
                if self._is_web_port(port_range):
                    score = 0.9  # web
                elif self._is_admin_port(port_range):
                    score = 0.7  # admin
                elif self._is_db_port(port_range):
                    score = 0.6  # db
                else:
                    score = 0.8  # other/high ports often risky

                # Adjust by asset type
                if asset.asset_type in ["elbv2:load-balancer", "elb:load-balancer"]:
                    score += 0.05

                # Adjust by rule specificity
                # If explicit CIDR was used but it's 0.0.0.0/0 (implied by being internet edge here), +0.0
                # If restricted CIDR (but still internet reachable? e.g. large public block), -0.1
                # Since we only create CAN_REACH from world for 0.0.0.0/0, it is open world.
                # So +0.0

                if score > best_edge_score:
                    best_edge_score = score

            return min(1.0, best_edge_score)

        # Fallback for legacy assets without CAN_REACH edges
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

    def _is_web_port(self, port_range: str) -> bool:
        return port_range in ["80-80", "443-443", "8080-8080", "8443-8443"]

    def _is_admin_port(self, port_range: str) -> bool:
        return port_range in ["22-22", "3389-3389", "5985-5985", "5986-5986"]

    def _is_db_port(self, port_range: str) -> bool:
        return port_range in ["3306-3306", "5432-5432", "1433-1433", "27017-27017"]

    def _exploitability(self, path_length: int) -> float:
        """Calculate exploitability based on path length (Legacy/Fallback)."""
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
                rel_id = path_rels[i - 1]
                # Find the specific relationship by ID
                matched = False
                for rel in graph.edges_from(path_assets[i - 1]):
                    if rel.id == rel_id:
                        step["via_relationship"] = {
                            "type": rel.relationship_type,
                            "properties": rel.properties,
                        }
                        matched = True
                        break
                # Fallback: match by target if relationship ID not found
                if not matched:
                    for rel in graph.edges_from(path_assets[i - 1]):
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
