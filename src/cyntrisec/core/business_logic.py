"""
Business Logic Engine - Apply business context to the capability graph.
"""

from __future__ import annotations

import logging
import fnmatch
from typing import Any

from cyntrisec.core.business_config import BusinessConfig
from cyntrisec.core.graph import AwsGraph
from cyntrisec.core.schema import Asset, AttackPath, Relationship

log = logging.getLogger(__name__)


class BusinessLogicEngine:
    """
    Applies business rules to the graph to distinguish between:
    - Business Critical (Must exist)
    - Legitimate Exposure (Accepted risk)
    - Unnecessary Exposure (Delta)
    """

    LABEL_BUSINESS = "business_required"
    LABEL_ENTRYPOINT = "business_entrypoint"
    LABEL_AUTHORIZED = "authorized"

    def __init__(self, graph: AwsGraph, config: BusinessConfig | None):
        self.graph = graph
        self.config = config

    def apply_labels(self) -> None:
        """Apply business labels to assets and relationships."""
        if not self.config:
            return

        log.info("Applying business labels to graph...")
        count = 0

        # 1. Label Entrypoints
        for asset in self.graph.all_assets():
            if self._is_entrypoint(asset):
                asset.labels.add(self.LABEL_BUSINESS)
                asset.labels.add(self.LABEL_ENTRYPOINT)
                count += 1
            
            # 2. Global Allowlist
            if self._matches_allowlist(asset):
                asset.labels.add(self.LABEL_BUSINESS)
                asset.labels.add(self.LABEL_AUTHORIZED)
                count += 1

        # 3. Critical Flows
        # TODO: Requires PathFinder to trace paths between source/target
        # Will be implemented in Pathfinding Upgrades phase
        
        log.info("Labeled %d assets as business-critical", count)

    def compute_delta(self, attack_paths: list[AttackPath]) -> list[AttackPath]:
        """
        Compute the 'Delta' (Unnecessary Exposure).
        
        Returns only the AttackPaths that are NOT fully legitimate.
        A path is legitimate if EVERY step is labeled 'business_required' or 'authorized'.
        """
        if not self.config:
            # If no config, everything is potential exposure (or return all)
            return attack_paths

        delta_paths = []
        for path in attack_paths:
            if not self._is_path_legitimate(path):
                delta_paths.append(path)
        
        return delta_paths

    def _is_entrypoint(self, asset: Asset) -> bool:
        """Check if asset matches entrypoint criteria."""
        criteria = self.config.entrypoints
        
        # By ID
        if asset.aws_resource_id in criteria.by_id or asset.id in criteria.by_id:
            return True
            
        # By Type
        if asset.asset_type in criteria.by_type:
            return True
            
        # By Tags
        for tag_key, tag_pattern in criteria.by_tags.items():
            val = asset.tags.get(tag_key)
            if val and fnmatch.fnmatch(val, tag_pattern):
                return True
                
        return False

    def _matches_allowlist(self, asset: Asset) -> bool:
        """Check if asset matches global allowlist tags."""
        for tag_key, tag_pattern in self.config.global_allowlist.items():
            val = asset.tags.get(tag_key)
            if val and fnmatch.fnmatch(val, tag_pattern):
                return True
        return False

    def _is_path_legitimate(self, path: AttackPath) -> bool:
        """
        Check if an attack path is fully justified by business rules.
        
        Strict mode: All assets and relationships must be labeled.
        Relaxed mode: Just check if source and target are authorized? 
        For now, we implement a check: access must be authorized.
        """
        # Optimized: Check if the *target* is authorized (e.g. "It's okay to access this DB")
        # OR if the *source* is an authorized entrypoint AND the flow is business_required.
        
        # For Phase 1, we'll check if the path consists of marked assets.
        # Note: We need to check Edges too eventually.
        
        for asset_id in path.path_asset_ids:
            asset = self.graph.asset(asset_id)
            if not asset: continue
            
            # If any node in the chain is NOT business-required, the path is suspect.
            # Exception: Maybe we allow traversal through unmarked nodes if the flow itself is marked?
            # That requires Critical Flow labeling (Edge labeling).
            
            if self.LABEL_BUSINESS not in asset.labels:
                 return False
                 
        return True
