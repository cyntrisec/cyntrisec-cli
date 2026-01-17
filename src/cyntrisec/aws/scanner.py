"""
AWS Scanner - Orchestrate collection, normalization, and analysis.

This is the main entry point for AWS scanning.
No database or queue dependencies.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import List, Optional, Sequence
import uuid

import boto3

from cyntrisec.aws.credentials import CredentialProvider
from cyntrisec.aws.collectors import (
    Ec2Collector,
    IamCollector,
    S3Collector,
    LambdaCollector,
    RdsCollector,
    NetworkCollector,
)
from cyntrisec.aws.normalizers import (
    Ec2Normalizer,
    IamNormalizer,
    S3Normalizer,
    LambdaNormalizer,
    RdsNormalizer,
    NetworkNormalizer,
)
from cyntrisec.core.schema import (
    Asset,
    AttackPath,
    Finding,
    Relationship,
    Snapshot,
    SnapshotStatus,
)
from cyntrisec.core.graph import GraphBuilder
from cyntrisec.core.paths import PathFinder
from cyntrisec.storage.protocol import StorageBackend

log = logging.getLogger(__name__)


class AwsScanner:
    """
    Orchestrate AWS scanning.
    
    Coordinates:
    1. Credential acquisition (AssumeRole)
    2. Resource collection (EC2, IAM, S3, Lambda, RDS, Network)
    3. Normalization to canonical schema
    4. Graph construction
    5. Attack path analysis
    6. Storage of results
    
    Example:
        storage = FileSystemStorage()
        scanner = AwsScanner(storage)
        snapshot = scanner.scan(
            role_arn="arn:aws:iam::123456789012:role/ReadOnly",
            regions=["us-east-1", "eu-west-1"]
        )
    """

    def __init__(self, storage: StorageBackend):
        self._storage = storage

    def scan(
        self,
        role_arn: str,
        regions: Sequence[str],
        *,
        external_id: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> Snapshot:
        """
        Run a full AWS scan.
        
        Args:
            role_arn: IAM role to assume
            regions: AWS regions to scan
            external_id: External ID for role assumption
            profile: AWS CLI profile for base credentials
            
        Returns:
            Snapshot with scan results
        """
        started_at = datetime.utcnow()
        start_time = time.monotonic()

        # 1. Assume role
        log.info("Assuming role: %s", role_arn)
        creds = CredentialProvider(profile=profile, region=regions[0])
        session = creds.assume_role(role_arn, external_id=external_id)
        
        # Get account ID
        identity = session.client("sts").get_caller_identity()
        account_id = identity["Account"]
        log.info("Connected to AWS account: %s", account_id)

        # 2. Initialize storage
        scan_id = self._storage.new_scan(account_id)
        snapshot = Snapshot(
            aws_account_id=account_id,
            regions=list(regions),
            scan_params={
                "role_arn": role_arn,
                "regions": list(regions),
            },
        )
        self._storage.save_snapshot(snapshot)

        # 3. Collect and normalize
        all_assets: List[Asset] = []
        all_relationships: List[Relationship] = []
        all_findings: List[Finding] = []

        # Collect global resources (IAM, S3)
        log.info("Collecting global resources (IAM, S3)...")
        try:
            iam_data = IamCollector(session).collect_all()
            assets, rels, findings = IamNormalizer(
                snapshot_id=snapshot.id
            ).normalize(iam_data)
            all_assets.extend(assets)
            all_relationships.extend(rels)
            all_findings.extend(findings)
            log.info("  IAM: %d assets, %d relationships", len(assets), len(rels))
        except Exception as e:
            log.error("Error collecting IAM: %s", e)

        try:
            s3_data = S3Collector(session).collect_all()
            assets, rels, findings = S3Normalizer(
                snapshot_id=snapshot.id
            ).normalize(s3_data)
            all_assets.extend(assets)
            all_relationships.extend(rels)
            all_findings.extend(findings)
            log.info("  S3: %d assets, %d findings", len(assets), len(findings))
        except Exception as e:
            log.error("Error collecting S3: %s", e)

        # Collect regional resources
        for region in regions:
            log.info("Scanning region: %s", region)
            
            # EC2
            try:
                ec2_data = Ec2Collector(session, region).collect_all()
                assets, rels, findings = Ec2Normalizer(
                    snapshot_id=snapshot.id,
                    region=region,
                    account_id=account_id,
                ).normalize(ec2_data)
                all_assets.extend(assets)
                all_relationships.extend(rels)
                all_findings.extend(findings)
                log.info("  EC2: %d assets", len(assets))
            except Exception as e:
                log.error("Error collecting EC2 in %s: %s", region, e)

            # Network (VPC, subnets, security groups)
            try:
                network_data = NetworkCollector(session, region).collect_all()
                assets, rels, findings = NetworkNormalizer(
                    snapshot_id=snapshot.id,
                    region=region,
                    account_id=account_id,
                ).normalize(network_data)
                all_assets.extend(assets)
                all_relationships.extend(rels)
                all_findings.extend(findings)
                log.info("  Network: %d assets, %d relationships", len(assets), len(rels))
            except Exception as e:
                log.error("Error collecting Network in %s: %s", region, e)

            # Lambda
            try:
                lambda_data = LambdaCollector(session, region).collect_all()
                assets, rels, findings = LambdaNormalizer(
                    snapshot_id=snapshot.id,
                    region=region,
                    account_id=account_id,
                ).normalize(lambda_data)
                all_assets.extend(assets)
                all_relationships.extend(rels)
                all_findings.extend(findings)
                log.info("  Lambda: %d assets", len(assets))
            except Exception as e:
                log.error("Error collecting Lambda in %s: %s", region, e)

            # RDS
            try:
                rds_data = RdsCollector(session, region).collect_all()
                assets, rels, findings = RdsNormalizer(
                    snapshot_id=snapshot.id,
                    region=region,
                    account_id=account_id,
                ).normalize(rds_data)
                all_assets.extend(assets)
                all_relationships.extend(rels)
                all_findings.extend(findings)
                log.info("  RDS: %d assets", len(assets))
            except Exception as e:
                log.error("Error collecting RDS in %s: %s", region, e)

        # 4. Build cross-service relationships
        log.info("Building cross-service relationships...")
        from cyntrisec.aws.relationship_builder import RelationshipBuilder
        extra_rels = RelationshipBuilder(snapshot.id).build(all_assets)
        all_relationships.extend(extra_rels)
        log.info("  Added %d cross-service relationships", len(extra_rels))

        # 5. Save collected data
        self._storage.save_assets(all_assets)
        self._storage.save_relationships(all_relationships)
        self._storage.save_findings(all_findings)

        log.info(
            "Collection complete: %d assets, %d relationships, %d findings",
            len(all_assets),
            len(all_relationships),
            len(all_findings),
        )

        # 5. Build graph
        log.info("Building capability graph...")
        graph = GraphBuilder().build(
            assets=all_assets,
            relationships=all_relationships,
        )
        log.info(
            "Graph: %d nodes, %d edges",
            graph.asset_count(),
            graph.relationship_count(),
        )

        # 6. Find attack paths
        log.info("Analyzing attack paths...")
        entry_count = len(graph.entry_points())
        target_count = len(graph.sensitive_targets())
        log.info("  Entry points: %d, Sensitive targets: %d", entry_count, target_count)

        paths = PathFinder().find_paths(graph, snapshot.id)
        self._storage.save_attack_paths(paths)
        log.info("  Attack paths found: %d", len(paths))

        # 7. Finalize snapshot
        duration = time.monotonic() - start_time
        snapshot.status = SnapshotStatus.completed
        snapshot.completed_at = datetime.utcnow()
        snapshot.asset_count = len(all_assets)
        snapshot.relationship_count = len(all_relationships)
        snapshot.finding_count = len(all_findings)
        snapshot.path_count = len(paths)
        self._storage.save_snapshot(snapshot)

        log.info("Scan complete in %.1fs", duration)
        log.info("Results saved to: ~/.cyntrisec/scans/%s/", scan_id)

        return snapshot
