"""
AWS Scanner - Orchestrate collection, normalization, and analysis.

This is the main entry point for AWS scanning.
No database or queue dependencies.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from datetime import datetime

from cyntrisec.aws.collectors import (
    Ec2Collector,
    IamCollector,
    LambdaCollector,
    NetworkCollector,
    RdsCollector,
    S3Collector,
)
from cyntrisec.aws.credentials import CredentialProvider
from cyntrisec.aws.normalizers import (
    Ec2Normalizer,
    IamNormalizer,
    LambdaNormalizer,
    NetworkNormalizer,
    RdsNormalizer,
    S3Normalizer,
)
from cyntrisec.core.graph import GraphBuilder
from cyntrisec.core.paths import PathFinder
from cyntrisec.core.schema import (
    Asset,
    Finding,
    Relationship,
    Snapshot,
    SnapshotStatus,
)
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
        regions: Sequence[str],
        *,
        role_arn: str | None = None,
        external_id: str | None = None,
        role_session_name: str | None = None,
        profile: str | None = None,
        business_config: str | None = None,
    ) -> Snapshot:
        """
        Run a full AWS scan.

        Args:
            regions: AWS regions to scan
            role_arn: IAM role to assume (optional - uses default creds if not provided)
            external_id: External ID for role assumption
            profile: AWS CLI profile for base credentials

        Returns:
            Snapshot with scan results
        """
        start_time = time.monotonic()

        try:
            if role_arn:
                log.info("Assuming role: %s", role_arn)
                creds = CredentialProvider(profile=profile, region=regions[0])
                session = creds.assume_role(
                    role_arn,
                    external_id=external_id,
                    session_name=role_session_name or "cyntrisec-scan",
                )
            else:
                log.info("Using default AWS credentials")
                import boto3

                session = boto3.Session(profile_name=profile, region_name=regions[0])

            # Get account ID
            identity = session.client("sts").get_caller_identity()
            account_id = identity["Account"]
            log.info("Connected to AWS account: %s", account_id)
        except Exception as e:
            log.debug("Caught exception in scanner: %s %s", type(e).__name__, e)
            raise ConnectionError(f"Failed to authenticate with AWS: {e}") from e

        # 2. Initialize storage
        scan_id = self._storage.new_scan(account_id)
        snapshot = Snapshot(
            aws_account_id=account_id,
            regions=list(regions),
            scan_params={
                "role_arn": role_arn,
                "regions": list(regions),
                "business_config": business_config,
            },
        )
        self._storage.save_snapshot(snapshot)

        # 3. Collect and normalize
        all_assets: list[Asset] = []
        all_relationships: list[Relationship] = []
        all_findings: list[Finding] = []
        collector_errors: list[dict[str, str]] = []

        # Collect global resources (IAM, S3)
        log.info("Collecting global resources (IAM, S3)...")
        try:
            iam_data = IamCollector(session).collect_all()
            assets, rels, findings = IamNormalizer(snapshot_id=snapshot.id).normalize(iam_data)
            all_assets.extend(assets)
            all_relationships.extend(rels)
            all_findings.extend(findings)
            log.info("  IAM: %d assets, %d relationships", len(assets), len(rels))
        except Exception as e:
            log.error("Error collecting IAM: %s", e)
            collector_errors.append({"service": "iam", "error": str(e)})

        try:
            s3_data = S3Collector(session).collect_all()
            assets, rels, findings = S3Normalizer(snapshot_id=snapshot.id).normalize(s3_data)
            all_assets.extend(assets)
            all_relationships.extend(rels)
            all_findings.extend(findings)
            log.info("  S3: %d assets, %d findings", len(assets), len(findings))
        except Exception as e:
            log.error("Error collecting S3: %s", e)
            collector_errors.append({"service": "s3", "error": str(e)})

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
                collector_errors.append({"service": "ec2", "region": region, "error": str(e)})

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
                collector_errors.append({"service": "network", "region": region, "error": str(e)})

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
                collector_errors.append({"service": "lambda", "region": region, "error": str(e)})

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
                collector_errors.append({"service": "rds", "region": region, "error": str(e)})

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

        if business_config:
            try:
                from cyntrisec.core.business_config import BusinessConfig
                from cyntrisec.core.business_logic import BusinessLogicEngine

                log.info("Loading business config from: %s", business_config)
                cfg = BusinessConfig.load(business_config)
                logic = BusinessLogicEngine(graph, cfg)
                logic.apply_labels()
            except Exception as e:
                log.error("Failed to apply business config: %s", e)
                if collector_errors is not None:
                    collector_errors.append({"service": "business_logic", "error": str(e)})

        paths = PathFinder().find_paths(graph, snapshot.id)
        self._storage.save_attack_paths(paths)
        log.info("  Attack paths found: %d", len(paths))

        # 7. Finalize snapshot
        duration = time.monotonic() - start_time
        if collector_errors:
            snapshot.status = SnapshotStatus.completed_with_errors
            snapshot.errors = collector_errors
        else:
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
