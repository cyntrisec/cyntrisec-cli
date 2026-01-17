"""S3 Normalizer - Transform S3 data to canonical schema."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
import uuid

from cyntrisec.core.schema import Asset, Finding, FindingSeverity, Relationship


class S3Normalizer:
    """Normalize S3 data to canonical assets and findings."""

    def __init__(self, snapshot_id: uuid.UUID):
        self._snapshot_id = snapshot_id

    def normalize(
        self,
        data: Dict[str, Any],
    ) -> Tuple[List[Asset], List[Relationship], List[Finding]]:
        """Normalize S3 data."""
        assets: List[Asset] = []
        findings: List[Finding] = []

        for bucket in data.get("buckets", []):
            asset, bucket_findings = self._normalize_bucket(bucket)
            assets.append(asset)
            findings.extend(bucket_findings)

        return assets, [], findings

    def _normalize_bucket(
        self,
        bucket: Dict[str, Any],
    ) -> Tuple[Asset, List[Finding]]:
        """Normalize an S3 bucket."""
        bucket_name = bucket["Name"]
        region = bucket.get("Location", "us-east-1")

        # Check if this is a sensitive bucket (by name heuristic)
        is_sensitive = any(
            kw in bucket_name.lower()
            for kw in ["backup", "secret", "credential", "key", "log", "audit"]
        )

        asset = Asset(
            snapshot_id=self._snapshot_id,
            asset_type="s3:bucket",
            aws_region=region,
            aws_resource_id=f"arn:aws:s3:::{bucket_name}",
            arn=f"arn:aws:s3:::{bucket_name}",
            name=bucket_name,
            properties={
                "creation_date": str(bucket.get("CreationDate")),
                "region": region,
                "has_policy": bucket.get("Policy") is not None,
                "public_access_block": bucket.get("PublicAccessBlock"),
            },
            is_sensitive_target=is_sensitive,
        )

        findings: List[Finding] = []

        # Check ACL for public access
        acl = bucket.get("Acl", {})
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            grantee_uri = grantee.get("URI", "")
            
            if "AllUsers" in grantee_uri:
                findings.append(Finding(
                    snapshot_id=self._snapshot_id,
                    asset_id=asset.id,
                    finding_type="s3-bucket-public-acl",
                    severity=FindingSeverity.critical,
                    title=f"S3 bucket {bucket_name} has public ACL",
                    description="Bucket ACL grants access to all users (public)",
                    remediation="Remove public ACL grants and enable Block Public Access",
                    evidence={"grant": grant},
                ))
            elif "AuthenticatedUsers" in grantee_uri:
                findings.append(Finding(
                    snapshot_id=self._snapshot_id,
                    asset_id=asset.id,
                    finding_type="s3-bucket-authenticated-users-acl",
                    severity=FindingSeverity.high,
                    title=f"S3 bucket {bucket_name} allows authenticated users",
                    description="Bucket ACL grants access to any authenticated AWS user",
                    remediation="Remove this grant - it allows any AWS account access",
                    evidence={"grant": grant},
                ))

        # Check public access block
        pab = bucket.get("PublicAccessBlock")
        if not pab:
            findings.append(Finding(
                snapshot_id=self._snapshot_id,
                asset_id=asset.id,
                finding_type="s3-bucket-no-public-access-block",
                severity=FindingSeverity.medium,
                title=f"S3 bucket {bucket_name} has no public access block",
                description="Block Public Access is not configured for this bucket",
                remediation="Enable Block Public Access at the bucket level",
            ))
        elif not all([
            pab.get("BlockPublicAcls"),
            pab.get("IgnorePublicAcls"),
            pab.get("BlockPublicPolicy"),
            pab.get("RestrictPublicBuckets"),
        ]):
            findings.append(Finding(
                snapshot_id=self._snapshot_id,
                asset_id=asset.id,
                finding_type="s3-bucket-partial-public-access-block",
                severity=FindingSeverity.low,
                title=f"S3 bucket {bucket_name} has partial public access block",
                description="Some Block Public Access settings are not enabled",
                evidence={"public_access_block": pab},
            ))

        return asset, findings
