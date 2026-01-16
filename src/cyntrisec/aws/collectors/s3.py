"""S3 Collector - Collect S3 buckets and policies."""
from __future__ import annotations

from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError


class S3Collector:
    """Collect S3 resources (global)."""

    def __init__(self, session: boto3.Session):
        self._s3 = session.client("s3")

    def collect_all(self) -> Dict[str, Any]:
        """Collect all S3 data."""
        buckets = self._collect_buckets()
        
        # Enrich with policies and ACLs
        for bucket in buckets:
            name = bucket["Name"]
            bucket["Policy"] = self._get_bucket_policy(name)
            bucket["Acl"] = self._get_bucket_acl(name)
            bucket["PublicAccessBlock"] = self._get_public_access_block(name)
            bucket["Location"] = self._get_bucket_location(name)
        
        return {"buckets": buckets}

    def _collect_buckets(self) -> List[Dict]:
        """List all buckets."""
        response = self._s3.list_buckets()
        return response.get("Buckets", [])

    def _get_bucket_policy(self, bucket_name: str) -> Dict | None:
        """Get bucket policy."""
        try:
            response = self._s3.get_bucket_policy(Bucket=bucket_name)
            return {"Policy": response.get("Policy")}
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return None
            return {"Error": str(e)}

    def _get_bucket_acl(self, bucket_name: str) -> Dict | None:
        """Get bucket ACL."""
        try:
            return self._s3.get_bucket_acl(Bucket=bucket_name)
        except ClientError:
            return None

    def _get_public_access_block(self, bucket_name: str) -> Dict | None:
        """Get public access block configuration."""
        try:
            response = self._s3.get_public_access_block(Bucket=bucket_name)
            return response.get("PublicAccessBlockConfiguration")
        except ClientError:
            return None

    def _get_bucket_location(self, bucket_name: str) -> str:
        """Get bucket region."""
        try:
            response = self._s3.get_bucket_location(Bucket=bucket_name)
            # None means us-east-1
            return response.get("LocationConstraint") or "us-east-1"
        except ClientError:
            return "unknown"
