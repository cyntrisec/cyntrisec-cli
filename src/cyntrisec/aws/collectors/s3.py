"""S3 Collector - Collect S3 buckets and policies."""

from __future__ import annotations

import logging
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)

# Throttle delay (seconds) between per-bucket API calls to avoid rate limiting
_BUCKET_THROTTLE_SECONDS = 0.1
_MAX_RETRIES = 3


class S3Collector:
    """Collect S3 resources (global)."""

    def __init__(self, session: boto3.Session):
        self._s3 = session.client("s3")

    def collect_all(self) -> dict[str, Any]:
        """Collect all S3 data."""
        buckets = self._collect_buckets()

        # Enrich with policies and ACLs (throttled to avoid rate limiting)
        for bucket in buckets:
            name = bucket["Name"]
            bucket["Policy"] = self._get_bucket_policy(name)
            bucket["Acl"] = self._get_bucket_acl(name)
            bucket["PublicAccessBlock"] = self._get_public_access_block(name)
            bucket["Location"] = self._get_bucket_location(name)
            time.sleep(_BUCKET_THROTTLE_SECONDS)

        return {"buckets": buckets}

    def _call_with_backoff(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        """Call an AWS API with exponential backoff on throttling."""
        for attempt in range(_MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in ("Throttling", "SlowDown") and attempt < _MAX_RETRIES - 1:
                    wait = (2 ** attempt) * 0.5
                    log.debug("Throttled on %s, retrying in %.1fs", func.__name__, wait)
                    time.sleep(wait)
                else:
                    raise

    def _collect_buckets(self) -> list[dict]:
        """List all buckets."""
        response = self._s3.list_buckets()
        return [dict(b) for b in response.get("Buckets", [])]

    def _get_bucket_policy(self, bucket_name: str) -> dict | None:
        """Get bucket policy."""
        try:
            response = self._call_with_backoff(
                self._s3.get_bucket_policy, Bucket=bucket_name
            )
            return {"Policy": str(response.get("Policy"))}
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return None
            return {"Error": str(e)}

    def _get_bucket_acl(self, bucket_name: str) -> dict | None:
        """Get bucket ACL."""
        try:
            return dict(
                self._call_with_backoff(self._s3.get_bucket_acl, Bucket=bucket_name)
            )
        except ClientError:
            return None

    def _get_public_access_block(self, bucket_name: str) -> dict | None:
        """Get public access block configuration."""
        try:
            response = self._call_with_backoff(
                self._s3.get_public_access_block, Bucket=bucket_name
            )
            return dict(response.get("PublicAccessBlockConfiguration", {}))
        except ClientError:
            return None

    def _get_bucket_location(self, bucket_name: str) -> str:
        """Get bucket region."""
        try:
            response = self._call_with_backoff(
                self._s3.get_bucket_location, Bucket=bucket_name
            )
            # None means us-east-1
            return response.get("LocationConstraint") or "us-east-1"
        except ClientError:
            return "unknown"
