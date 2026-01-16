"""
AWS Credential Provider - Handle role assumption and profiles.

Supports:
- AssumeRole with optional external ID
- AWS CLI profiles
- Default credential chain (env vars, instance metadata)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class RoleCredentials:
    """Temporary credentials from AssumeRole."""
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    assumed_role_arn: str


class CredentialProvider:
    """
    AWS credential provider for CLI mode.
    
    Example:
        provider = CredentialProvider(profile="my-profile")
        session = provider.assume_role(
            role_arn="arn:aws:iam::123456789012:role/ReadOnly",
            external_id="my-external-id"
        )
    """

    def __init__(
        self,
        *,
        profile: Optional[str] = None,
        region: str = "us-east-1",
    ):
        self._profile = profile
        self._region = region
        self._base_session: Optional[boto3.Session] = None

    def _get_base_session(self) -> boto3.Session:
        """Get or create the base boto3 session."""
        if self._base_session is None:
            self._base_session = boto3.Session(
                profile_name=self._profile,
                region_name=self._region,
            )
        return self._base_session

    def assume_role(
        self,
        role_arn: str,
        *,
        external_id: Optional[str] = None,
        session_name: str = "cyntrisec-cli",
        duration_seconds: int = 3600,
    ) -> boto3.Session:
        """
        Assume an IAM role and return a configured boto3 session.
        
        Args:
            role_arn: ARN of the role to assume
            external_id: External ID for the role (optional)
            session_name: Name for the assumed role session
            duration_seconds: How long the credentials are valid
            
        Returns:
            boto3.Session configured with temporary credentials
        """
        base = self._get_base_session()
        sts = base.client("sts")

        assume_kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": duration_seconds,
        }
        if external_id:
            assume_kwargs["ExternalId"] = external_id

        log.info("Assuming role: %s", role_arn)
        
        try:
            response = sts.assume_role(**assume_kwargs)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "AccessDenied":
                raise PermissionError(
                    f"Access denied when assuming role {role_arn}. "
                    "Check that your credentials can assume this role."
                ) from e
            raise

        creds = response["Credentials"]
        
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self._region,
        )

    def get_caller_identity(self) -> dict:
        """Get the identity of the current credentials."""
        session = self._get_base_session()
        sts = session.client("sts")
        return sts.get_caller_identity()

    def validate_role(
        self,
        role_arn: str,
        *,
        external_id: Optional[str] = None,
    ) -> bool:
        """
        Validate that a role can be assumed.
        
        Returns True if role assumption succeeds.
        """
        try:
            session = self.assume_role(
                role_arn,
                external_id=external_id,
                duration_seconds=900,  # Minimum
            )
            # Verify we can make a call
            session.client("sts").get_caller_identity()
            return True
        except Exception as e:
            log.warning("Role validation failed for %s: %s", role_arn, e)
            return False
