"""IAM Normalizer - Transform IAM data to canonical schema."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple
import uuid

from cyntrisec.core.schema import Asset, Finding, FindingSeverity, Relationship


class IamNormalizer:
    """Normalize IAM data to canonical assets and relationships."""

    def __init__(self, snapshot_id: uuid.UUID):
        self._snapshot_id = snapshot_id
        self._role_assets: Dict[str, Asset] = {}

    def normalize(
        self,
        data: Dict[str, Any],
    ) -> Tuple[List[Asset], List[Relationship], List[Finding]]:
        """Normalize IAM data."""
        assets: List[Asset] = []
        relationships: List[Relationship] = []
        findings: List[Finding] = []

        # Normalize users
        for user in data.get("users", []):
            asset, user_findings = self._normalize_user(user)
            assets.append(asset)
            findings.extend(user_findings)

        # Normalize roles
        for role in data.get("roles", []):
            asset, rels, role_findings = self._normalize_role(role)
            assets.append(asset)
            self._role_assets[role["RoleName"]] = asset
            relationships.extend(rels)
            findings.extend(role_findings)

        return assets, relationships, findings

    def _normalize_user(
        self,
        user: Dict[str, Any],
    ) -> Tuple[Asset, List[Finding]]:
        """Normalize an IAM user."""
        user_name = user["UserName"]
        user_arn = user["Arn"]

        asset = Asset(
            snapshot_id=self._snapshot_id,
            asset_type="iam:user",
            aws_resource_id=user_arn,
            arn=user_arn,
            name=user_name,
            properties={
                "user_id": user.get("UserId"),
                "created_date": str(user.get("CreateDate")),
                "password_last_used": str(user.get("PasswordLastUsed")) if user.get("PasswordLastUsed") else None,
            },
        )

        findings: List[Finding] = []

        # Check for root user
        if user_name == "root":
            findings.append(Finding(
                snapshot_id=self._snapshot_id,
                asset_id=asset.id,
                finding_type="iam-root-user",
                severity=FindingSeverity.info,
                title="Root user exists",
                description="The AWS root user should only be used for account management tasks",
            ))

        return asset, findings

    def _normalize_role(
        self,
        role: Dict[str, Any],
    ) -> Tuple[Asset, List[Relationship], List[Finding]]:
        """Normalize an IAM role with trust relationships."""
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        # Check if this is a sensitive/admin role
        is_sensitive = any(
            kw in role_name.lower()
            for kw in ["admin", "root", "power", "full-access"]
        )

        asset = Asset(
            snapshot_id=self._snapshot_id,
            asset_type="iam:role",
            aws_resource_id=role_arn,
            arn=role_arn,
            name=role_name,
            properties={
                "role_id": role.get("RoleId"),
                "created_date": str(role.get("CreateDate")),
                "max_session_duration": role.get("MaxSessionDuration"),
                "description": role.get("Description"),
            },
            is_sensitive_target=is_sensitive,
        )

        relationships: List[Relationship] = []
        findings: List[Finding] = []

        # Parse trust policy
        trust_policy = role.get("AssumeRolePolicyDocument")
        if trust_policy:
            if isinstance(trust_policy, str):
                trust_policy = json.loads(trust_policy)
            
            for statement in trust_policy.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue
                
                principal = statement.get("Principal", {})
                
                # Check for overly permissive trust
                if principal == "*" or principal.get("AWS") == "*":
                    findings.append(Finding(
                        snapshot_id=self._snapshot_id,
                        asset_id=asset.id,
                        finding_type="iam-role-trust-any-principal",
                        severity=FindingSeverity.critical,
                        title=f"IAM role {role_name} trusts any principal",
                        description="Role trust policy allows any AWS principal to assume it",
                        remediation="Restrict the Principal to specific AWS accounts or roles",
                        evidence={"trust_policy": trust_policy},
                    ))

        return asset, relationships, findings
