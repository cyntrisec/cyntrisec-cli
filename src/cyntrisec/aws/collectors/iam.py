"""IAM Collector - Collect IAM users, roles, policies."""

from __future__ import annotations

from typing import Any

import boto3


class IamCollector:
    """Collect IAM resources (global)."""

    def __init__(self, session: boto3.Session):
        self._iam = session.client("iam")

    def collect_all(self) -> dict[str, Any]:
        """Collect all IAM data."""
        return {
            "users": self._collect_users(),
            "roles": self._collect_roles(),
            "policies": self._collect_policies(),
            "instance_profiles": self._collect_instance_profiles(),
        }

    def _collect_users(self) -> list[dict]:
        """Collect IAM users."""
        users = []
        paginator = self._iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
        return [dict(u) for u in users]

    def _collect_roles(self) -> list[dict]:
        """Collect IAM roles with trust policies."""
        roles = []
        paginator = self._iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role_data in page.get("Roles", []):
                role = dict(role_data)
                role_name = role.get("RoleName")
                if role_name:
                    role["InlinePolicies"] = self._collect_inline_role_policies(str(role_name))
                    role["AttachedPolicies"] = self._collect_attached_role_policies(str(role_name))
                # Trust policy is included in list_roles
                roles.append(role)
        return roles

    def _collect_policies(self) -> list[dict]:
        """Collect customer-managed policies."""
        policies = []
        paginator = self._iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            policies.extend(page.get("Policies", []))
        return [dict(p) for p in policies]

    def _collect_inline_role_policies(self, role_name: str) -> list[dict]:
        """Collect inline policy documents for a role."""
        policies: list[dict] = []
        paginator = self._iam.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page.get("PolicyNames", []):
                try:
                    response = self._iam.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name,
                    )
                except Exception:
                    continue
                policies.append(
                    {
                        "PolicyName": policy_name,
                        "Document": response.get("PolicyDocument"),
                    }
                )
        return policies

    def _collect_attached_role_policies(self, role_name: str) -> list[dict]:
        """Collect attached managed policy documents for a role."""
        policies: list[dict] = []
        paginator = self._iam.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy in page.get("AttachedPolicies", []):
                policy_arn = policy.get("PolicyArn")
                if not policy_arn:
                    continue
                document = self._get_managed_policy_document(policy_arn)
                policies.append(
                    {
                        "PolicyName": policy.get("PolicyName"),
                        "PolicyArn": policy_arn,
                        "Document": document,
                    }
                )
        return policies

    def _get_managed_policy_document(self, policy_arn: str) -> dict | None:
        """Fetch the default policy document for a managed policy."""
        try:
            policy = self._iam.get_policy(PolicyArn=policy_arn)
            version_id = policy.get("Policy", {}).get("DefaultVersionId")
            if not version_id:
                return None
            version = self._iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )
            doc = version.get("PolicyVersion", {}).get("Document")
            if isinstance(doc, dict):
                return dict(doc)
            return {}
        except Exception:
            return None

    def _collect_instance_profiles(self) -> list[dict]:
        """Collect IAM instance profiles and attached roles."""
        profiles = []
        paginator = self._iam.get_paginator("list_instance_profiles")
        for page in paginator.paginate():
            profiles.extend(page.get("InstanceProfiles", []))
        return [dict(p) for p in profiles]
