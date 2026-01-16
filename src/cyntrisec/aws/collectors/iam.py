"""IAM Collector - Collect IAM users, roles, policies."""
from __future__ import annotations

from typing import Any, Dict, List

import boto3


class IamCollector:
    """Collect IAM resources (global)."""

    def __init__(self, session: boto3.Session):
        self._iam = session.client("iam")

    def collect_all(self) -> Dict[str, Any]:
        """Collect all IAM data."""
        return {
            "users": self._collect_users(),
            "roles": self._collect_roles(),
            "policies": self._collect_policies(),
        }

    def _collect_users(self) -> List[Dict]:
        """Collect IAM users."""
        users = []
        paginator = self._iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
        return users

    def _collect_roles(self) -> List[Dict]:
        """Collect IAM roles with trust policies."""
        roles = []
        paginator = self._iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                # Trust policy is included in list_roles
                roles.append(role)
        return roles

    def _collect_policies(self) -> List[Dict]:
        """Collect customer-managed policies."""
        policies = []
        paginator = self._iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            policies.extend(page.get("Policies", []))
        return policies
