"""
Usage Collector - Collect IAM last-accessed data for waste analysis.

Uses AWS IAM's generate_service_last_accessed_details API to determine
which permissions have actually been used vs which are just granted.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


@dataclass
class ServiceAccess:
    """Service access record from IAM last-accessed data."""
    service_name: str
    service_namespace: str
    last_authenticated: Optional[datetime] = None
    last_authenticated_entity: Optional[str] = None
    total_authenticated_entities: int = 0
    
    @property
    def is_unused(self) -> bool:
        """Check if service was never accessed."""
        return self.last_authenticated is None


@dataclass 
class ActionAccess:
    """Action-level access record."""
    action_name: str
    last_accessed: Optional[datetime] = None
    
    @property
    def is_unused(self) -> bool:
        return self.last_accessed is None


@dataclass
class RoleUsageReport:
    """Usage report for an IAM role."""
    role_arn: str
    role_name: str
    services: List[ServiceAccess] = field(default_factory=list)
    actions: List[ActionAccess] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def unused_services(self) -> List[ServiceAccess]:
        return [s for s in self.services if s.is_unused]
    
    @property
    def used_services(self) -> List[ServiceAccess]:
        return [s for s in self.services if not s.is_unused]


class UsageCollector:
    """
    Collect IAM usage data using AWS Access Advisor.
    
    The last-accessed data shows which services a role has permissions for
    and when those permissions were last used.
    """
    
    def __init__(self, session):
        """
        Initialize with a boto3 Session.
        
        Args:
            session: boto3.Session with IAM permissions
        """
        self._session = session
        self._iam = session.client("iam")
    
    def get_role_usage(
        self,
        role_arn: str,
        *,
        max_wait_seconds: int = 30,
    ) -> Optional[RoleUsageReport]:
        """
        Get usage report for an IAM role.
        
        Args:
            role_arn: ARN of the role to analyze
            max_wait_seconds: Maximum time to wait for report generation
            
        Returns:
            RoleUsageReport with service access data, or None if failed
        """
        role_name = role_arn.split("/")[-1]
        log.debug("Generating last-accessed report for %s", role_name)
        
        try:
            # Start the report generation
            response = self._iam.generate_service_last_accessed_details(
                Arn=role_arn,
                Granularity="SERVICE_LEVEL",
            )
            job_id = response["JobId"]
            
            # Poll for completion
            start_time = time.time()
            while time.time() - start_time < max_wait_seconds:
                result = self._iam.get_service_last_accessed_details(JobId=job_id)
                status = result.get("JobStatus")
                
                if status == "COMPLETED":
                    return self._parse_report(role_arn, role_name, result)
                elif status == "FAILED":
                    log.warning("Last-accessed report failed for %s", role_name)
                    return None
                
                time.sleep(1)
            
            log.warning("Timeout waiting for last-accessed report for %s", role_name)
            return None
            
        except Exception as e:
            log.debug("Error getting usage for %s: %s", role_name, e)
            return None
    
    def _parse_report(
        self,
        role_arn: str,
        role_name: str,
        result: Dict[str, Any],
    ) -> RoleUsageReport:
        """Parse the IAM last-accessed response."""
        services = []
        
        for svc in result.get("ServicesLastAccessed", []):
            last_auth = svc.get("LastAuthenticated")
            services.append(ServiceAccess(
                service_name=svc.get("ServiceName", ""),
                service_namespace=svc.get("ServiceNamespace", ""),
                last_authenticated=last_auth,
                last_authenticated_entity=svc.get("LastAuthenticatedEntity"),
                total_authenticated_entities=svc.get("TotalAuthenticatedEntities", 0),
            ))
        
        return RoleUsageReport(
            role_arn=role_arn,
            role_name=role_name,
            services=services,
        )
    
    def collect_all_roles(
        self,
        role_arns: List[str],
        *,
        max_roles: int = 50,
    ) -> List[RoleUsageReport]:
        """
        Collect usage reports for multiple roles.
        
        Args:
            role_arns: List of role ARNs to analyze
            max_roles: Maximum number of roles to analyze (API throttling)
            
        Returns:
            List of usage reports
        """
        reports = []
        
        for i, arn in enumerate(role_arns[:max_roles]):
            log.info("Analyzing role %d/%d: %s", i + 1, min(len(role_arns), max_roles), arn.split("/")[-1])
            report = self.get_role_usage(arn)
            if report:
                reports.append(report)
        
        return reports
