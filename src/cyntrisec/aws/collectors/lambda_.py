"""Lambda Collector - Collect Lambda functions."""
from __future__ import annotations

from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError


class LambdaCollector:
    """Collect Lambda resources."""

    def __init__(self, session: boto3.Session, region: str):
        self._lambda = session.client("lambda", region_name=region)
        self._region = region

    def collect_all(self) -> Dict[str, Any]:
        """Collect all Lambda data."""
        functions = self._collect_functions()
        
        # Enrich with policies
        for func in functions:
            name = func["FunctionName"]
            func["Policy"] = self._get_function_policy(name)
        
        return {"functions": functions}

    def _collect_functions(self) -> List[Dict]:
        """List all Lambda functions."""
        functions = []
        paginator = self._lambda.get_paginator("list_functions")
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))
        return functions

    def _get_function_policy(self, function_name: str) -> Dict | None:
        """Get function resource policy."""
        try:
            response = self._lambda.get_policy(FunctionName=function_name)
            return {"Policy": response.get("Policy")}
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            return {"Error": str(e)}
