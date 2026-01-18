"""Lambda Normalizer - Transform Lambda data to canonical schema."""

from __future__ import annotations

import uuid
from typing import Any

from cyntrisec.core.schema import Asset, Finding, FindingSeverity, Relationship


class LambdaNormalizer:
    """Normalize Lambda data to canonical assets."""

    def __init__(
        self,
        snapshot_id: uuid.UUID,
        region: str,
        account_id: str,
    ):
        self._snapshot_id = snapshot_id
        self._region = region
        self._account_id = account_id

    def normalize(
        self,
        data: dict[str, Any],
    ) -> tuple[list[Asset], list[Relationship], list[Finding]]:
        """Normalize Lambda data."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        for func in data.get("functions", []):
            asset, func_findings = self._normalize_function(func)
            assets.append(asset)
            findings.extend(func_findings)

        return assets, [], findings

    def _normalize_function(
        self,
        func: dict[str, Any],
    ) -> tuple[Asset, list[Finding]]:
        """Normalize a Lambda function."""
        func_name = func["FunctionName"]
        func_arn = func["FunctionArn"]

        asset = Asset(
            snapshot_id=self._snapshot_id,
            asset_type="lambda:function",
            aws_region=self._region,
            aws_resource_id=func_arn,
            arn=func_arn,
            name=func_name,
            properties={
                "runtime": func.get("Runtime"),
                "handler": func.get("Handler"),
                "memory_size": func.get("MemorySize"),
                "timeout": func.get("Timeout"),
                "role": func.get("Role"),
                "vpc_config": func.get("VpcConfig"),
                "last_modified": func.get("LastModified"),
            },
        )

        findings: list[Finding] = []

        # Check for deprecated runtime
        runtime = func.get("Runtime", "")
        deprecated_runtimes = ["python2.7", "python3.6", "nodejs10.x", "nodejs12.x", "ruby2.5"]
        if any(runtime.startswith(dr) for dr in deprecated_runtimes):
            findings.append(
                Finding(
                    snapshot_id=self._snapshot_id,
                    asset_id=asset.id,
                    finding_type="lambda-deprecated-runtime",
                    severity=FindingSeverity.medium,
                    title=f"Lambda function {func_name} uses deprecated runtime",
                    description=f"Function uses runtime {runtime} which is deprecated or EOL",
                    remediation="Upgrade to a supported runtime version",
                )
            )

        return asset, findings
