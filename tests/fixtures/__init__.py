"""Test fixtures for cyntrisec-cli."""

from tests.fixtures.vulnerable_aws_scenarios import (
    ALL_SCENARIOS,
    ExpectedPath,
    SNAPSHOT_ID,
    get_all_scenarios,
    get_scenario,
    make_asset,
    make_ec2_instance,
    make_iam_role,
    make_internet_asset,
    make_lambda_function,
    make_relationship,
    make_security_group,
)

__all__ = [
    "ALL_SCENARIOS",
    "ExpectedPath",
    "SNAPSHOT_ID",
    "get_all_scenarios",
    "get_scenario",
    "make_asset",
    "make_ec2_instance",
    "make_iam_role",
    "make_internet_asset",
    "make_lambda_function",
    "make_relationship",
    "make_security_group",
]
