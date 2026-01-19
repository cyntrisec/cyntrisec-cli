from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cyntrisec.cli import manifest


def test_manifest_includes_ask_and_remediate():
    names = {c["name"] for c in manifest.CAPABILITIES}
    assert "ask" in names
    assert "remediate" in names


def test_scan_role_arn_is_not_required():
    """Test scan.role_arn is not required (Requirements 7.1)."""
    scan_cmd = next(c for c in manifest.CAPABILITIES if c["name"] == "scan")
    role_arn_param = next(p for p in scan_cmd["parameters"] if p["name"] == "role_arn")
    assert role_arn_param["required"] is False


def test_scan_has_profile_and_format_parameters():
    """Test scan command has profile and format parameters (Requirements 7.2)."""
    scan_cmd = next(c for c in manifest.CAPABILITIES if c["name"] == "scan")
    param_names = {p["name"] for p in scan_cmd["parameters"]}
    assert "profile" in param_names
    assert "format" in param_names


def test_scan_output_uses_correct_field_names():
    """Test scan output uses asset_count not assets (Requirements 7.3)."""
    scan_cmd = next(c for c in manifest.CAPABILITIES if c["name"] == "scan")
    output_props = scan_cmd["output"]["properties"]
    assert "asset_count" in output_props
    assert "relationship_count" in output_props
    assert "finding_count" in output_props
    assert "attack_path_count" in output_props
    # Should NOT have old field names
    assert "assets" not in output_props
    assert "relationships" not in output_props
    assert "findings" not in output_props
    assert "attack_paths" not in output_props


# Commands that should have --snapshot parameter
COMMANDS_WITH_SNAPSHOT = ["cuts", "waste", "can", "comply"]


@pytest.mark.parametrize("cmd_name", COMMANDS_WITH_SNAPSHOT)
def test_commands_have_snapshot_parameter(cmd_name):
    """Test commands with --snapshot have snapshot parameter (Requirements 7.4).
    
    **Feature: cyntrisec-bugfixes, Property 6: Manifest Parameter Completeness**
    """
    cmd = next((c for c in manifest.CAPABILITIES if c["name"] == cmd_name), None)
    assert cmd is not None, f"Command {cmd_name} not found in manifest"
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "snapshot" in param_names, f"Command {cmd_name} missing snapshot parameter"


def test_analyze_paths_has_scan_parameter():
    """Test analyze paths has scan parameter (Requirements 7.4)."""
    cmd = next(c for c in manifest.CAPABILITIES if c["name"] == "analyze paths")
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "scan" in param_names


# Commands that should have agent in format enum
COMMANDS_WITH_AGENT_FORMAT = ["cuts", "waste", "can", "diff", "comply", "analyze paths"]


@pytest.mark.parametrize("cmd_name", COMMANDS_WITH_AGENT_FORMAT)
def test_commands_have_agent_in_format_enum(cmd_name):
    """Test commands with agent format have agent in enum (Requirements 7.5).
    
    **Feature: cyntrisec-bugfixes, Property 7: Manifest Format Enum Completeness**
    """
    cmd = next((c for c in manifest.CAPABILITIES if c["name"] == cmd_name), None)
    assert cmd is not None, f"Command {cmd_name} not found in manifest"
    format_param = next((p for p in cmd["parameters"] if p["name"] == "format"), None)
    assert format_param is not None, f"Command {cmd_name} missing format parameter"
    assert "enum" in format_param, f"Command {cmd_name} format param missing enum"
    assert "agent" in format_param["enum"], f"Command {cmd_name} format enum missing 'agent'"


# All CLI commands that should have manifest entries
EXPECTED_COMMANDS = [
    "scan",
    "cuts",
    "waste",
    "can",
    "diff",
    "comply",
    "analyze paths",
    "analyze business",
    "analyze findings",
    "analyze stats",
    "remediate",
    "ask",
    "report",
    "validate-role",
    "setup iam",
    "explain",
]


@pytest.mark.parametrize("cmd_name", EXPECTED_COMMANDS)
def test_all_cli_commands_have_manifest_entries(cmd_name):
    """Test all CLI commands have manifest entries (Requirements 12.1-12.6).
    
    **Feature: cyntrisec-bugfixes, Property 10: Manifest Command Coverage**
    """
    names = {c["name"] for c in manifest.CAPABILITIES}
    assert cmd_name in names, f"Command {cmd_name} missing from manifest"


def test_cuts_has_cost_source_parameter():
    """Test cuts has cost-source parameter (Requirements 7.6)."""
    cmd = next(c for c in manifest.CAPABILITIES if c["name"] == "cuts")
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "cost_source" in param_names


def test_waste_has_cost_source_and_max_roles():
    """Test waste has cost-source and max-roles parameters (Requirements 7.6)."""
    cmd = next(c for c in manifest.CAPABILITIES if c["name"] == "waste")
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "cost_source" in param_names
    assert "max_roles" in param_names


def test_analyze_paths_has_min_risk_and_limit():
    """Test analyze paths has min-risk and limit parameters (Requirements 7.6)."""
    cmd = next(c for c in manifest.CAPABILITIES if c["name"] == "analyze paths")
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "min_risk" in param_names
    assert "limit" in param_names


def test_report_command_exists():
    """Test report command entry exists (Requirements 12.1)."""
    cmd = next((c for c in manifest.CAPABILITIES if c["name"] == "report"), None)
    assert cmd is not None
    assert cmd["description"] is not None
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "scan" in param_names
    assert "output" in param_names
    assert "format" in param_names


def test_validate_role_command_exists():
    """Test validate-role command entry exists (Requirements 12.2)."""
    cmd = next((c for c in manifest.CAPABILITIES if c["name"] == "validate-role"), None)
    assert cmd is not None
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "role_arn" in param_names
    assert "external_id" in param_names


def test_setup_iam_command_exists():
    """Test setup iam command entry exists (Requirements 12.3)."""
    cmd = next((c for c in manifest.CAPABILITIES if c["name"] == "setup iam"), None)
    assert cmd is not None
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "account_id" in param_names
    assert "format" in param_names


def test_explain_command_exists():
    """Test explain command entry exists (Requirements 12.4)."""
    cmd = next((c for c in manifest.CAPABILITIES if c["name"] == "explain"), None)
    assert cmd is not None
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "category" in param_names
    assert "identifier" in param_names
    assert "format" in param_names


def test_analyze_findings_command_exists():
    """Test analyze findings command entry exists (Requirements 12.5)."""
    cmd = next((c for c in manifest.CAPABILITIES if c["name"] == "analyze findings"), None)
    assert cmd is not None
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "scan" in param_names
    assert "severity" in param_names
    assert "format" in param_names


def test_analyze_stats_command_exists():
    """Test analyze stats command entry exists (Requirements 12.6)."""
    cmd = next((c for c in manifest.CAPABILITIES if c["name"] == "analyze stats"), None)
    assert cmd is not None
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "scan" in param_names
    assert "format" in param_names


# Property-based tests

@given(st.sampled_from(COMMANDS_WITH_SNAPSHOT))
@settings(max_examples=100)
def test_property_snapshot_parameter_completeness(cmd_name):
    """Property 6: Manifest Parameter Completeness.
    
    *For any* CLI command that accepts a --snapshot parameter,
    the manifest description SHALL include the snapshot parameter.
    
    **Feature: cyntrisec-bugfixes, Property 6: Manifest Parameter Completeness**
    **Validates: Requirements 7.4**
    """
    cmd = next((c for c in manifest.CAPABILITIES if c["name"] == cmd_name), None)
    assert cmd is not None
    param_names = {p["name"] for p in cmd["parameters"]}
    assert "snapshot" in param_names


@given(st.sampled_from(COMMANDS_WITH_AGENT_FORMAT))
@settings(max_examples=100)
def test_property_format_enum_completeness(cmd_name):
    """Property 7: Manifest Format Enum Completeness.
    
    *For any* CLI command that supports --format agent,
    the manifest format enum SHALL include "agent".
    
    **Feature: cyntrisec-bugfixes, Property 7: Manifest Format Enum Completeness**
    **Validates: Requirements 7.5**
    """
    cmd = next((c for c in manifest.CAPABILITIES if c["name"] == cmd_name), None)
    assert cmd is not None
    format_param = next((p for p in cmd["parameters"] if p["name"] == "format"), None)
    assert format_param is not None
    assert "agent" in format_param.get("enum", [])


@given(st.sampled_from(EXPECTED_COMMANDS))
@settings(max_examples=100)
def test_property_manifest_command_coverage(cmd_name):
    """Property 10: Manifest Command Coverage.
    
    *For any* CLI command available via cyntrisec --help,
    the manifest SHALL include a corresponding capability entry.
    
    **Feature: cyntrisec-bugfixes, Property 10: Manifest Command Coverage**
    **Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.6**
    """
    names = {c["name"] for c in manifest.CAPABILITIES}
    assert cmd_name in names
