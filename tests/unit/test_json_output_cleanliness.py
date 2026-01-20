"""
Unit tests for JSON output cleanliness.

Property 1: JSON Output Cleanliness
*For any* CLI command with --format json, the stdout output SHALL be valid JSON
with no non-JSON content.

Tests for:
- stdout contains only valid JSON when --format json is used
- status messages go to stderr
- no human-readable logs in stdout

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 21.1**
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cyntrisec.cli.output import emit_agent_or_json, resolve_format


class TestJsonOutputCleanliness:
    """Tests for JSON output cleanliness - Property 1."""

    def test_emit_agent_or_json_outputs_valid_json(self, capsys):
        """Test that emit_agent_or_json outputs valid JSON to stdout."""
        emit_agent_or_json(
            "json",
            {"test": "data", "count": 42},
            status="success",
        )
        captured = capsys.readouterr()
        
        # stdout should contain valid JSON
        payload = json.loads(captured.out)
        assert payload["status"] == "success"
        assert payload["data"]["test"] == "data"
        assert payload["data"]["count"] == 42
        
        # stderr should be empty for this call
        assert captured.err == ""

    def test_emit_agent_format_outputs_valid_json(self, capsys):
        """Test that emit_agent_or_json with agent format outputs valid JSON."""
        emit_agent_or_json(
            "agent",
            {"result": "success"},
            suggested=[{"command": "cyntrisec scan", "reason": "Run a scan"}],
            status="success",
        )
        captured = capsys.readouterr()
        
        # stdout should contain valid JSON
        payload = json.loads(captured.out)
        assert payload["status"] == "success"
        assert payload["data"]["result"] == "success"
        assert payload["suggested_actions"][0]["command"] == "cyntrisec scan"

    def test_json_output_has_schema_version(self, capsys):
        """Test that JSON output includes schema_version field."""
        emit_agent_or_json(
            "json",
            {"test": True},
            status="success",
        )
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        
        assert "schema_version" in payload
        assert payload["schema_version"] == "1.0"

    def test_json_output_no_extra_text(self, capsys):
        """Test that JSON output contains no extra text before or after JSON."""
        emit_agent_or_json(
            "json",
            {"key": "value"},
            status="success",
        )
        captured = capsys.readouterr()
        
        # The output should be parseable as JSON without stripping
        # (json.loads handles leading/trailing whitespace, but not other text)
        output = captured.out
        
        # Verify no non-JSON content by checking the output starts with { and ends with }
        stripped = output.strip()
        assert stripped.startswith("{"), "JSON output should start with {"
        assert stripped.endswith("}"), "JSON output should end with }"
        
        # Verify it's valid JSON
        json.loads(output)


class TestStatusMessagesToStderr:
    """Tests for status messages going to stderr."""

    def test_typer_echo_with_err_true_goes_to_stderr(self, capsys):
        """Test that typer.echo with err=True outputs to stderr."""
        import typer
        
        typer.echo("Status message", err=True)
        captured = capsys.readouterr()
        
        assert captured.out == ""
        assert "Status message" in captured.err

    def test_typer_echo_without_err_goes_to_stdout(self, capsys):
        """Test that typer.echo without err outputs to stdout."""
        import typer
        
        typer.echo("Output message")
        captured = capsys.readouterr()
        
        assert "Output message" in captured.out
        assert captured.err == ""


class TestResolveFormat:
    """Tests for resolve_format function."""

    def test_resolve_format_returns_json_when_not_tty(self, monkeypatch):
        """Test that resolve_format defaults to json when stdout is not a TTY."""
        from types import SimpleNamespace
        import sys
        
        fake_stdout = SimpleNamespace(isatty=lambda: False)
        monkeypatch.setattr(sys, "stdout", fake_stdout)
        
        fmt = resolve_format(None, default_tty="text", allowed=["text", "json", "agent"])
        assert fmt == "json"

    def test_resolve_format_returns_default_when_tty(self, monkeypatch):
        """Test that resolve_format returns default_tty when stdout is a TTY."""
        from types import SimpleNamespace
        import sys
        
        fake_stdout = SimpleNamespace(isatty=lambda: True)
        monkeypatch.setattr(sys, "stdout", fake_stdout)
        
        fmt = resolve_format(None, default_tty="text", allowed=["text", "json", "agent"])
        assert fmt == "text"

    def test_resolve_format_respects_explicit_format(self, monkeypatch):
        """Test that resolve_format respects explicitly specified format."""
        from types import SimpleNamespace
        import sys
        
        fake_stdout = SimpleNamespace(isatty=lambda: True)
        monkeypatch.setattr(sys, "stdout", fake_stdout)
        
        fmt = resolve_format("json", default_tty="text", allowed=["text", "json", "agent"])
        assert fmt == "json"


class TestScanJsonOutput:
    """Tests for scan command JSON output cleanliness."""

    def test_scan_status_messages_use_err_true(self):
        """Verify scan.py uses err=True for status messages."""
        import inspect
        from cyntrisec.cli import scan
        
        source = inspect.getsource(scan.scan_cmd)
        
        # Check that status messages use err=True
        assert 'typer.echo("Starting AWS scan...", err=True)' in source
        assert 'typer.echo("Scan complete!", err=True)' in source
        assert 'typer.echo(f"  Assets: {snapshot.asset_count}", err=True)' in source


class TestValidateJsonOutput:
    """Tests for validate-role command JSON output cleanliness."""

    def test_validate_status_messages_use_err_true(self):
        """Verify validate.py uses err=True for status messages."""
        import inspect
        from cyntrisec.cli import validate
        
        source = inspect.getsource(validate.validate_role_cmd)
        
        # Check that status messages use err=True
        assert 'err=True' in source
        # The "Validating role:" message should use err=True
        assert 'typer.echo(f"Validating role: {role_arn}", err=True)' in source


class TestCanJsonOutput:
    """Tests for can command JSON output cleanliness."""

    def test_can_uses_rich_console_for_status(self):
        """Verify can.py uses a stderr console for status output."""
        import inspect
        from cyntrisec.cli import can
        
        source = inspect.getsource(can)
        
        assert "Console(stderr=True)" in source
        assert 'status_console.print("[cyan]Running live policy simulation...[/cyan]")' in source


class TestPropertyJsonOutputCleanliness:
    """Property-based tests for JSON output cleanliness."""

    @given(st.dictionaries(
        keys=st.sampled_from(["key1", "key2", "key3", "name", "value", "count", "status"]),
        values=st.one_of(
            st.text(max_size=50),
            st.integers(min_value=-1000, max_value=1000),
            st.booleans(),
            st.none(),
        ),
        min_size=1,
        max_size=5,
    ))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
    def test_property_emit_produces_valid_json(self, capsys, data):
        """Property 1: JSON Output Cleanliness.
        
        *For any* data dictionary passed to emit_agent_or_json,
        the stdout output SHALL be valid JSON.
        
        **Feature: v0.1.3-bugfixes, Property 1: JSON Output Cleanliness**
        **Validates: Requirements 1.1, 1.2, 1.3**
        """
        emit_agent_or_json(
            "json",
            data,
            status="success",
        )
        captured = capsys.readouterr()
        
        # stdout should contain valid JSON
        try:
            payload = json.loads(captured.out)
        except json.JSONDecodeError as e:
            pytest.fail(f"Output is not valid JSON: {e}\nOutput: {captured.out}")
        
        # Verify structure
        assert "status" in payload
        assert "data" in payload
        assert "schema_version" in payload

    @given(st.sampled_from(["json", "agent"]))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_format_produces_valid_json(self, capsys, format_type):
        """Property 1: JSON Output Cleanliness.
        
        *For any* format type (json or agent),
        the stdout output SHALL be valid JSON.
        
        **Feature: v0.1.3-bugfixes, Property 1: JSON Output Cleanliness**
        **Validates: Requirements 1.1, 1.3**
        """
        emit_agent_or_json(
            format_type,
            {"test": "data"},
            status="success",
        )
        captured = capsys.readouterr()
        
        # stdout should contain valid JSON
        try:
            payload = json.loads(captured.out)
        except json.JSONDecodeError as e:
            pytest.fail(f"Output is not valid JSON for format {format_type}: {e}")
        
        assert payload["status"] == "success"


class TestJsonOutputNoLogMessages:
    """Tests verifying JSON output contains no log messages."""

    def test_json_output_no_starting_message(self, capsys):
        """Test that JSON output doesn't contain 'Starting' messages."""
        emit_agent_or_json(
            "json",
            {"scan_id": "test"},
            status="success",
        )
        captured = capsys.readouterr()
        
        # stdout should not contain status messages
        assert "Starting" not in captured.out
        assert "Validating" not in captured.out
        assert "Running" not in captured.out
        assert "Fetching" not in captured.out

    def test_json_output_is_parseable_without_preprocessing(self, capsys):
        """Test that JSON output can be parsed without any preprocessing."""
        emit_agent_or_json(
            "json",
            {"key": "value", "number": 123},
            status="success",
        )
        captured = capsys.readouterr()
        
        # Should be able to parse directly without stripping log lines
        payload = json.loads(captured.out)
        assert payload["data"]["key"] == "value"
        assert payload["data"]["number"] == 123

