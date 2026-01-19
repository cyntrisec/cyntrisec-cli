"""
Unit tests for SSO error handling.

Tests for:
- SSO errors return AUTH_ERROR error code
- No tracebacks in JSON output
- Error envelope structure is correct

**Validates: Requirements 7.1, 7.2, 7.3, 7.4, 21.7**
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import typer

from cyntrisec.cli.errors import (
    CyntriError,
    ErrorCode,
    EXIT_CODE_MAP,
    handle_errors,
)
from cyntrisec.cli.output import emit_agent_or_json


class TestAuthErrorCode:
    """Tests for AUTH_ERROR error code existence and usage."""

    def test_auth_error_exists_in_error_code(self):
        """Test that AUTH_ERROR is defined in ErrorCode class.
        
        **Validates: Requirements 7.1**
        """
        assert hasattr(ErrorCode, "AUTH_ERROR")
        assert ErrorCode.AUTH_ERROR == "AUTH_ERROR"

    def test_auth_error_distinct_from_internal_error(self):
        """Test that AUTH_ERROR is distinct from INTERNAL_ERROR.
        
        **Validates: Requirements 7.1**
        """
        assert ErrorCode.AUTH_ERROR != ErrorCode.INTERNAL_ERROR


class TestCyntriErrorWithAuthError:
    """Tests for CyntriError with AUTH_ERROR code."""

    def test_cyntri_error_with_auth_error_code(self):
        """Test that CyntriError can be created with AUTH_ERROR code."""
        error = CyntriError(
            error_code=ErrorCode.AUTH_ERROR,
            message="SSO authentication failed",
            hint="Run 'aws sso login --profile myprofile' to refresh credentials",
            exit_code=EXIT_CODE_MAP["usage"],
        )
        
        assert error.error_code == ErrorCode.AUTH_ERROR
        assert "SSO" in error.message
        assert "aws sso login" in error.hint

    def test_cyntri_error_to_payload_includes_hint(self):
        """Test that CyntriError.to_payload() includes hint for user guidance."""
        error = CyntriError(
            error_code=ErrorCode.AUTH_ERROR,
            message="SSO token expired",
            hint="Run 'aws sso login --profile test' to refresh",
            exit_code=EXIT_CODE_MAP["usage"],
        )
        
        payload = error.to_payload()
        assert payload["message"] == "SSO token expired"
        assert payload["hint"] == "Run 'aws sso login --profile test' to refresh"


class TestErrorEnvelopeNoTraceback:
    """Tests for error envelope containing no tracebacks."""

    def test_error_envelope_no_traceback_in_json(self, capsys):
        """Test that error envelope in JSON format contains no traceback.
        
        **Validates: Requirements 7.2, 7.4**
        """
        emit_agent_or_json(
            "json",
            {"message": "Authentication failed"},
            status="error",
            error_code=ErrorCode.AUTH_ERROR,
            message="SSO token expired",
        )
        
        captured = capsys.readouterr()
        output = captured.out
        
        # Should be valid JSON
        payload = json.loads(output)
        
        # Should not contain traceback indicators
        output_str = json.dumps(payload)
        assert "Traceback" not in output_str
        assert "File \"" not in output_str
        assert "line " not in output_str.lower() or "line" in payload.get("message", "").lower()

    def test_error_envelope_structure_is_clean(self, capsys):
        """Test that error envelope has clean structure without debug info.
        
        **Validates: Requirements 7.4**
        """
        emit_agent_or_json(
            "agent",
            {"error_details": "Token expired"},
            status="error",
            error_code=ErrorCode.AUTH_ERROR,
            message="Authentication failed",
        )
        
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        
        # Verify expected structure
        assert payload["status"] == "error"
        assert payload["error_code"] == ErrorCode.AUTH_ERROR
        assert payload["message"] == "Authentication failed"
        assert "schema_version" in payload
        
        # Should not have internal debug fields
        assert "__traceback__" not in payload
        assert "stack_trace" not in payload


class TestHandleErrorsDecorator:
    """Tests for handle_errors decorator with AUTH_ERROR."""

    def test_handle_errors_catches_cyntri_error_with_auth_error(self, capsys):
        """Test that handle_errors decorator properly handles AUTH_ERROR.
        
        **Validates: Requirements 7.1, 7.4**
        """
        @handle_errors
        def failing_command(format: str = "json"):
            raise CyntriError(
                error_code=ErrorCode.AUTH_ERROR,
                message="SSO authentication failed",
                hint="Run 'aws sso login'",
                exit_code=EXIT_CODE_MAP["usage"],
            )
        
        with pytest.raises(typer.Exit) as exc:
            failing_command(format="json")
        
        assert exc.value.exit_code == EXIT_CODE_MAP["usage"]
        
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        
        assert payload["status"] == "error"
        assert payload["error_code"] == ErrorCode.AUTH_ERROR
        assert "SSO" in payload["data"]["message"]

    def test_handle_errors_no_traceback_for_cyntri_error(self, capsys):
        """Test that handle_errors doesn't include traceback for CyntriError.
        
        **Validates: Requirements 7.2**
        """
        @handle_errors
        def failing_command(format: str = "json"):
            raise CyntriError(
                error_code=ErrorCode.AUTH_ERROR,
                message="Token expired",
                exit_code=EXIT_CODE_MAP["usage"],
            )
        
        with pytest.raises(typer.Exit):
            failing_command(format="json")
        
        captured = capsys.readouterr()
        
        # stdout should be clean JSON without traceback
        assert "Traceback" not in captured.out
        assert "File \"" not in captured.out
        
        # stderr should also not have traceback (handle_errors catches it)
        assert "Traceback" not in captured.err

    def test_handle_errors_internal_error_no_traceback_in_stdout(self, capsys):
        """Test that even INTERNAL_ERROR doesn't leak traceback to stdout.
        
        **Validates: Requirements 7.2, 7.4**
        """
        @handle_errors
        def failing_command(format: str = "json"):
            raise ValueError("Something went wrong internally")
        
        with pytest.raises(typer.Exit):
            failing_command(format="json")
        
        captured = capsys.readouterr()
        
        # stdout should be clean JSON
        payload = json.loads(captured.out)
        assert payload["status"] == "error"
        assert payload["error_code"] == ErrorCode.INTERNAL_ERROR
        
        # stdout should not contain traceback
        assert "Traceback" not in captured.out


class TestJsonOutputOnError:
    """Tests for JSON output cleanliness when errors occur."""

    def test_json_output_valid_on_auth_error(self, capsys):
        """Test that JSON output is valid even when AUTH_ERROR occurs.
        
        **Validates: Requirements 7.4**
        """
        emit_agent_or_json(
            "json",
            {"message": "SSO token expired"},
            status="error",
            error_code=ErrorCode.AUTH_ERROR,
            message="Authentication failed. Run 'aws sso login --profile test'",
        )
        
        captured = capsys.readouterr()
        
        # Should be parseable JSON
        try:
            payload = json.loads(captured.out)
        except json.JSONDecodeError as e:
            pytest.fail(f"Error output is not valid JSON: {e}")
        
        # Verify structure
        assert payload["status"] == "error"
        assert payload["error_code"] == ErrorCode.AUTH_ERROR

    def test_agent_format_valid_on_auth_error(self, capsys):
        """Test that agent format output is valid even when AUTH_ERROR occurs.
        
        **Validates: Requirements 7.4**
        """
        emit_agent_or_json(
            "agent",
            {"message": "SSO token expired"},
            status="error",
            error_code=ErrorCode.AUTH_ERROR,
            message="Authentication failed",
        )
        
        captured = capsys.readouterr()
        
        # Should be parseable JSON
        payload = json.loads(captured.out)
        assert payload["status"] == "error"
        assert payload["error_code"] == ErrorCode.AUTH_ERROR


class TestErrorHintForSSO:
    """Tests for helpful error hints in SSO errors."""

    def test_auth_error_can_include_profile_hint(self, capsys):
        """Test that AUTH_ERROR can include profile-specific hint.
        
        **Validates: Requirements 7.3**
        """
        profile = "my-sso-profile"
        error = CyntriError(
            error_code=ErrorCode.AUTH_ERROR,
            message="SSO token expired",
            hint=f"Run 'aws sso login --profile {profile}' to refresh credentials",
            exit_code=EXIT_CODE_MAP["usage"],
        )
        
        emit_agent_or_json(
            "json",
            error.to_payload(),
            status="error",
            error_code=error.error_code,
            message=error.message,
        )
        
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        
        # Hint should be in the data payload
        assert "aws sso login" in payload["data"]["hint"]
        assert profile in payload["data"]["hint"]
