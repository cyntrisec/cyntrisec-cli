"""
Central error handling and envelope utilities.

Defines a small error taxonomy and helpers to wrap CLI commands so that
all failures return a consistent agent-friendly envelope.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import typer
from pydantic import ValidationError

from cyntrisec.cli.output import emit_agent_or_json


class ErrorCode:
    AWS_ACCESS_DENIED = "AWS_ACCESS_DENIED"
    AWS_THROTTLED = "AWS_THROTTLED"
    AWS_REGION_DISABLED = "AWS_REGION_DISABLED"
    SNAPSHOT_NOT_FOUND = "SNAPSHOT_NOT_FOUND"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    INVALID_QUERY = "INVALID_QUERY"
    INTERNAL_ERROR = "INTERNAL_ERROR"


EXIT_CODE_MAP = {
    "ok": 0,
    "findings": 1,
    "usage": 2,
    "transient": 3,
    "internal": 4,
}


@dataclass
class CyntriError(Exception):
    error_code: str
    message: str
    details: Any | None = None
    hint: str | None = None
    retryable: bool = False
    status: str = "error"
    exit_code: int = EXIT_CODE_MAP["internal"]

    def to_payload(self) -> dict:
        return {
            "message": self.message,
            "details": self.details,
            "hint": self.hint,
        }


def handle_errors(command: Callable) -> Callable:
    """
    Decorator to wrap Typer commands and emit consistent envelopes on failure.
    """

    @functools.wraps(command)
    def wrapper(*args, **kwargs):
        from typer.models import OptionInfo

        clean_kwargs = {k: (None if isinstance(v, OptionInfo) else v) for k, v in kwargs.items()}
        format_arg = clean_kwargs.get("format") or clean_kwargs.get("output_format")
        try:
            return command(*args, **clean_kwargs)
        except CyntriError as ce:
            emit_agent_or_json(
                "agent" if format_arg in {"agent", "json"} else "json",
                ce.to_payload(),
                status=ce.status,
                error_code=ce.error_code,
                message=ce.message,
                suggested=[],
            )
            raise typer.Exit(code=ce.exit_code)
        except ValidationError as ve:
            emit_agent_or_json(
                "json",
                {"errors": ve.errors()},
                status="error",
                error_code=ErrorCode.SCHEMA_MISMATCH,
                message="Response schema validation failed",
                suggested=[],
            )
            raise typer.Exit(code=EXIT_CODE_MAP["internal"])
        except typer.Exit:
            raise
        except Exception as e:  # pragma: no cover
            emit_agent_or_json(
                "json",
                {"message": str(e)},
                status="error",
                error_code=ErrorCode.INTERNAL_ERROR,
                message=str(e),
                suggested=[],
            )
            raise typer.Exit(code=EXIT_CODE_MAP["internal"])

    return wrapper
