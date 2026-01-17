from __future__ import annotations

import json
import sys
from types import SimpleNamespace

from cyntrisec.cli.output import emit_agent_or_json, resolve_format


def test_resolve_format_defaults_to_json_when_not_tty(monkeypatch):
    fake_stdout = SimpleNamespace(isatty=lambda: False)
    monkeypatch.setattr(sys, "stdout", fake_stdout)
    
    fmt = resolve_format(None, default_tty="table", allowed=["table", "json", "agent"])
    assert fmt == "json"


def test_resolve_format_respects_explicit_format(monkeypatch):
    fake_stdout = SimpleNamespace(isatty=lambda: True)
    monkeypatch.setattr(sys, "stdout", fake_stdout)
    
    fmt = resolve_format("table", default_tty="json", allowed=["table", "json"])
    assert fmt == "table"


def test_emit_agent_includes_suggested_actions(capsys):
    emit_agent_or_json(
        "agent",
        {"ok": True},
        suggested=[{"command": "do-thing", "reason": "because"}],
        status="success",
    )
    captured = capsys.readouterr().out
    payload = json.loads(captured)
    
    assert payload["status"] == "success"
    assert payload["schema_version"]
    assert payload["data"] == {"ok": True}
    assert payload["suggested_actions"][0]["command"] == "do-thing"
    assert "artifact_paths" in payload  # may be null
