from __future__ import annotations

from cyntrisec.cli import manifest


def test_manifest_includes_ask_and_remediate():
    names = {c["name"] for c in manifest.CAPABILITIES}
    assert "ask" in names
    assert "remediate" in names
