from __future__ import annotations

import json

import pytest


def test_latest_pointer_traversal_is_rejected_and_falls_back(tmp_path):
    from cyntrisec.storage.filesystem import FileSystemStorage

    base_dir = tmp_path / "scans"
    storage = FileSystemStorage(base_dir=base_dir)

    good_scan_id = "2026-01-20_010203_123456789012"
    (base_dir / good_scan_id).mkdir(parents=True, exist_ok=True)

    # Simulate Windows "latest" file fallback tampered with traversal
    (base_dir / "latest").write_text("../outside", encoding="utf-8")

    assert storage.resolve_scan_id(None) == good_scan_id
    scan_path = storage.get_scan_path(None)
    assert scan_path.resolve().is_relative_to(base_dir.resolve())


def test_report_html_escapes_user_controlled_fields():
    from cyntrisec.cli.report import _generate_html

    injected = "<script>alert('pwned')</script>"
    html_out = _generate_html(
        {
            "snapshot": {"aws_account_id": "123456789012", "regions": ["us-east-1"]},
            "assets": [],
            "findings": [{"severity": "high", "finding_type": "test", "title": injected}],
            "attack_paths": [{"risk_score": 0.9, "attack_vector": injected}],
        },
        title=injected,
    )

    assert injected not in html_out
    assert "&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;" in html_out


def test_business_config_loads_yaml_and_json_equivalently(tmp_path):
    from cyntrisec.core.business_config import BusinessConfig

    config_dict = {
        "version": "1.0",
        "entrypoints": {"by_id": ["asset-1"], "by_tags": {"Environment": "Prod"}, "by_type": []},
        "critical_flows": [{"source": "asset-1", "target": "asset-2"}],
        "global_allowlist": {"App": "Frontend"},
    }

    json_path = tmp_path / "business.json"
    yaml_path = tmp_path / "business.yaml"

    json_path.write_text(json.dumps(config_dict), encoding="utf-8")
    yaml_path.write_text(
        "\n".join(
            [
                "version: '1.0'",
                "entrypoints:",
                "  by_id: ['asset-1']",
                "  by_tags: {Environment: 'Prod'}",
                "  by_type: []",
                "critical_flows:",
                "  - source: 'asset-1'",
                "    target: 'asset-2'",
                "global_allowlist: {App: 'Frontend'}",
            ]
        ),
        encoding="utf-8",
    )

    cfg_json = BusinessConfig.load(str(json_path))
    cfg_yaml = BusinessConfig.load(str(yaml_path))

    assert cfg_json == cfg_yaml


def test_terraform_output_is_truncated(monkeypatch):
    from cyntrisec.cli.remediate import _run_terraform

    class Result:
        def __init__(self, stdout: bytes, stderr: bytes, returncode: int = 0):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    def mock_run(cmd, **kwargs):
        if "init" in cmd:
            return Result(stdout=b"Initialized", stderr=b"")
        return Result(stdout=b"A" * 10000, stderr=b"B" * 10000)

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
    monkeypatch.setattr("subprocess.run", mock_run)

    result = _run_terraform("terraform", "/path/to/tf/dir", include_output=True)
    assert result["ok"] is True
    assert "...[truncated" in result["stdout"]
    assert "...[truncated" in result["stderr"]
