from __future__ import annotations

import json

from cyntrisec.cli.explain import explain_cmd
from cyntrisec.cli.setup import setup_iam
from cyntrisec.cli.serve import serve_cmd


def test_explain_agent_schema(capsys):
    explain_cmd(category="path", identifier="instance-compromise", format="agent")
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["type"] == "path"
    assert payload["data"]["id"] == "instance-compromise"
    assert payload["status"] == "success"


def test_setup_iam_agent_schema(capsys):
    setup_iam(account_id="123456789012", role_name="RoleName", external_id=None, format="terraform", output=None, output_format="agent")
    payload = json.loads(capsys.readouterr().out)
    data = payload["data"]
    assert data["account_id"] == "123456789012"
    assert data["template_format"] == "terraform"
    assert "template" in data


def test_serve_list_tools_agent(capsys):
    serve_cmd(list_tools=True, format="agent")
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["tools"]
