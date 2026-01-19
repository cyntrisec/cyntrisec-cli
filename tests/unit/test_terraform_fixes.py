"""
Unit tests for Terraform integration fixes.

Tests for:
- Property 2: Terraform Argument Format - -chdir=<dir> format in subprocess calls
- Property 3: Remediate Status Accuracy - status reflects terraform result

**Validates: Requirements 2.1, 2.2, 2.3, 3.1, 3.2, 21.2, 21.3**
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

from cyntrisec.cli.remediate import _run_terraform, _run_terraform_plan


class TestTerraformArgumentFormat:
    """
    Property 2: Terraform Argument Format
    
    *For any* remediate command that invokes terraform, the -chdir argument
    SHALL be formatted as `-chdir=<dir>` (single argument).
    
    **Validates: Requirements 2.1, 2.2, 2.3**
    """

    def test_run_terraform_uses_chdir_equals_format(self, monkeypatch):
        """Test that _run_terraform uses -chdir=<dir> format."""
        captured_commands = []

        def mock_run(cmd, **kwargs):
            captured_commands.append(cmd)
            result = MagicMock()
            result.returncode = 0
            result.stdout = b"Success"
            result.stderr = b""
            return result

        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
        monkeypatch.setattr("subprocess.run", mock_run)

        _run_terraform("terraform", "/path/to/tf/dir")

        # Should have captured init and apply commands
        assert len(captured_commands) >= 2

        # Check init command
        init_cmd = captured_commands[0]
        assert any(arg.startswith("-chdir=") for arg in init_cmd), \
            f"Init command should use -chdir=<dir> format, got: {init_cmd}"
        assert "-chdir" not in init_cmd or not any(arg == "-chdir" for arg in init_cmd), \
            f"Init command should not have -chdir as separate argument, got: {init_cmd}"

        # Check apply command
        apply_cmd = captured_commands[1]
        assert any(arg.startswith("-chdir=") for arg in apply_cmd), \
            f"Apply command should use -chdir=<dir> format, got: {apply_cmd}"

    def test_run_terraform_plan_uses_chdir_equals_format(self, monkeypatch):
        """Test that _run_terraform_plan uses -chdir=<dir> format."""
        captured_commands = []

        def mock_run(cmd, **kwargs):
            captured_commands.append(cmd)
            result = MagicMock()
            result.returncode = 0
            result.stdout = b"Plan: 0 to add, 0 to change, 0 to destroy."
            result.stderr = b""
            return result

        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
        monkeypatch.setattr("subprocess.run", mock_run)

        _run_terraform_plan("terraform", "/path/to/tf/dir")

        # Should have captured init and plan commands
        assert len(captured_commands) >= 2

        # Check init command
        init_cmd = captured_commands[0]
        assert any(arg.startswith("-chdir=") for arg in init_cmd), \
            f"Init command should use -chdir=<dir> format, got: {init_cmd}"

        # Check plan command
        plan_cmd = captured_commands[1]
        assert any(arg.startswith("-chdir=") for arg in plan_cmd), \
            f"Plan command should use -chdir=<dir> format, got: {plan_cmd}"

    @given(tf_dir=st.text(min_size=1, max_size=100).filter(lambda x: x.strip() and "/" not in x[:1]))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_chdir_format_property_for_any_directory(self, tf_dir, monkeypatch):
        """
        Property test: For any valid directory path, -chdir should be formatted
        as a single argument with equals sign.
        
        **Feature: v0.1.3-bugfixes, Property 2: Terraform Argument Format**
        **Validates: Requirements 2.1, 2.2, 2.3**
        """
        # Skip empty or whitespace-only paths
        if not tf_dir.strip():
            return

        captured_commands = []

        def mock_run(cmd, **kwargs):
            captured_commands.append(cmd)
            result = MagicMock()
            result.returncode = 0
            result.stdout = b"Success"
            result.stderr = b""
            return result

        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
        monkeypatch.setattr("subprocess.run", mock_run)

        _run_terraform("terraform", tf_dir)

        # Verify all commands use -chdir=<dir> format
        for cmd in captured_commands:
            chdir_args = [arg for arg in cmd if "-chdir" in arg]
            for chdir_arg in chdir_args:
                assert chdir_arg.startswith("-chdir="), \
                    f"Expected -chdir=<dir> format, got: {chdir_arg}"
                # Verify the directory is included in the same argument
                assert "=" in chdir_arg, \
                    f"Expected equals sign in -chdir argument, got: {chdir_arg}"


class TestRemediateStatusAccuracy:
    """
    Property 3: Remediate Status Accuracy
    
    *For any* remediate command where terraform fails, the status SHALL be
    "terraform_failed" and applied SHALL be false.
    
    **Validates: Requirements 3.1, 3.2**
    """

    def test_run_terraform_returns_failed_status_on_error(self, monkeypatch):
        """Test that _run_terraform returns ok=False when terraform fails."""
        def mock_run(cmd, **kwargs):
            raise subprocess.CalledProcessError(
                returncode=1,
                cmd=cmd,
                output=b"Error: something went wrong",
                stderr=b"Error details"
            )

        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
        monkeypatch.setattr("subprocess.run", mock_run)

        result = _run_terraform("terraform", "/path/to/tf/dir")

        assert result["ok"] is False, "Result should indicate failure"
        assert result["exit_code"] == 1, "Exit code should be 1"

    def test_run_terraform_plan_returns_failed_status_on_error(self, monkeypatch):
        """Test that _run_terraform_plan returns ok=False when terraform fails."""
        def mock_run(cmd, **kwargs):
            raise subprocess.CalledProcessError(
                returncode=1,
                cmd=cmd,
                output=b"Error: plan failed",
                stderr=b"Error details"
            )

        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
        monkeypatch.setattr("subprocess.run", mock_run)

        result = _run_terraform_plan("terraform", "/path/to/tf/dir")

        assert result["ok"] is False, "Result should indicate failure"
        assert result["exit_code"] == 1, "Exit code should be 1"

    def test_run_terraform_returns_success_status_on_success(self, monkeypatch):
        """Test that _run_terraform returns ok=True when terraform succeeds."""
        def mock_run(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = b"Apply complete!"
            result.stderr = b""
            return result

        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
        monkeypatch.setattr("subprocess.run", mock_run)

        result = _run_terraform("terraform", "/path/to/tf/dir")

        assert result["ok"] is True, "Result should indicate success"
        assert result["exit_code"] == 0, "Exit code should be 0"

    def test_run_terraform_missing_binary_returns_failed(self, monkeypatch):
        """Test that _run_terraform returns ok=False when terraform is not found."""
        monkeypatch.setattr("shutil.which", lambda _: None)

        result = _run_terraform("terraform", "/path/to/tf/dir")

        assert result["ok"] is False, "Result should indicate failure"
        assert "not found" in result["error"], "Error should mention terraform not found"

    @given(exit_code=st.integers(min_value=1, max_value=255))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_status_accuracy_property_for_any_failure_code(self, exit_code, monkeypatch):
        """
        Property test: For any non-zero exit code from terraform, the result
        should have ok=False.
        
        **Feature: v0.1.3-bugfixes, Property 3: Remediate Status Accuracy**
        **Validates: Requirements 3.1, 3.2**
        """
        def mock_run(cmd, **kwargs):
            raise subprocess.CalledProcessError(
                returncode=exit_code,
                cmd=cmd,
                output=b"Error",
                stderr=b"Error details"
            )

        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
        monkeypatch.setattr("subprocess.run", mock_run)

        result = _run_terraform("terraform", "/path/to/tf/dir")

        assert result["ok"] is False, \
            f"Result should indicate failure for exit code {exit_code}"
        assert result["exit_code"] == exit_code, \
            f"Exit code should be {exit_code}, got {result.get('exit_code')}"


class TestApplyPlanStatusIntegration:
    """Integration tests for _apply_plan status handling."""

    def test_apply_plan_sets_terraform_failed_status_on_failure(self, tmp_path, monkeypatch):
        """Test that _apply_plan sets correct status when terraform fails."""
        from cyntrisec.cli.remediate import _apply_plan

        def mock_run(cmd, **kwargs):
            # Fail on apply command
            if "apply" in cmd:
                raise subprocess.CalledProcessError(
                    returncode=1,
                    cmd=cmd,
                    output=b"Error: apply failed",
                    stderr=b"Error details"
                )
            # Succeed on init
            result = MagicMock()
            result.returncode = 0
            result.stdout = b"Initialized"
            result.stderr = b""
            return result

        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
        monkeypatch.setattr("subprocess.run", mock_run)

        plan = [{"priority": 1, "action": "test", "description": "test", "paths_blocked": 1, "terraform": "# test"}]
        plan_path = str(tmp_path / "plan.json")
        tf_dir = str(tmp_path / "tf")
        tf_main = str(tmp_path / "tf" / "main.tf")

        items, plan_result = _apply_plan(
            plan,
            snapshot=None,
            plan_path=plan_path,
            tf_dir=tf_dir,
            tf_main_path=tf_main,
            dry_run=False,
            execute_terraform=True,
            terraform_plan=False,
            terraform_cmd="terraform",
        )

        # Verify status reflects terraform failure
        assert all(item["status"] == "terraform_failed" for item in items), \
            f"Status should be terraform_failed, got: {[item['status'] for item in items]}"
        assert all(item["terraform_result"]["ok"] is False for item in items), \
            "terraform_result should indicate failure"

    def test_apply_plan_sets_terraform_invoked_status_on_success(self, tmp_path, monkeypatch):
        """Test that _apply_plan sets correct status when terraform succeeds."""
        from cyntrisec.cli.remediate import _apply_plan

        def mock_run(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = b"Success"
            result.stderr = b""
            return result

        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
        monkeypatch.setattr("subprocess.run", mock_run)

        plan = [{"priority": 1, "action": "test", "description": "test", "paths_blocked": 1, "terraform": "# test"}]
        plan_path = str(tmp_path / "plan.json")
        tf_dir = str(tmp_path / "tf")
        tf_main = str(tmp_path / "tf" / "main.tf")

        items, plan_result = _apply_plan(
            plan,
            snapshot=None,
            plan_path=plan_path,
            tf_dir=tf_dir,
            tf_main_path=tf_main,
            dry_run=False,
            execute_terraform=True,
            terraform_plan=False,
            terraform_cmd="terraform",
        )

        # Verify status reflects terraform success
        assert all(item["status"] == "terraform_invoked" for item in items), \
            f"Status should be terraform_invoked, got: {[item['status'] for item in items]}"
        assert all(item["terraform_result"]["ok"] is True for item in items), \
            "terraform_result should indicate success"

    def test_apply_plan_dry_run_does_not_execute_terraform(self, tmp_path, monkeypatch):
        """Test that _apply_plan with dry_run=True does not execute terraform."""
        from cyntrisec.cli.remediate import _apply_plan

        terraform_called = []

        def mock_run(cmd, **kwargs):
            terraform_called.append(cmd)
            result = MagicMock()
            result.returncode = 0
            result.stdout = b"Success"
            result.stderr = b""
            return result

        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/terraform")
        monkeypatch.setattr("subprocess.run", mock_run)

        plan = [{"priority": 1, "action": "test", "description": "test", "paths_blocked": 1, "terraform": "# test"}]
        plan_path = str(tmp_path / "plan.json")
        tf_dir = str(tmp_path / "tf")
        tf_main = str(tmp_path / "tf" / "main.tf")

        items, plan_result = _apply_plan(
            plan,
            snapshot=None,
            plan_path=plan_path,
            tf_dir=tf_dir,
            tf_main_path=tf_main,
            dry_run=True,
            execute_terraform=False,
            terraform_plan=False,
            terraform_cmd="terraform",
        )

        # Verify terraform was not called
        assert len(terraform_called) == 0, "Terraform should not be called in dry_run mode"
        assert all(item["status"] == "pending_dry_run" for item in items), \
            f"Status should be pending_dry_run, got: {[item['status'] for item in items]}"
