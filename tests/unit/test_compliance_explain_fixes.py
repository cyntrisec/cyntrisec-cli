"""
Unit tests for compliance and explain command fixes.

Tests for:
- Property 7: Compliance Finding Mapping - findings map to controls
- Property 8: Explain Finding Coverage - explain covers all finding types
- Markdown output is valid markdown

**Validates: Requirements 8.1, 8.2, 8.3, 8.4, 9.1, 9.2, 9.3, 9.4, 12.1, 12.2, 12.3, 21.8, 21.9**
"""

from __future__ import annotations

import uuid
from io import StringIO

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

from cyntrisec.core.compliance import (
    FINDING_TO_CONTROLS,
    ComplianceChecker,
    Framework,
)
from cyntrisec.core.schema import Finding, FindingSeverity
from cyntrisec.cli.explain import FINDING_EXPLANATIONS


class TestComplianceFindingMapping:
    """
    Property 7: Compliance Finding Mapping
    
    *For any* scan with findings, the comply command SHALL map those findings
    to relevant controls and reflect them in the compliance score.
    
    **Validates: Requirements 8.1, 8.2, 8.3, 8.4**
    """

    def test_s3_bucket_partial_public_access_block_maps_to_cis_controls(self):
        """
        Test that s3-bucket-partial-public-access-block finding maps to CIS controls.
        
        **Validates: Requirements 8.1**
        """
        finding_type = "s3-bucket-partial-public-access-block"
        assert finding_type in FINDING_TO_CONTROLS, \
            f"Finding type '{finding_type}' should be in FINDING_TO_CONTROLS"
        
        controls = FINDING_TO_CONTROLS[finding_type]
        # Should map to CIS-AWS:2.1.1 and CIS-AWS:2.1.5
        assert any("CIS-AWS:2.1.1" in c for c in controls), \
            f"Finding '{finding_type}' should map to CIS-AWS:2.1.1"
        assert any("CIS-AWS:2.1.5" in c for c in controls), \
            f"Finding '{finding_type}' should map to CIS-AWS:2.1.5"

    def test_ec2_public_ip_maps_to_cis_controls(self):
        """
        Test that ec2-public-ip finding maps to CIS controls.
        
        **Validates: Requirements 8.2**
        """
        finding_type = "ec2-public-ip"
        assert finding_type in FINDING_TO_CONTROLS, \
            f"Finding type '{finding_type}' should be in FINDING_TO_CONTROLS"
        
        controls = FINDING_TO_CONTROLS[finding_type]
        # Should map to CIS-AWS:5.1 and CIS-AWS:5.2
        assert any("CIS-AWS:5.1" in c for c in controls), \
            f"Finding '{finding_type}' should map to CIS-AWS:5.1"
        assert any("CIS-AWS:5.2" in c for c in controls), \
            f"Finding '{finding_type}' should map to CIS-AWS:5.2"

    def test_security_group_open_to_world_maps_to_cis_controls(self):
        """
        Test that security-group-open-to-world finding maps to CIS controls.
        
        **Validates: Requirements 8.3**
        """
        finding_type = "security-group-open-to-world"
        assert finding_type in FINDING_TO_CONTROLS, \
            f"Finding type '{finding_type}' should be in FINDING_TO_CONTROLS"
        
        controls = FINDING_TO_CONTROLS[finding_type]
        # Should map to CIS-AWS:5.1 and CIS-AWS:5.2
        assert any("CIS-AWS:5.1" in c for c in controls), \
            f"Finding '{finding_type}' should map to CIS-AWS:5.1"
        assert any("CIS-AWS:5.2" in c for c in controls), \
            f"Finding '{finding_type}' should map to CIS-AWS:5.2"

    def test_compliance_checker_marks_controls_as_failing_for_findings(self):
        """
        Test that ComplianceChecker marks controls as failing when findings exist.
        
        **Validates: Requirements 8.4**
        """
        checker = ComplianceChecker()
        snapshot_id = uuid.uuid4()
        asset_id = uuid.uuid4()
        
        # Create a finding that maps to CIS controls
        finding = Finding(
            snapshot_id=snapshot_id,
            asset_id=asset_id,
            finding_type="s3-bucket-partial-public-access-block",
            severity=FindingSeverity.high,
            title="S3 Bucket Missing Public Access Block",
        )
        
        report = checker.check([finding], [], framework=Framework.CIS_AWS)
        
        # Find the control that should be failing
        failing_controls = [r for r in report.results if r.status == "fail"]
        failing_control_ids = [r.control.full_id for r in failing_controls]
        
        # At least one of the mapped controls should be failing
        expected_controls = FINDING_TO_CONTROLS["s3-bucket-partial-public-access-block"]
        assert any(ctrl_id in failing_control_ids for ctrl_id in expected_controls), \
            f"Expected at least one of {expected_controls} to be failing, got {failing_control_ids}"

    def test_compliance_score_reflects_findings(self):
        """
        Test that compliance score reflects the ratio of passing to total controls.
        
        **Validates: Requirements 8.4**
        """
        checker = ComplianceChecker()
        snapshot_id = uuid.uuid4()
        asset_id = uuid.uuid4()
        
        # Test with no findings - should have 100% compliance
        report_no_findings = checker.check([], [], framework=Framework.CIS_AWS)
        assert report_no_findings.compliance_score == 1.0, \
            "Compliance score should be 100% with no findings"
        
        # Test with findings - should have less than 100% compliance
        finding = Finding(
            snapshot_id=snapshot_id,
            asset_id=asset_id,
            finding_type="security-group-open-to-world",
            severity=FindingSeverity.high,
            title="Security Group Open to World",
        )
        
        report_with_findings = checker.check([finding], [], framework=Framework.CIS_AWS)
        assert report_with_findings.compliance_score < 1.0, \
            "Compliance score should be less than 100% with findings"
        assert report_with_findings.failing > 0, \
            "Should have at least one failing control"

    @given(finding_type=st.sampled_from(list(FINDING_TO_CONTROLS.keys())))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_all_mapped_findings_cause_control_failures(self, finding_type):
        """
        Property test: For any finding type in FINDING_TO_CONTROLS, creating a finding
        of that type should cause at least one control to fail.
        
        **Feature: v0.1.3-bugfixes, Property 7: Compliance Finding Mapping**
        **Validates: Requirements 8.1, 8.2, 8.3, 8.4**
        """
        checker = ComplianceChecker()
        snapshot_id = uuid.uuid4()
        asset_id = uuid.uuid4()
        
        finding = Finding(
            snapshot_id=snapshot_id,
            asset_id=asset_id,
            finding_type=finding_type,
            severity=FindingSeverity.high,
            title=f"Test finding: {finding_type}",
        )
        
        # Check against both frameworks to ensure mapping works
        for framework in [Framework.CIS_AWS, Framework.SOC2]:
            report = checker.check([finding], [], framework=framework)
            expected_controls = FINDING_TO_CONTROLS[finding_type]
            
            # Filter to controls that belong to this framework
            framework_controls = [c for c in expected_controls if c.startswith(framework.value)]
            
            if framework_controls:
                failing_control_ids = [r.control.full_id for r in report.results if r.status == "fail"]
                assert any(ctrl_id in failing_control_ids for ctrl_id in framework_controls), \
                    f"Finding '{finding_type}' should cause at least one of {framework_controls} to fail in {framework.value}"


class TestExplainFindingCoverage:
    """
    Property 8: Explain Finding Coverage
    
    *For any* finding type produced by scan, the explain command SHALL provide
    an explanation.
    
    **Validates: Requirements 9.1, 9.2, 9.3, 9.4**
    """

    def test_s3_bucket_partial_public_access_block_has_explanation(self):
        """
        Test that s3-bucket-partial-public-access-block has an explanation.
        
        **Validates: Requirements 9.1**
        """
        finding_type = "s3-bucket-partial-public-access-block"
        assert finding_type in FINDING_EXPLANATIONS, \
            f"Finding type '{finding_type}' should have an explanation"
        
        explanation = FINDING_EXPLANATIONS[finding_type]
        assert "title" in explanation
        assert "severity" in explanation
        assert "what" in explanation
        assert "why" in explanation
        assert "fix" in explanation

    def test_ec2_public_ip_has_explanation(self):
        """
        Test that ec2-public-ip has an explanation.
        
        **Validates: Requirements 9.2**
        """
        finding_type = "ec2-public-ip"
        assert finding_type in FINDING_EXPLANATIONS, \
            f"Finding type '{finding_type}' should have an explanation"
        
        explanation = FINDING_EXPLANATIONS[finding_type]
        assert "title" in explanation
        assert "severity" in explanation
        assert "what" in explanation
        assert "why" in explanation
        assert "fix" in explanation

    def test_security_group_open_to_world_has_explanation(self):
        """
        Test that security-group-open-to-world has an explanation.
        
        **Validates: Requirements 9.3**
        """
        finding_type = "security-group-open-to-world"
        assert finding_type in FINDING_EXPLANATIONS, \
            f"Finding type '{finding_type}' should have an explanation"
        
        explanation = FINDING_EXPLANATIONS[finding_type]
        assert "title" in explanation
        assert "severity" in explanation
        assert "what" in explanation
        assert "why" in explanation
        assert "fix" in explanation

    def test_all_compliance_mapped_findings_have_explanations(self):
        """
        Test that all finding types in FINDING_TO_CONTROLS have explanations.
        
        This ensures consistency between compliance mappings and explanations.
        """
        # Key finding types that should have explanations
        key_finding_types = [
            "s3-bucket-partial-public-access-block",
            "ec2-public-ip",
            "security-group-open-to-world",
        ]
        
        for finding_type in key_finding_types:
            assert finding_type in FINDING_EXPLANATIONS, \
                f"Finding type '{finding_type}' should have an explanation"

    def test_explanation_structure_is_complete(self):
        """
        Test that all explanations have the required fields.
        """
        required_fields = ["title", "severity", "what", "why", "fix"]
        
        for finding_type, explanation in FINDING_EXPLANATIONS.items():
            for field in required_fields:
                assert field in explanation, \
                    f"Explanation for '{finding_type}' missing required field '{field}'"
                assert explanation[field], \
                    f"Explanation for '{finding_type}' has empty '{field}' field"

    @given(finding_type=st.sampled_from([
        "s3-bucket-partial-public-access-block",
        "ec2-public-ip", 
        "security-group-open-to-world",
        "s3-bucket-public-access-block",
        "security_group_open_to_world",
        "s3_public_bucket",
        "iam_overly_permissive_trust",
    ]))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_explain_coverage_property(self, finding_type):
        """
        Property test: For any common finding type, an explanation should exist
        with all required fields populated.
        
        **Feature: v0.1.3-bugfixes, Property 8: Explain Finding Coverage**
        **Validates: Requirements 9.1, 9.2, 9.3, 9.4**
        """
        assert finding_type in FINDING_EXPLANATIONS, \
            f"Finding type '{finding_type}' should have an explanation"
        
        explanation = FINDING_EXPLANATIONS[finding_type]
        required_fields = ["title", "severity", "what", "why", "fix"]
        
        for field in required_fields:
            assert field in explanation, \
                f"Explanation for '{finding_type}' missing required field '{field}'"
            assert explanation[field], \
                f"Explanation for '{finding_type}' has empty '{field}' field"


class TestExplainMarkdownOutput:
    """
    Test that explain --format markdown outputs valid Markdown.
    
    **Validates: Requirements 12.1, 12.2, 12.3**
    """

    def test_explain_finding_markdown_format(self, capsys):
        """
        Test that explain finding outputs valid Markdown syntax.
        
        **Validates: Requirements 12.1, 12.2**
        """
        from cyntrisec.cli.explain import _explain_finding
        
        _explain_finding("security-group-open-to-world", "markdown")
        
        captured = capsys.readouterr()
        output = captured.out
        
        # Should contain Markdown headers
        assert "# " in output, "Markdown output should contain headers"
        
        # Should contain the title
        assert "Security Group Open to World" in output
        
        # Should contain section headers
        assert "## What is it?" in output or "**Severity:**" in output
        
        # Should NOT contain Rich panel characters
        assert "╭" not in output, "Markdown output should not contain Rich panel characters"
        assert "╰" not in output, "Markdown output should not contain Rich panel characters"
        assert "│" not in output, "Markdown output should not contain Rich panel characters"

    def test_explain_path_markdown_format(self, capsys):
        """
        Test that explain path outputs valid Markdown syntax.
        
        **Validates: Requirements 12.1, 12.2**
        """
        from cyntrisec.cli.explain import _explain_path
        
        _explain_path("instance-compromise", "markdown")
        
        captured = capsys.readouterr()
        output = captured.out
        
        # Should contain Markdown headers
        assert "# " in output, "Markdown output should contain headers"
        
        # Should contain the title
        assert "Instance Compromise" in output
        
        # Should NOT contain Rich panel characters
        assert "╭" not in output, "Markdown output should not contain Rich panel characters"
        assert "╰" not in output, "Markdown output should not contain Rich panel characters"

    def test_explain_control_markdown_format(self, capsys):
        """
        Test that explain control outputs valid Markdown syntax.
        
        **Validates: Requirements 12.1, 12.2**
        """
        from cyntrisec.cli.explain import _explain_control
        
        _explain_control("CIS-AWS:5.1", "markdown")
        
        captured = capsys.readouterr()
        output = captured.out
        
        # Should contain Markdown headers
        assert "# " in output, "Markdown output should contain headers"
        
        # Should contain the control ID
        assert "CIS-AWS:5.1" in output
        
        # Should NOT contain Rich panel characters
        assert "╭" not in output, "Markdown output should not contain Rich panel characters"
        assert "╰" not in output, "Markdown output should not contain Rich panel characters"

    def test_markdown_uses_proper_syntax(self, capsys):
        """
        Test that Markdown output uses proper syntax elements.
        
        **Validates: Requirements 12.3**
        """
        from cyntrisec.cli.explain import _explain_finding
        
        _explain_finding("ec2-public-ip", "markdown")
        
        captured = capsys.readouterr()
        output = captured.out
        
        # Should use # for headers
        assert output.count("#") >= 1, "Should use # for headers"
        
        # Should use ** for bold (severity)
        assert "**" in output, "Should use ** for bold text"

    @given(finding_type=st.sampled_from(list(FINDING_EXPLANATIONS.keys())))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_markdown_output_property_no_rich_panels(self, finding_type, capsys):
        """
        Property test: For any finding type, markdown output should not contain
        Rich panel characters.
        
        **Validates: Requirements 12.2**
        """
        from cyntrisec.cli.explain import _explain_finding
        
        _explain_finding(finding_type, "markdown")
        
        captured = capsys.readouterr()
        output = captured.out
        
        # Rich panel characters that should NOT appear
        rich_chars = ["╭", "╰", "╮", "╯", "│", "─", "┌", "┐", "└", "┘"]
        
        for char in rich_chars:
            assert char not in output, \
                f"Markdown output for '{finding_type}' should not contain Rich character '{char}'"
