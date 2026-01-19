"""
Unit tests for report and setup command fixes.

Tests for:
- Property 4: Report Format Inference - format inferred from file extension
- Property 5: Setup IAM Template Validity - valid HCL with external-id
- Property 6: Setup IAM Account ID Usage - account_id used in Principal

**Validates: Requirements 4.1, 4.2, 4.3, 4.4, 5.1, 5.2, 5.3, 6.1, 6.2, 6.3, 21.4, 21.5, 21.6**
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck


class TestReportFormatInference:
    """
    Property 4: Report Format Inference
    
    *For any* report command with --output path, the format SHALL be inferred
    from the file extension when --format is not specified.
    
    **Validates: Requirements 4.1, 4.2, 4.3, 4.4**
    """

    def test_infer_html_from_extension(self):
        """Test that .html extension infers html format."""
        from cyntrisec.cli.report import _infer_format_from_extension

        result = _infer_format_from_extension(Path("report.html"))
        assert result == "html"

    def test_infer_json_from_extension(self):
        """Test that .json extension infers json format."""
        from cyntrisec.cli.report import _infer_format_from_extension

        result = _infer_format_from_extension(Path("report.json"))
        assert result == "json"

    def test_infer_html_case_insensitive(self):
        """Test that .HTML extension (uppercase) infers html format."""
        from cyntrisec.cli.report import _infer_format_from_extension

        result = _infer_format_from_extension(Path("report.HTML"))
        assert result == "html"

    def test_infer_json_case_insensitive(self):
        """Test that .JSON extension (uppercase) infers json format."""
        from cyntrisec.cli.report import _infer_format_from_extension

        result = _infer_format_from_extension(Path("report.JSON"))
        assert result == "json"

    def test_infer_returns_none_for_unknown_extension(self):
        """Test that unknown extension returns None."""
        from cyntrisec.cli.report import _infer_format_from_extension

        result = _infer_format_from_extension(Path("report.txt"))
        assert result is None

    def test_infer_returns_none_for_no_extension(self):
        """Test that no extension returns None."""
        from cyntrisec.cli.report import _infer_format_from_extension

        result = _infer_format_from_extension(Path("report"))
        assert result is None

    def test_infer_with_path_components(self):
        """Test that format inference works with full paths."""
        from cyntrisec.cli.report import _infer_format_from_extension

        result = _infer_format_from_extension(Path("/path/to/output/report.html"))
        assert result == "html"

        result = _infer_format_from_extension(Path("./reports/scan-2026-01-19.json"))
        assert result == "json"

    @given(filename=st.text(min_size=1, max_size=50).filter(lambda x: x.strip() and "/" not in x))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_format_inference_property_html(self, filename):
        """
        Property test: For any filename ending with .html, format should be inferred as html.
        
        **Feature: v0.1.3-bugfixes, Property 4: Report Format Inference**
        **Validates: Requirements 4.1, 4.3**
        """
        from cyntrisec.cli.report import _infer_format_from_extension

        path = Path(f"{filename}.html")
        result = _infer_format_from_extension(path)
        assert result == "html", f"Expected 'html' for {path}, got {result}"

    @given(filename=st.text(min_size=1, max_size=50).filter(lambda x: x.strip() and "/" not in x))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_format_inference_property_json(self, filename):
        """
        Property test: For any filename ending with .json, format should be inferred as json.
        
        **Feature: v0.1.3-bugfixes, Property 4: Report Format Inference**
        **Validates: Requirements 4.2, 4.3**
        """
        from cyntrisec.cli.report import _infer_format_from_extension

        path = Path(f"{filename}.json")
        result = _infer_format_from_extension(path)
        assert result == "json", f"Expected 'json' for {path}, got {result}"


class TestSetupIamTemplateValidity:
    """
    Property 5: Setup IAM Template Validity
    
    *For any* setup iam command with --external-id, the generated Terraform
    SHALL be valid HCL with proper Condition structure.
    
    **Validates: Requirements 5.1, 5.2, 5.3**
    """

    def test_gen_terraform_without_external_id(self):
        """Test that _gen_terraform generates valid HCL without external-id."""
        from cyntrisec.cli.setup import _gen_terraform

        policy = {"Version": "2012-10-17", "Statement": []}
        result = _gen_terraform("123456789012", "TestRole", None, policy)

        # Should contain resource definition
        assert 'resource "aws_iam_role"' in result
        assert "TestRole" in result
        # Should NOT contain Condition when no external-id
        assert "Condition" not in result or "StringEquals" not in result

    def test_gen_terraform_with_external_id_has_condition(self):
        """Test that _gen_terraform includes Condition with external-id."""
        from cyntrisec.cli.setup import _gen_terraform

        policy = {"Version": "2012-10-17", "Statement": []}
        result = _gen_terraform("123456789012", "TestRole", "my-external-id", policy)

        # Should contain Condition with StringEquals
        assert "Condition" in result
        assert "StringEquals" in result
        assert "sts:ExternalId" in result
        assert "my-external-id" in result

    def test_gen_terraform_no_invalid_condition_block(self):
        """Test that _gen_terraform does NOT generate invalid 'condition { }' HCL block."""
        from cyntrisec.cli.setup import _gen_terraform

        policy = {"Version": "2012-10-17", "Statement": []}
        result = _gen_terraform("123456789012", "TestRole", "my-external-id", policy)

        # Should NOT contain HCL-style condition block (which is invalid inside jsonencode)
        # The pattern "condition {" or "condition{" would indicate invalid HCL
        assert not re.search(r'condition\s*\{', result, re.IGNORECASE), \
            "Generated Terraform should not contain 'condition { }' block inside jsonencode"

    def test_gen_terraform_uses_jsonencode(self):
        """Test that _gen_terraform uses jsonencode for assume_role_policy."""
        from cyntrisec.cli.setup import _gen_terraform

        policy = {"Version": "2012-10-17", "Statement": []}
        result = _gen_terraform("123456789012", "TestRole", "my-external-id", policy)

        # Should use jsonencode for the assume_role_policy
        assert "jsonencode(" in result

    def test_gen_terraform_condition_is_valid_json_structure(self):
        """Test that the Condition in assume_role_policy is valid JSON structure."""
        from cyntrisec.cli.setup import _gen_terraform

        policy = {"Version": "2012-10-17", "Statement": []}
        result = _gen_terraform("123456789012", "TestRole", "test-id-123", policy)

        # Extract the assume_role_policy JSON from the generated Terraform
        # The pattern is: assume_role_policy = jsonencode({...})
        match = re.search(r'assume_role_policy\s*=\s*jsonencode\((\{.*?\})\)', result, re.DOTALL)
        assert match, "Could not find assume_role_policy jsonencode block"

        # Parse the JSON to verify it's valid
        json_str = match.group(1)
        assume_policy = json.loads(json_str)

        # Verify Condition structure
        assert "Statement" in assume_policy
        assert len(assume_policy["Statement"]) > 0
        statement = assume_policy["Statement"][0]
        assert "Condition" in statement
        assert "StringEquals" in statement["Condition"]
        assert "sts:ExternalId" in statement["Condition"]["StringEquals"]
        assert statement["Condition"]["StringEquals"]["sts:ExternalId"] == "test-id-123"

    @given(external_id=st.text(min_size=1, max_size=64).filter(lambda x: x.strip() and '"' not in x and '\\' not in x))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_template_validity_property_for_any_external_id(self, external_id):
        """
        Property test: For any valid external-id, the generated Terraform should
        contain a valid Condition structure with that external-id.
        
        **Feature: v0.1.3-bugfixes, Property 5: Setup IAM Template Validity**
        **Validates: Requirements 5.1, 5.2, 5.3**
        """
        from cyntrisec.cli.setup import _gen_terraform

        policy = {"Version": "2012-10-17", "Statement": []}
        result = _gen_terraform("123456789012", "TestRole", external_id, policy)

        # Should contain Condition with the external-id
        assert "Condition" in result, f"Missing Condition for external_id={external_id}"
        assert "StringEquals" in result, f"Missing StringEquals for external_id={external_id}"
        assert "sts:ExternalId" in result, f"Missing sts:ExternalId for external_id={external_id}"

        # Should NOT contain invalid HCL condition block
        assert not re.search(r'condition\s*\{', result, re.IGNORECASE), \
            f"Invalid 'condition {{ }}' block found for external_id={external_id}"


class TestSetupIamAccountIdUsage:
    """
    Property 6: Setup IAM Account ID Usage
    
    *For any* setup iam command, the generated trust policy Principal SHALL
    use the provided account_id.
    
    **Validates: Requirements 6.1, 6.2, 6.3**
    """

    def test_gen_terraform_uses_provided_account_id(self):
        """Test that _gen_terraform uses the provided account_id in Principal."""
        from cyntrisec.cli.setup import _gen_terraform

        policy = {"Version": "2012-10-17", "Statement": []}
        result = _gen_terraform("123456789012", "TestRole", None, policy)

        # Should contain the account_id in the Principal ARN
        assert "arn:aws:iam::123456789012:root" in result

    def test_gen_terraform_does_not_use_aws_caller_identity(self):
        """Test that _gen_terraform does NOT use data.aws_caller_identity."""
        from cyntrisec.cli.setup import _gen_terraform

        policy = {"Version": "2012-10-17", "Statement": []}
        result = _gen_terraform("123456789012", "TestRole", None, policy)

        # Should NOT contain data.aws_caller_identity reference
        assert "aws_caller_identity" not in result
        assert "AWS::AccountId" not in result

    def test_gen_terraform_principal_format(self):
        """Test that Principal is in correct ARN format."""
        from cyntrisec.cli.setup import _gen_terraform

        policy = {"Version": "2012-10-17", "Statement": []}
        result = _gen_terraform("987654321098", "TestRole", None, policy)

        # Extract and verify the Principal ARN
        match = re.search(r'assume_role_policy\s*=\s*jsonencode\((\{.*?\})\)', result, re.DOTALL)
        assert match, "Could not find assume_role_policy jsonencode block"

        json_str = match.group(1)
        assume_policy = json.loads(json_str)

        statement = assume_policy["Statement"][0]
        principal = statement["Principal"]["AWS"]
        assert principal == "arn:aws:iam::987654321098:root"

    @given(account_id=st.from_regex(r'[0-9]{12}', fullmatch=True))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_account_id_usage_property_for_any_account(self, account_id):
        """
        Property test: For any valid 12-digit account_id, the generated Terraform
        should use that account_id in the trust policy Principal.
        
        **Feature: v0.1.3-bugfixes, Property 6: Setup IAM Account ID Usage**
        **Validates: Requirements 6.1, 6.2, 6.3**
        """
        from cyntrisec.cli.setup import _gen_terraform

        policy = {"Version": "2012-10-17", "Statement": []}
        result = _gen_terraform(account_id, "TestRole", None, policy)

        expected_arn = f"arn:aws:iam::{account_id}:root"
        assert expected_arn in result, \
            f"Expected Principal ARN {expected_arn} not found in generated Terraform"

        # Should NOT use data sources or intrinsic functions
        assert "aws_caller_identity" not in result, \
            "Generated Terraform should not use aws_caller_identity data source"
        assert "AWS::AccountId" not in result, \
            "Generated Terraform should not use AWS::AccountId intrinsic function"

    def test_gen_terraform_with_external_id_still_uses_account_id(self):
        """Test that account_id is used even when external-id is provided."""
        from cyntrisec.cli.setup import _gen_terraform

        policy = {"Version": "2012-10-17", "Statement": []}
        result = _gen_terraform("111222333444", "TestRole", "my-external-id", policy)

        # Should contain the account_id in the Principal ARN
        assert "arn:aws:iam::111222333444:root" in result

        # Extract and verify the full structure
        match = re.search(r'assume_role_policy\s*=\s*jsonencode\((\{.*?\})\)', result, re.DOTALL)
        assert match
        json_str = match.group(1)
        assume_policy = json.loads(json_str)

        statement = assume_policy["Statement"][0]
        # Verify Principal uses account_id
        assert statement["Principal"]["AWS"] == "arn:aws:iam::111222333444:root"
        # Verify Condition also present
        assert "Condition" in statement
        assert statement["Condition"]["StringEquals"]["sts:ExternalId"] == "my-external-id"
