"""Unit tests for AWS Credential Provider."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from cyntrisec.aws.credentials import CredentialProvider


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "err"}}, "op")


class TestDefaultSession:
    @patch("cyntrisec.aws.credentials.boto3.Session")
    def test_creates_session(self, mock_session_cls):
        provider = CredentialProvider(profile="test", region="eu-west-1")
        session = provider.default_session()

        mock_session_cls.assert_called_once_with(
            profile_name="test", region_name="eu-west-1"
        )
        assert session is mock_session_cls.return_value

    @patch("cyntrisec.aws.credentials.boto3.Session")
    def test_caches_session(self, mock_session_cls):
        provider = CredentialProvider()
        s1 = provider.default_session()
        s2 = provider.default_session()

        assert s1 is s2
        assert mock_session_cls.call_count == 1


class TestAssumeRole:
    @patch("cyntrisec.aws.credentials.boto3.Session")
    def test_happy_path(self, mock_session_cls):
        mock_base = MagicMock()
        mock_session_cls.return_value = mock_base
        mock_sts = MagicMock()
        mock_base.client.return_value = mock_sts
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIA",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": datetime(2025, 1, 1, tzinfo=timezone.utc),
            }
        }

        provider = CredentialProvider()
        session = provider.assume_role("arn:aws:iam::123:role/R")

        mock_sts.assume_role.assert_called_once()
        call_kwargs = mock_sts.assume_role.call_args[1]
        assert call_kwargs["RoleArn"] == "arn:aws:iam::123:role/R"
        assert "ExternalId" not in call_kwargs
        # Second Session call is for the assumed role
        assert mock_session_cls.call_count == 2

    @patch("cyntrisec.aws.credentials.boto3.Session")
    def test_with_external_id(self, mock_session_cls):
        mock_base = MagicMock()
        mock_session_cls.return_value = mock_base
        mock_sts = MagicMock()
        mock_base.client.return_value = mock_sts
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIA",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": datetime(2025, 1, 1, tzinfo=timezone.utc),
            }
        }

        provider = CredentialProvider()
        provider.assume_role("arn:aws:iam::123:role/R", external_id="ext-1")

        call_kwargs = mock_sts.assume_role.call_args[1]
        assert call_kwargs["ExternalId"] == "ext-1"

    @patch("cyntrisec.aws.credentials.boto3.Session")
    def test_access_denied_raises_permission_error(self, mock_session_cls):
        mock_base = MagicMock()
        mock_session_cls.return_value = mock_base
        mock_sts = MagicMock()
        mock_base.client.return_value = mock_sts
        mock_sts.assume_role.side_effect = _client_error("AccessDenied")

        provider = CredentialProvider()
        with pytest.raises(PermissionError, match="Access denied"):
            provider.assume_role("arn:aws:iam::123:role/R")

    @patch("cyntrisec.aws.credentials.boto3.Session")
    def test_other_error_re_raises(self, mock_session_cls):
        mock_base = MagicMock()
        mock_session_cls.return_value = mock_base
        mock_sts = MagicMock()
        mock_base.client.return_value = mock_sts
        mock_sts.assume_role.side_effect = _client_error("InvalidIdentityToken")

        provider = CredentialProvider()
        with pytest.raises(ClientError):
            provider.assume_role("arn:aws:iam::123:role/R")


class TestGetCallerIdentity:
    @patch("cyntrisec.aws.credentials.boto3.Session")
    def test_returns_dict(self, mock_session_cls):
        mock_base = MagicMock()
        mock_session_cls.return_value = mock_base
        mock_sts = MagicMock()
        mock_base.client.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {
            "Account": "123", "Arn": "arn:x", "UserId": "uid"
        }

        provider = CredentialProvider()
        result = provider.get_caller_identity()

        assert result["Account"] == "123"


class TestValidateRole:
    @patch("cyntrisec.aws.credentials.boto3.Session")
    def test_success_returns_true(self, mock_session_cls):
        mock_base = MagicMock()
        mock_assumed = MagicMock()

        # First call creates base, second creates assumed session
        mock_session_cls.side_effect = [mock_base, mock_assumed]

        mock_sts_base = MagicMock()
        mock_base.client.return_value = mock_sts_base
        mock_sts_base.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIA",
                "SecretAccessKey": "s",
                "SessionToken": "t",
                "Expiration": datetime(2025, 1, 1, tzinfo=timezone.utc),
            }
        }

        mock_sts_assumed = MagicMock()
        mock_assumed.client.return_value = mock_sts_assumed

        provider = CredentialProvider()
        result = provider.validate_role("arn:aws:iam::123:role/R")
        assert result is True

    @patch("cyntrisec.aws.credentials.boto3.Session")
    def test_failure_returns_false(self, mock_session_cls):
        mock_base = MagicMock()
        mock_session_cls.return_value = mock_base
        mock_sts = MagicMock()
        mock_base.client.return_value = mock_sts
        mock_sts.assume_role.side_effect = _client_error("AccessDenied")

        provider = CredentialProvider()
        result = provider.validate_role("arn:aws:iam::123:role/R")
        assert result is False
