"""Unit tests for S3 Collector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError

from cyntrisec.aws.collectors.s3 import S3Collector


def _make_collector():
    session = MagicMock(spec=boto3.Session)
    client = MagicMock()
    session.client.return_value = client
    return S3Collector(session), client


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "err"}}, "op")


class TestS3CollectorCollectAll:
    @patch("cyntrisec.aws.collectors.s3.time.sleep")
    def test_collect_all_enriches_buckets(self, mock_sleep):
        collector, client = _make_collector()
        client.list_buckets.return_value = {
            "Buckets": [{"Name": "b1"}]
        }
        client.get_bucket_policy.return_value = {"Policy": "{}"}
        client.get_bucket_acl.return_value = {"Grants": []}
        client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}
        }
        client.get_bucket_location.return_value = {"LocationConstraint": "us-west-2"}

        result = collector.collect_all()
        assert len(result["buckets"]) == 1
        bucket = result["buckets"][0]
        assert "Policy" in bucket
        assert "Acl" in bucket
        assert "PublicAccessBlock" in bucket
        assert "Location" in bucket
        mock_sleep.assert_called()

    @patch("cyntrisec.aws.collectors.s3.time.sleep")
    def test_collect_all_empty_buckets(self, mock_sleep):
        collector, client = _make_collector()
        client.list_buckets.return_value = {"Buckets": []}

        result = collector.collect_all()
        assert result["buckets"] == []


class TestS3CollectorBucketPolicy:
    def test_get_bucket_policy_happy(self):
        collector, client = _make_collector()
        client.get_bucket_policy.return_value = {"Policy": '{"v": 1}'}

        result = collector._get_bucket_policy("b1")
        assert result == {"Policy": '{"v": 1}'}

    def test_get_bucket_policy_no_such_policy(self):
        collector, client = _make_collector()
        client.get_bucket_policy.side_effect = _client_error("NoSuchBucketPolicy")

        result = collector._get_bucket_policy("b1")
        assert result is None

    def test_get_bucket_policy_other_error(self):
        collector, client = _make_collector()
        client.get_bucket_policy.side_effect = _client_error("AccessDenied")

        result = collector._get_bucket_policy("b1")
        assert "Error" in result


class TestS3CollectorAcl:
    def test_get_bucket_acl_happy(self):
        collector, client = _make_collector()
        client.get_bucket_acl.return_value = {"Grants": [], "Owner": {}}

        result = collector._get_bucket_acl("b1")
        assert result is not None
        assert "Grants" in result

    def test_get_bucket_acl_error(self):
        collector, client = _make_collector()
        client.get_bucket_acl.side_effect = _client_error("AccessDenied")

        result = collector._get_bucket_acl("b1")
        assert result is None


class TestS3CollectorPublicAccessBlock:
    def test_happy(self):
        collector, client = _make_collector()
        client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}
        }

        result = collector._get_public_access_block("b1")
        assert result == {"BlockPublicAcls": True}

    def test_error(self):
        collector, client = _make_collector()
        client.get_public_access_block.side_effect = _client_error("NoSuchPublicAccessBlockConfiguration")

        result = collector._get_public_access_block("b1")
        assert result is None


class TestS3CollectorLocation:
    def test_happy(self):
        collector, client = _make_collector()
        client.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}

        result = collector._get_bucket_location("b1")
        assert result == "eu-west-1"

    def test_none_means_us_east_1(self):
        collector, client = _make_collector()
        client.get_bucket_location.return_value = {"LocationConstraint": None}

        result = collector._get_bucket_location("b1")
        assert result == "us-east-1"

    def test_error_returns_unknown(self):
        collector, client = _make_collector()
        client.get_bucket_location.side_effect = _client_error("AccessDenied")

        result = collector._get_bucket_location("b1")
        assert result == "unknown"


class TestS3CollectorBackoff:
    @patch("cyntrisec.aws.collectors.s3.time.sleep")
    def test_success_no_retry(self, mock_sleep):
        collector, _ = _make_collector()
        func = MagicMock(return_value="ok", __name__="test_func")

        result = collector._call_with_backoff(func, "arg1")
        assert result == "ok"
        func.assert_called_once_with("arg1")
        mock_sleep.assert_not_called()

    @patch("cyntrisec.aws.collectors.s3.time.sleep")
    def test_throttling_retry(self, mock_sleep):
        collector, _ = _make_collector()
        func = MagicMock(
            side_effect=[_client_error("Throttling"), "ok"],
            __name__="test_func",
        )

        result = collector._call_with_backoff(func)
        assert result == "ok"
        assert func.call_count == 2
        mock_sleep.assert_called_once()

    @patch("cyntrisec.aws.collectors.s3.time.sleep")
    def test_slowdown_retry(self, mock_sleep):
        collector, _ = _make_collector()
        func = MagicMock(
            side_effect=[_client_error("SlowDown"), "ok"],
            __name__="test_func",
        )

        result = collector._call_with_backoff(func)
        assert result == "ok"
        assert func.call_count == 2

    @patch("cyntrisec.aws.collectors.s3.time.sleep")
    def test_max_retries_raises(self, mock_sleep):
        collector, _ = _make_collector()
        err = _client_error("Throttling")
        func = MagicMock(side_effect=[err, err, err], __name__="test_func")

        import pytest

        with pytest.raises(ClientError):
            collector._call_with_backoff(func)
        assert func.call_count == 3

    @patch("cyntrisec.aws.collectors.s3.time.sleep")
    def test_non_throttle_error_raises_immediately(self, mock_sleep):
        collector, _ = _make_collector()
        func = MagicMock(side_effect=_client_error("AccessDenied"), __name__="test_func")

        import pytest

        with pytest.raises(ClientError):
            collector._call_with_backoff(func)
        assert func.call_count == 1
        mock_sleep.assert_not_called()
