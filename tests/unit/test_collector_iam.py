"""Unit tests for IAM Collector."""

from __future__ import annotations

from unittest.mock import MagicMock

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cyntrisec.aws.collectors.iam import IamCollector


def _make_collector():
    session = MagicMock(spec=boto3.Session)
    client = MagicMock()
    session.client.return_value = client
    return IamCollector(session), client


def _client_error(code: str = "AccessDenied") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "err"}}, "op")


class TestIamCollectorCollectAll:
    def test_collect_all_returns_four_keys(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [{}]

        result = collector.collect_all()
        assert set(result.keys()) == {"users", "roles", "policies", "instance_profiles"}

    def test_collect_users_pagination(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"Users": [{"UserName": "u1"}]},
            {"Users": [{"UserName": "u2"}]},
        ]

        result = collector._collect_users()
        assert len(result) == 2

    def test_collect_policies_local_scope(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"Policies": [{"PolicyName": "p1"}]}
        ]

        result = collector._collect_policies()
        assert len(result) == 1
        pag.paginate.assert_called_with(Scope="Local")

    def test_collect_instance_profiles(self):
        collector, client = _make_collector()
        pag = MagicMock()
        client.get_paginator.return_value = pag
        pag.paginate.return_value = [
            {"InstanceProfiles": [{"InstanceProfileName": "ip1"}]}
        ]

        result = collector._collect_instance_profiles()
        assert len(result) == 1


class TestIamCollectorRoles:
    def test_collect_roles_enriches_with_policies(self):
        collector, client = _make_collector()
        # list_roles paginator
        roles_pag = MagicMock()
        roles_pag.paginate.return_value = [
            {"Roles": [{"RoleName": "role1"}]}
        ]
        # inline policies paginator (empty)
        inline_pag = MagicMock()
        inline_pag.paginate.return_value = [{"PolicyNames": []}]
        # attached policies paginator (empty)
        attached_pag = MagicMock()
        attached_pag.paginate.return_value = [{"AttachedPolicies": []}]

        def get_paginator(name):
            if name == "list_roles":
                return roles_pag
            if name == "list_role_policies":
                return inline_pag
            if name == "list_attached_role_policies":
                return attached_pag
            return MagicMock()

        client.get_paginator.side_effect = get_paginator

        result = collector._collect_roles()
        assert len(result) == 1
        assert "InlinePolicies" in result[0]
        assert "AttachedPolicies" in result[0]

    def test_role_without_rolename_skips_enrichment(self):
        collector, client = _make_collector()
        pag = MagicMock()
        pag.paginate.return_value = [{"Roles": [{"Arn": "arn:aws:iam::123:role/x"}]}]
        client.get_paginator.return_value = pag

        result = collector._collect_roles()
        assert len(result) == 1
        assert "InlinePolicies" not in result[0]


class TestIamCollectorInlinePolicies:
    def test_inline_policies_happy_path(self):
        collector, client = _make_collector()
        pag = MagicMock()
        pag.paginate.return_value = [{"PolicyNames": ["pol1"]}]
        client.get_paginator.return_value = pag
        client.get_role_policy.return_value = {
            "PolicyDocument": {"Statement": []}
        }

        result = collector._collect_inline_role_policies("role1")
        assert len(result) == 1
        assert result[0]["PolicyName"] == "pol1"
        assert result[0]["Document"] == {"Statement": []}

    def test_inline_policies_client_error_skips(self):
        collector, client = _make_collector()
        pag = MagicMock()
        pag.paginate.return_value = [{"PolicyNames": ["pol1"]}]
        client.get_paginator.return_value = pag
        client.get_role_policy.side_effect = _client_error()

        result = collector._collect_inline_role_policies("role1")
        assert result == []

    def test_inline_policies_botocore_error_skips(self):
        collector, client = _make_collector()
        pag = MagicMock()
        pag.paginate.return_value = [{"PolicyNames": ["pol1"]}]
        client.get_paginator.return_value = pag
        client.get_role_policy.side_effect = BotoCoreError()

        result = collector._collect_inline_role_policies("role1")
        assert result == []


class TestIamCollectorAttachedPolicies:
    def test_attached_policies_happy_path(self):
        collector, client = _make_collector()
        pag = MagicMock()
        pag.paginate.return_value = [
            {"AttachedPolicies": [{"PolicyName": "ap1", "PolicyArn": "arn:aws:iam::123:policy/ap1"}]}
        ]
        client.get_paginator.return_value = pag
        client.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        client.get_policy_version.return_value = {
            "PolicyVersion": {"Document": {"Statement": []}}
        }

        result = collector._collect_attached_role_policies("role1")
        assert len(result) == 1
        assert result[0]["PolicyArn"] == "arn:aws:iam::123:policy/ap1"

    def test_attached_policies_no_arn_skips(self):
        collector, client = _make_collector()
        pag = MagicMock()
        pag.paginate.return_value = [
            {"AttachedPolicies": [{"PolicyName": "ap1"}]}
        ]
        client.get_paginator.return_value = pag

        result = collector._collect_attached_role_policies("role1")
        assert result == []


class TestIamCollectorManagedPolicyDocument:
    def test_managed_policy_happy_path(self):
        collector, client = _make_collector()
        client.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        client.get_policy_version.return_value = {
            "PolicyVersion": {"Document": {"Statement": []}}
        }

        result = collector._get_managed_policy_document("arn:aws:iam::123:policy/p1")
        assert result == {"Statement": []}

    def test_managed_policy_no_version_id(self):
        collector, client = _make_collector()
        client.get_policy.return_value = {"Policy": {}}

        result = collector._get_managed_policy_document("arn:aws:iam::123:policy/p1")
        assert result is None

    def test_managed_policy_client_error(self):
        collector, client = _make_collector()
        client.get_policy.side_effect = _client_error()

        result = collector._get_managed_policy_document("arn:aws:iam::123:policy/p1")
        assert result is None

    def test_managed_policy_non_dict_returns_empty(self):
        collector, client = _make_collector()
        client.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        client.get_policy_version.return_value = {
            "PolicyVersion": {"Document": "not-a-dict"}
        }

        result = collector._get_managed_policy_document("arn:aws:iam::123:policy/p1")
        assert result == {}
