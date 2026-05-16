from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.kms import check_kms_dependent_path, get_kms_key_summary, list_kms_keys


class FakeKmsClient:
    def __init__(self) -> None:
        self.describe_requests: list[str] = []

    def list_keys(self, **_: Any) -> dict[str, Any]:
        return {
            "Keys": [
                {
                    "KeyId": "key-1",
                    "KeyArn": "arn:aws:kms:eu-west-2:123456789012:key/key-1",
                }
            ],
            "Truncated": False,
        }

    def describe_key(self, KeyId: str) -> dict[str, Any]:
        self.describe_requests.append(KeyId)
        return {
            "KeyMetadata": {
                "KeyId": KeyId,
                "Arn": f"arn:aws:kms:eu-west-2:123456789012:key/{KeyId}",
                "Description": "app encryption key",
                "Enabled": True,
                "KeyState": "Enabled",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyManager": "CUSTOMER",
                "Origin": "AWS_KMS",
                "CreationDate": datetime(2026, 1, 1, tzinfo=UTC),
                "MultiRegion": False,
            }
        }

    def get_key_rotation_status(self, KeyId: str) -> dict[str, Any]:
        assert KeyId == "key-1"
        return {"KeyRotationEnabled": True}

    def list_aliases(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs["KeyId"] == "key-1"
        return {
            "Aliases": [
                {
                    "AliasName": "alias/dev-key",
                    "AliasArn": "arn:aws:kms:eu-west-2:123456789012:alias/dev-key",
                    "TargetKeyId": "key-1",
                }
            ]
        }

    def list_key_policies(self, KeyId: str, **_: Any) -> dict[str, Any]:
        assert KeyId == "key-1"
        return {"PolicyNames": ["default"]}

    def get_key_policy(self, KeyId: str, PolicyName: str) -> dict[str, Any]:
        assert KeyId == "key-1"
        assert PolicyName == "default"
        return {
            "Policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "sqs.amazonaws.com"},
                        "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
                        "Resource": "*",
                    }
                ]
            }
        }


class FakeIamClient:
    def simulate_principal_policy(self, **_: Any) -> dict[str, Any]:
        return {"EvaluationResults": [{"EvalDecision": "allowed"}]}


class FakeRuntime:
    config = AwsSafeConfig(allowed_account_ids=["123456789012"])
    region = "eu-west-2"

    def __init__(self) -> None:
        self.kms_client = FakeKmsClient()
        self.iam_client = FakeIamClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        if service_name == "kms":
            assert region == "eu-west-2"
            return self.kms_client
        if service_name == "iam":
            return self.iam_client
        raise AssertionError(f"unexpected service {service_name}")


def test_list_kms_keys_returns_metadata_inventory() -> None:
    runtime = FakeRuntime()

    result = list_kms_keys(runtime)

    assert result["count"] == 1
    assert result["summary"] == {
        "key_count": 1,
        "by_state": {"Enabled": 1},
        "by_usage": {"ENCRYPT_DECRYPT": 1},
    }
    assert result["keys"][0]["key_id"] == "key-1"
    assert result["keys"][0]["key_manager"] == "CUSTOMER"


def test_get_kms_key_summary_returns_alias_rotation_and_policy_names() -> None:
    result = get_kms_key_summary(FakeRuntime(), "key-1")

    assert result["metadata"]["key_state"] == "Enabled"
    assert result["rotation"] == {"available": True, "enabled": True}
    assert result["aliases"][0]["alias_name"] == "alias/dev-key"
    assert result["policy"] == {
        "available": True,
        "policy_name_count": 1,
        "policy_names": ["default"],
    }
    assert "Policy" not in str(result)


def test_get_kms_key_summary_rejects_empty_key_id() -> None:
    with pytest.raises(ToolInputError, match="key_id is required"):
        get_kms_key_summary(FakeRuntime(), " ")


def test_list_kms_keys_normalizes_list_errors() -> None:
    runtime = FakeRuntime()
    runtime.kms_client = FailingListKmsClient()

    with pytest.raises(AwsToolError, match="AWS kms.ListKeys AccessDenied"):
        list_kms_keys(runtime)


def test_get_kms_key_summary_keeps_optional_warnings() -> None:
    runtime = FakeRuntime()
    runtime.kms_client = OptionalFailureKmsClient()

    result = get_kms_key_summary(runtime, "key-1")

    assert result["metadata"]["key_id"] == "key-1"
    assert result["rotation"] == {"available": False, "enabled": None}
    assert result["aliases"] == []
    assert result["policy"]["policy_name_count"] == 0
    assert len(result["warnings"]) == 3


def test_check_kms_dependent_path_checks_role_and_service_principal() -> None:
    result = check_kms_dependent_path(
        FakeRuntime(),
        "key-1",
        "arn:aws:iam::123456789012:role/app-role",
        service_principal="sqs.amazonaws.com",
    )

    assert result["path_summary"] == {
        "key_usable": True,
        "role_has_required_actions": True,
        "service_principal_has_data_key_access": True,
        "likely_usable": True,
    }
    assert len(result["role_permission_checks"]) == 3
    assert result["service_principal_check"]["allowed_actions"] == [
        "kms:Decrypt",
        "kms:GenerateDataKey",
    ]
    assert "Statement" not in str(result)


def test_check_kms_dependent_path_rejects_bad_role_arn() -> None:
    with pytest.raises(ToolInputError, match="role_arn must be an IAM role ARN"):
        check_kms_dependent_path(FakeRuntime(), "key-1", "not-a-role")


class FailingListKmsClient(FakeKmsClient):
    def list_keys(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "ListKeys",
        )


class OptionalFailureKmsClient(FakeKmsClient):
    def get_key_rotation_status(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetKeyRotationStatus",
        )

    def list_aliases(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "ListAliases",
        )

    def list_key_policies(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "ListKeyPolicies",
        )
