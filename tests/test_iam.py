from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.iam import get_iam_role_summary


class FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages

    def paginate(self, **_: Any) -> list[dict[str, Any]]:
        return self.pages


class FakeIamClient:
    def get_role(self, RoleName: str) -> dict[str, Any]:
        assert RoleName == "dev-lambda"
        return {
            "Role": {
                "RoleName": "dev-lambda",
                "Arn": "arn:aws:iam::123456789012:role/dev-lambda",
                "Path": "/service/",
                "CreateDate": datetime(2026, 1, 1, tzinfo=UTC),
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Action": "sts:AssumeRole",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                        }
                    ]
                },
                "PermissionsBoundary": {
                    "PermissionsBoundaryType": "Policy",
                    "PermissionsBoundaryArn": (
                        "arn:aws:iam::123456789012:policy/dev-boundary"
                    ),
                },
            }
        }

    def get_paginator(self, operation_name: str) -> FakePaginator:
        if operation_name == "list_attached_role_policies":
            return FakePaginator(
                [
                    {
                        "AttachedPolicies": [
                            {
                                "PolicyName": "AWSLambdaBasicExecutionRole",
                                "PolicyArn": (
                                    "arn:aws:iam::aws:policy/service-role/"
                                    "AWSLambdaBasicExecutionRole"
                                ),
                            }
                        ]
                    }
                ]
            )
        if operation_name == "list_role_policies":
            return FakePaginator([{"PolicyNames": ["InlineDynamoAccess"]}])
        raise AssertionError(operation_name)


class FakeRuntime:
    config = AwsSafeConfig(allowed_account_ids=["123456789012"])
    region = "eu-west-2"

    def __init__(self) -> None:
        self.iam_client = FakeIamClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert service_name == "iam"
        assert region == "eu-west-2"
        return self.iam_client


def test_get_iam_role_summary_returns_safe_role_shape() -> None:
    result = get_iam_role_summary(FakeRuntime(), "dev-lambda")

    assert result["role_name"] == "dev-lambda"
    assert result["path"] == "/service/"
    assert result["trust_policy"] == {
        "statement_count": 1,
        "actions": ["sts:AssumeRole"],
        "service_principals": ["lambda.amazonaws.com"],
        "aws_principals": [],
        "federated_principals": [],
    }
    assert result["attached_policy_count"] == 1
    assert result["inline_policy_names"] == ["InlineDynamoAccess"]
    assert result["permissions_boundary"]["present"] is True
    assert "AssumeRolePolicyDocument" not in str(result)


def test_get_iam_role_summary_accepts_role_arn() -> None:
    result = get_iam_role_summary(
        FakeRuntime(),
        "arn:aws:iam::123456789012:role/service/dev-lambda",
    )

    assert result["role_name"] == "dev-lambda"


def test_get_iam_role_summary_rejects_invalid_inputs() -> None:
    with pytest.raises(ToolInputError, match="role_name is required"):
        get_iam_role_summary(FakeRuntime(), " ")
    with pytest.raises(ToolInputError, match="IAM role ARN"):
        get_iam_role_summary(FakeRuntime(), "arn:aws:iam::123456789012:user/dev")


def test_get_iam_role_summary_normalizes_get_role_errors() -> None:
    runtime = FakeRuntime()
    runtime.iam_client = FailingGetRoleIamClient()

    with pytest.raises(AwsToolError, match="AWS iam.GetRole AccessDenied"):
        get_iam_role_summary(runtime, "dev-lambda")


def test_get_iam_role_summary_keeps_policy_listing_warnings() -> None:
    runtime = FakeRuntime()
    runtime.iam_client = FailingPolicyListIamClient()

    result = get_iam_role_summary(runtime, "dev-lambda")

    assert result["attached_policy_count"] == 0
    assert result["inline_policy_count"] == 0
    assert len(result["warnings"]) == 2


class FailingGetRoleIamClient(FakeIamClient):
    def get_role(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetRole",
        )


class FailingPolicyListIamClient(FakeIamClient):
    def get_paginator(self, operation_name: str) -> FakePaginator:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": f"{operation_name} denied"}},
            operation_name,
        )
