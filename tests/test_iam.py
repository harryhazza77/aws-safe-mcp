from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.iam import explain_iam_simulation_denial, get_iam_role_summary


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
                    "PermissionsBoundaryArn": ("arn:aws:iam::123456789012:policy/dev-boundary"),
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

    def simulate_principal_policy(self, **_: Any) -> dict[str, Any]:
        return {
            "EvaluationResults": [
                {
                    "EvalDecision": "explicitDeny",
                    "MatchedStatements": [
                        {
                            "SourcePolicyId": "InlineDeny",
                            "SourcePolicyType": "IAM Policy",
                            "StartPosition": {"Line": 2, "Column": 3},
                            "EndPosition": {"Line": 8, "Column": 4},
                        }
                    ],
                    "MissingContextValues": ["aws:SourceVpc"],
                }
            ]
        }


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


def test_explain_iam_simulation_denial_summarizes_explicit_deny_metadata() -> None:
    result = explain_iam_simulation_denial(
        FakeRuntime(),
        principal_arn="arn:aws:iam::123456789012:role/dev-lambda",
        action="s3:GetObject",
        resource_arn="arn:aws:s3:::dev-bucket/key",
    )

    assert result["summary"] == {
        "status": "explicit_deny",
        "decision": "explicitDeny",
        "matched_statement_count": 1,
        "missing_context_key_count": 1,
    }
    assert result["likely_policy_layer"] == "identity_or_resource_policy_explicit_deny"
    assert result["evaluation"]["matched_statements"] == [
        {
            "source_policy_id": "InlineDeny",
            "source_policy_type": "IAM Policy",
            "start_position": {"Line": 2, "Column": 3},
            "end_position": {"Line": 8, "Column": 4},
        }
    ]
    assert result["evaluation"]["missing_context_values"] == ["aws:SourceVpc"]
    assert result["uncertainty"]["raw_policy_documents_returned"] is False
    assert "Statement" not in str(result)


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
