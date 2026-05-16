"""IAM tool integration tests against moto."""

from __future__ import annotations

import json

import boto3

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.tools.iam import get_iam_role_summary
from tests.conftest import MOTO_REGION


def _trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _inline_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
        }
    )


def test_get_iam_role_summary_returns_attached_and_inline_policies(
    moto_runtime: AwsRuntime,
) -> None:
    iam = boto3.client("iam", region_name=MOTO_REGION)
    iam.create_role(RoleName="dev-summary-role", AssumeRolePolicyDocument=_trust_policy())
    managed = iam.create_policy(
        PolicyName="DevManagedPolicy",
        PolicyDocument=_inline_policy(),
    )["Policy"]
    iam.attach_role_policy(
        RoleName="dev-summary-role",
        PolicyArn=managed["Arn"],
    )
    iam.put_role_policy(
        RoleName="dev-summary-role",
        PolicyName="InlineS3Read",
        PolicyDocument=_inline_policy(),
    )

    result = get_iam_role_summary(moto_runtime, "dev-summary-role")

    assert result["role_name"] == "dev-summary-role"
    assert result["role_arn"].endswith(":role/dev-summary-role")
    assert result["attached_policy_count"] == 1
    assert result["attached_policies"][0]["policy_arn"].endswith("DevManagedPolicy")
    assert result["inline_policy_count"] == 1
    assert result["inline_policy_names"] == ["InlineS3Read"]
    assert result["trust_policy"]["service_principals"] == ["lambda.amazonaws.com"]
    # The raw trust policy document must never leak into the response.
    assert "AssumeRolePolicyDocument" not in json.dumps(result)


def test_get_iam_role_summary_accepts_role_arn(moto_runtime: AwsRuntime) -> None:
    iam = boto3.client("iam", region_name=MOTO_REGION)
    role = iam.create_role(RoleName="dev-arn-role", AssumeRolePolicyDocument=_trust_policy())[
        "Role"
    ]

    result = get_iam_role_summary(moto_runtime, role["Arn"])

    assert result["role_name"] == "dev-arn-role"
