"""Lambda tool integration tests against moto.

These exercise the real boto3 client shapes (capitalization, pagination
tokens, ARN formats) rather than hand-rolled fakes. Hand-rolled fakes
can silently drift from AWS reality; moto pins us to the schema the
SDK actually returns.

Scope is intentionally narrow: one happy-path test per public Lambda
tool we depend on, asserting only the contractual fields. Unit tests
still cover error branches and redaction behavior.
"""

from __future__ import annotations

import io
import json
import zipfile

import boto3

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.tools.lambda_tools import (
    explain_lambda_dependencies,
    get_lambda_alias_version_summary,
    get_lambda_event_source_mapping_diagnostics,
    get_lambda_summary,
    list_lambda_functions,
)
from tests.conftest import MOTO_ACCOUNT_ID, MOTO_REGION


def _zip_handler() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return {}\n")
    return buffer.getvalue()


def _create_role(name: str) -> str:
    iam = boto3.client("iam", region_name=MOTO_REGION)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    response = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    return str(response["Role"]["Arn"])


def _create_lambda(name: str, role_arn: str, env: dict[str, str] | None = None) -> str:
    client = boto3.client("lambda", region_name=MOTO_REGION)
    response = client.create_function(
        FunctionName=name,
        Runtime="python3.11",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_handler()},
        Timeout=30,
        MemorySize=256,
        Environment={"Variables": env or {}},
    )
    return str(response["FunctionArn"])


def test_list_lambda_functions_returns_real_shape(moto_runtime: AwsRuntime) -> None:
    role_arn = _create_role("dev-lambda-role")
    _create_lambda("dev-api", role_arn)
    _create_lambda("dev-worker", role_arn)
    _create_lambda("prod-api", role_arn)

    result = list_lambda_functions(moto_runtime, name_prefix="dev-")

    assert result["region"] == MOTO_REGION
    names = sorted(item["function_name"] for item in result["functions"])
    assert names == ["dev-api", "dev-worker"]
    assert all(item["runtime"] == "python3.11" for item in result["functions"])
    assert all(item["memory_mb"] == 256 for item in result["functions"])


def test_get_lambda_summary_returns_environment_keys_only(moto_runtime: AwsRuntime) -> None:
    role_arn = _create_role("dev-summary-role")
    _create_lambda(
        "dev-summary",
        role_arn,
        env={"DATABASE_URL": "postgres://x", "API_KEY": "secret-must-not-leak"},
    )

    result = get_lambda_summary(moto_runtime, "dev-summary")

    assert result["function_name"] == "dev-summary"
    assert result["runtime"] == "python3.11"
    assert result["memory_mb"] == 256
    assert result["timeout_seconds"] == 30
    assert sorted(result["environment_variable_keys"]) == ["API_KEY", "DATABASE_URL"]
    # Never leak values, even when explicitly named *_KEY.
    assert "secret-must-not-leak" not in json.dumps(result)
    assert "postgres://x" not in json.dumps(result)


def test_get_lambda_alias_version_summary_against_real_aliases(
    moto_runtime: AwsRuntime,
) -> None:
    role_arn = _create_role("dev-alias-role")
    _create_lambda("dev-aliased", role_arn)
    client = boto3.client("lambda", region_name=MOTO_REGION)
    v1 = client.publish_version(FunctionName="dev-aliased")["Version"]
    client.create_alias(FunctionName="dev-aliased", Name="live", FunctionVersion=v1)

    result = get_lambda_alias_version_summary(moto_runtime, "dev-aliased")

    assert result["function_name"] == "dev-aliased"
    assert result["summary"]["alias_count"] == 1
    assert result["aliases"][0]["name"] == "live"
    assert result["aliases"][0]["function_version"] == v1


def test_get_lambda_event_source_mapping_diagnostics_against_real_mapping(
    moto_runtime: AwsRuntime,
) -> None:
    role_arn = _create_role("dev-esm-role")
    _create_lambda("dev-consumer", role_arn)
    sqs = boto3.client("sqs", region_name=MOTO_REGION)
    queue_url = sqs.create_queue(QueueName="dev-source")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    lambda_client = boto3.client("lambda", region_name=MOTO_REGION)
    lambda_client.create_event_source_mapping(
        EventSourceArn=queue_arn,
        FunctionName="dev-consumer",
        BatchSize=5,
    )

    # Disable permission checks: moto does not implement
    # simulate_principal_policy. Unit tests cover the simulation path.
    result = get_lambda_event_source_mapping_diagnostics(
        moto_runtime, "dev-consumer", include_permission_checks=False
    )

    assert result["function_name"] == "dev-consumer"
    assert result["summary"]["mapping_count"] == 1
    mapping = result["mappings"][0]
    assert mapping["event_source_arn"] == queue_arn
    assert mapping["batch_size"] == 5


def test_explain_lambda_dependencies_includes_log_group_edge(
    moto_runtime: AwsRuntime,
) -> None:
    role_arn = _create_role("dev-deps-role")
    _create_lambda("dev-deps", role_arn)

    result = explain_lambda_dependencies(moto_runtime, "dev-deps", include_permission_checks=False)

    assert result["function_name"] == "dev-deps"
    assert result["region"] == MOTO_REGION
    assert result["nodes"]["log_group"]["name"] == "/aws/lambda/dev-deps"
    # Execution role edge must be present regardless of IAM simulation outcome.
    assert any(edge["relationship"] == "uses_execution_role" for edge in result["edges"])
    assert any(edge["relationship"] == "writes_logs_to" for edge in result["edges"])
    assert f"arn:aws:iam::{MOTO_ACCOUNT_ID}:role/dev-deps-role" in result["nodes"][
        "execution_role"
    ].get("role_arn", "")
