"""JSON schema contract tests for MCP tool outputs.

Pins the shape MCP clients depend on. Accidental field renames or type
changes fail loudly here rather than silently in the wild.

Scope: a curated set of high-traffic tools (identity, list+summary tools
for each major service, the cross-service `search_aws_resources`). Each
schema is intentionally narrow — it pins **what callers consume**, not
every internal field — so harmless internal additions stay non-breaking.

Outputs are exercised against moto-mocked AWS so the schemas describe
real boto3 shapes, not hand-rolled fakes.
"""

from __future__ import annotations

import io
import json
import zipfile

import boto3
from jsonschema import Draft202012Validator

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.tools.dynamodb import get_dynamodb_table_summary, list_dynamodb_tables
from aws_safe_mcp.tools.iam import get_iam_role_summary
from aws_safe_mcp.tools.identity import get_aws_auth_status, get_aws_identity
from aws_safe_mcp.tools.lambda_tools import get_lambda_summary, list_lambda_functions
from aws_safe_mcp.tools.resource_search import search_aws_resources
from aws_safe_mcp.tools.sqs import get_sqs_queue_summary, list_sqs_queues
from tests.conftest import MOTO_REGION


def _zip_handler() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("index.py", "def handler(event, context): return {}\n")
    return buffer.getvalue()


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


def _validate(schema: dict, instance: object) -> None:
    """Validate `instance` against `schema` using a Draft 2020-12 validator."""
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(instance)


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------


IDENTITY_SCHEMA: dict = {
    "type": "object",
    "required": ["account", "arn", "user_id", "region", "readonly"],
    "properties": {
        "account": {"type": "string"},
        "arn": {"type": "string"},
        "user_id": {"type": "string"},
        "profile": {"type": ["string", "null"]},
        "region": {"type": "string"},
        "readonly": {"type": "boolean"},
    },
}


AUTH_STATUS_SCHEMA: dict = {
    "type": "object",
    "required": ["authenticated", "account", "arn", "region", "readonly"],
    "properties": {
        "authenticated": {"type": "boolean"},
        "account": {"type": ["string", "null"]},
        "arn": {"type": ["string", "null"]},
        "principal_type": {"type": ["string", "null"]},
        "principal_name": {"type": ["string", "null"]},
        "session_name": {"type": ["string", "null"]},
        "profile": {"type": ["string", "null"]},
        "region": {"type": ["string", "null"]},
        "readonly": {"type": "boolean"},
        "message": {"type": ["string", "null"]},
    },
}


def test_get_aws_identity_contract(moto_runtime: AwsRuntime) -> None:
    _validate(IDENTITY_SCHEMA, get_aws_identity(moto_runtime))


def test_get_aws_auth_status_contract(moto_runtime: AwsRuntime) -> None:
    _validate(AUTH_STATUS_SCHEMA, get_aws_auth_status(moto_runtime))


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------


LAMBDA_LIST_SCHEMA: dict = {
    "type": "object",
    "required": ["region", "count", "functions"],
    "properties": {
        "region": {"type": "string"},
        "count": {"type": "integer", "minimum": 0},
        "functions": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["function_name", "runtime"],
                "properties": {
                    "function_name": {"type": "string"},
                    "runtime": {"type": ["string", "null"]},
                    "memory_mb": {"type": ["integer", "null"]},
                    "timeout_seconds": {"type": ["integer", "null"]},
                    "role_arn": {"type": ["string", "null"]},
                },
            },
        },
    },
}


LAMBDA_SUMMARY_SCHEMA: dict = {
    "type": "object",
    "required": [
        "function_name",
        "function_arn",
        "runtime",
        "region",
        "environment_variable_keys",
        "vpc",
        "dead_letter",
    ],
    "properties": {
        "function_name": {"type": "string"},
        "function_arn": {"type": "string"},
        "runtime": {"type": ["string", "null"]},
        "region": {"type": "string"},
        "environment_variable_keys": {
            "type": "array",
            "items": {"type": "string"},
        },
        "vpc": {"type": "object"},
        "dead_letter": {"type": "object"},
    },
}


def _seed_lambda(name: str) -> None:
    iam = boto3.client("iam", region_name=MOTO_REGION)
    role = iam.create_role(RoleName=f"{name}-role", AssumeRolePolicyDocument=_trust_policy())[
        "Role"
    ]
    boto3.client("lambda", region_name=MOTO_REGION).create_function(
        FunctionName=name,
        Runtime="python3.11",
        Role=role["Arn"],
        Handler="index.handler",
        Code={"ZipFile": _zip_handler()},
    )


def test_list_lambda_functions_contract(moto_runtime: AwsRuntime) -> None:
    _seed_lambda("dev-contract")

    _validate(LAMBDA_LIST_SCHEMA, list_lambda_functions(moto_runtime))


def test_get_lambda_summary_contract(moto_runtime: AwsRuntime) -> None:
    _seed_lambda("dev-summary-contract")

    _validate(LAMBDA_SUMMARY_SCHEMA, get_lambda_summary(moto_runtime, "dev-summary-contract"))


# ---------------------------------------------------------------------------
# SQS
# ---------------------------------------------------------------------------


SQS_LIST_SCHEMA: dict = {
    "type": "object",
    "required": ["region", "count", "queues"],
    "properties": {
        "region": {"type": "string"},
        "count": {"type": "integer", "minimum": 0},
        "queues": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["queue_name", "queue_url"],
                "properties": {
                    "queue_name": {"type": "string"},
                    "queue_url": {"type": "string"},
                },
            },
        },
    },
}


SQS_SUMMARY_SCHEMA: dict = {
    "type": "object",
    "required": [
        "queue_name",
        "queue_url",
        "queue_arn",
        "region",
        "fifo",
        "message_counts",
        "dead_letter",
    ],
    "properties": {
        "queue_name": {"type": "string"},
        "queue_url": {"type": "string"},
        "queue_arn": {"type": "string"},
        "region": {"type": "string"},
        "fifo": {"type": "boolean"},
        "message_counts": {"type": "object"},
        "dead_letter": {"type": "object"},
    },
}


def test_list_sqs_queues_contract(moto_runtime: AwsRuntime) -> None:
    boto3.client("sqs", region_name=MOTO_REGION).create_queue(QueueName="dev-contract-queue")

    _validate(SQS_LIST_SCHEMA, list_sqs_queues(moto_runtime))


def test_get_sqs_queue_summary_contract(moto_runtime: AwsRuntime) -> None:
    url = boto3.client("sqs", region_name=MOTO_REGION).create_queue(QueueName="dev-summary-queue")[
        "QueueUrl"
    ]

    _validate(SQS_SUMMARY_SCHEMA, get_sqs_queue_summary(moto_runtime, url))


# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------


DYNAMODB_LIST_SCHEMA: dict = {
    "type": "object",
    "required": ["region", "count", "tables"],
    "properties": {
        "region": {"type": "string"},
        "count": {"type": "integer", "minimum": 0},
        "tables": {"type": "array", "items": {"type": "string"}},
    },
}


DYNAMODB_SUMMARY_SCHEMA: dict = {
    "type": "object",
    "required": ["table_name", "region", "billing_mode"],
    "properties": {
        "table_name": {"type": "string"},
        "region": {"type": "string"},
        "billing_mode": {"type": ["string", "null"]},
    },
}


def test_list_dynamodb_tables_contract(moto_runtime: AwsRuntime) -> None:
    boto3.client("dynamodb", region_name=MOTO_REGION).create_table(
        TableName="dev-contract-table",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    _validate(DYNAMODB_LIST_SCHEMA, list_dynamodb_tables(moto_runtime))


def test_get_dynamodb_table_summary_contract(moto_runtime: AwsRuntime) -> None:
    boto3.client("dynamodb", region_name=MOTO_REGION).create_table(
        TableName="dev-table-summary",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    _validate(
        DYNAMODB_SUMMARY_SCHEMA, get_dynamodb_table_summary(moto_runtime, "dev-table-summary")
    )


# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------


IAM_ROLE_SUMMARY_SCHEMA: dict = {
    "type": "object",
    "required": [
        "role_name",
        "role_arn",
        "trust_policy",
        "attached_policy_count",
        "inline_policy_count",
    ],
    "properties": {
        "role_name": {"type": "string"},
        "role_arn": {"type": "string"},
        "trust_policy": {"type": "object"},
        "attached_policy_count": {"type": "integer", "minimum": 0},
        "inline_policy_count": {"type": "integer", "minimum": 0},
    },
}


def test_get_iam_role_summary_contract(moto_runtime: AwsRuntime) -> None:
    boto3.client("iam", region_name=MOTO_REGION).create_role(
        RoleName="dev-contract-role", AssumeRolePolicyDocument=_trust_policy()
    )

    _validate(IAM_ROLE_SUMMARY_SCHEMA, get_iam_role_summary(moto_runtime, "dev-contract-role"))


# ---------------------------------------------------------------------------
# Cross-service: search_aws_resources
# ---------------------------------------------------------------------------


SEARCH_AWS_SCHEMA: dict = {
    "type": "object",
    "required": ["query", "services", "region", "count", "results", "warnings"],
    "properties": {
        "query": {"type": "string"},
        "services": {"type": "array", "items": {"type": "string"}},
        "region": {"type": "string"},
        "count": {"type": "integer", "minimum": 0},
        "results": {"type": "array"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
}


def test_search_aws_resources_contract(moto_runtime: AwsRuntime) -> None:
    # Seed at least one match so the result list is non-trivial.
    _seed_lambda("dev-search-match")

    _validate(SEARCH_AWS_SCHEMA, search_aws_resources(moto_runtime, "dev-search-match"))
