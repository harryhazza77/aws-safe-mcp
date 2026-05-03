from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.dynamodb import dynamodb_table_summary, list_dynamodb_tables


class FakeDynamoDbClient:
    def __init__(self) -> None:
        self.last_request: dict[str, Any] | None = None

    def describe_table(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "Table": {
                "TableName": "dev-orders",
                "TableArn": "arn:aws:dynamodb:eu-west-2:123456789012:table/dev-orders",
                "TableStatus": "ACTIVE",
                "CreationDateTime": datetime(2026, 1, 1, tzinfo=UTC),
                "KeySchema": [
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
                "AttributeDefinitions": [
                    {"AttributeName": "pk", "AttributeType": "S"},
                    {"AttributeName": "sk", "AttributeType": "S"},
                ],
                "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
                "ItemCount": 42,
                "TableSizeBytes": 2048,
                "GlobalSecondaryIndexes": [
                    {
                        "IndexName": "gsi1",
                        "IndexStatus": "ACTIVE",
                        "KeySchema": [{"AttributeName": "sk", "KeyType": "HASH"}],
                        "Projection": {"ProjectionType": "ALL"},
                        "ItemCount": 40,
                        "IndexSizeBytes": 1024,
                    }
                ],
                "LocalSecondaryIndexes": [],
                "StreamSpecification": {
                    "StreamEnabled": True,
                    "StreamViewType": "NEW_AND_OLD_IMAGES",
                },
                "LatestStreamArn": (
                    "arn:aws:dynamodb:eu-west-2:123456789012:table/dev-orders/stream/1"
                ),
                "SSEDescription": {
                    "Status": "ENABLED",
                    "SSEType": "KMS",
                    "KMSMasterKeyArn": "arn:aws:kms:eu-west-2:123456789012:key/example",
                },
            }
        }

    def list_tables(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {"TableNames": ["dev-orders", "prod-orders", "dev-users"]}


class FakeRuntime:
    def __init__(self) -> None:
        self.config = AwsSafeConfig(
            allowed_account_ids=["123456789012"],
        )
        self.region = "eu-west-2"
        self.client_obj = FakeDynamoDbClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert service_name == "dynamodb"
        assert region == "eu-west-2"
        return self.client_obj


def test_dynamodb_table_summary_returns_metadata_without_scan() -> None:
    runtime = FakeRuntime()

    result = dynamodb_table_summary(runtime, "dev-orders")

    assert result["table_name"] == "dev-orders"
    assert result["billing_mode"] == "PAY_PER_REQUEST"
    assert result["item_count"] == 42
    assert result["size_bytes"] == 2048
    assert result["global_secondary_indexes"][0]["name"] == "gsi1"
    assert result["stream"]["enabled"] is True
    assert result["sse"]["type"] == "KMS"
    assert result["point_in_time_recovery"] is None
    assert runtime.client_obj.last_request == {"TableName": "dev-orders"}


def test_list_dynamodb_tables_returns_names() -> None:
    runtime = FakeRuntime()

    result = list_dynamodb_tables(runtime, name_prefix="dev-", max_results=2)

    assert result["tables"] == ["dev-orders", "dev-users"]
    assert result["count"] == 2
    assert runtime.client_obj.last_request == {"Limit": 2}


def test_dynamodb_table_summary_rejects_blank_table_name() -> None:
    with pytest.raises(ToolInputError, match="table_name is required"):
        dynamodb_table_summary(FakeRuntime(), " ")


def test_dynamodb_table_summary_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.client_obj = FailingDynamoDbClient()

    with pytest.raises(AwsToolError, match="AWS dynamodb.DescribeTable ResourceNotFoundException"):
        dynamodb_table_summary(runtime, "missing-table")


class FailingDynamoDbClient:
    def list_tables(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListTables",
        )

    def describe_table(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "missing"}},
            "DescribeTable",
        )


def test_list_dynamodb_tables_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.client_obj = FailingDynamoDbClient()

    with pytest.raises(AwsToolError, match="AWS dynamodb.ListTables AccessDeniedException"):
        list_dynamodb_tables(runtime)
