from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import ToolInputError
from aws_safe_mcp.tools.resource_search import search_aws_resources, search_aws_resources_by_tag


class FakePaginator:
    def paginate(self, **_: Any) -> list[dict[str, Any]]:
        return [{"Functions": [{"FunctionName": "dev-api"}]}]


class FakeLambdaClient:
    def get_paginator(self, operation_name: str) -> FakePaginator:
        assert operation_name == "list_functions"
        return FakePaginator()


class FakeStepFunctionsClient:
    def get_paginator(self, operation_name: str) -> Any:
        assert operation_name == "list_state_machines"

        class Paginator:
            def paginate(self, **_: Any) -> list[dict[str, Any]]:
                return [{"stateMachines": [{"name": "dev-flow", "stateMachineArn": "arn"}]}]

        return Paginator()


class FakeS3Client:
    def list_buckets(self) -> dict[str, Any]:
        return {
            "Buckets": [{"Name": "dev-bucket", "CreationDate": datetime(2026, 1, 1, tzinfo=UTC)}]
        }


class FakeDynamoDbClient:
    def list_tables(self, **_: Any) -> dict[str, Any]:
        return {"TableNames": ["dev-table"]}


class FakeLogsClient:
    def describe_log_groups(self, **_: Any) -> dict[str, Any]:
        return {"logGroups": [{"logGroupName": "/aws/lambda/dev-api"}]}


class FakeRestApiClient:
    def get_rest_apis(self, **_: Any) -> dict[str, Any]:
        return {"items": [{"id": "rest1", "name": "dev-rest"}]}


class FakeHttpApiClient:
    def get_apis(self, **_: Any) -> dict[str, Any]:
        return {"Items": [{"ApiId": "http1", "Name": "dev-http", "ProtocolType": "HTTP"}]}


class FakeEventsClient:
    def list_event_buses(self, **_: Any) -> dict[str, Any]:
        return {"EventBuses": [{"Name": "default"}]}

    def list_rules(self, **_: Any) -> dict[str, Any]:
        return {
            "Rules": [
                {
                    "Name": "dev-rule",
                    "Arn": "arn:aws:events:eu-west-2:123456789012:rule/dev-rule",
                    "State": "ENABLED",
                }
            ]
        }

    def list_targets_by_rule(self, **_: Any) -> dict[str, Any]:
        return {"Targets": []}


class FakeTaggingClient:
    def __init__(self) -> None:
        self.last_request: dict[str, Any] | None = None

    def get_resources(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:lambda:eu-west-2:123456789012:function:dev-api",
                    "Tags": [{"Key": "Environment", "Value": "dev"}],
                },
                {
                    "ResourceARN": "arn:aws:sqs:eu-west-2:123456789012:dev-queue",
                    "Tags": [{"Key": "Environment", "Value": "dev"}],
                },
            ],
            "PaginationToken": "",
        }


class FakeRuntime:
    config = AwsSafeConfig(allowed_account_ids=["123456789012"])
    region = "eu-west-2"

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert region == "eu-west-2"
        if service_name == "lambda":
            return FakeLambdaClient()
        if service_name == "stepfunctions":
            return FakeStepFunctionsClient()
        if service_name == "s3":
            return FakeS3Client()
        if service_name == "dynamodb":
            return FakeDynamoDbClient()
        if service_name == "logs":
            return FakeLogsClient()
        if service_name == "apigateway":
            return FakeRestApiClient()
        if service_name == "apigatewayv2":
            return FakeHttpApiClient()
        if service_name == "events":
            return FakeEventsClient()
        if service_name == "resourcegroupstaggingapi":
            return FakeTaggingClient()
        raise AssertionError(service_name)


def test_search_aws_resources_searches_selected_services() -> None:
    result = search_aws_resources(
        FakeRuntime(),
        query="api",
        services=["lambda"],
        max_results=10,
    )

    assert result["count"] == 1
    assert result["results"][0]["service"] == "lambda"
    assert result["results"][0]["name"] == "dev-api"


def test_search_aws_resources_searches_all_supported_services() -> None:
    result = search_aws_resources(FakeRuntime(), query="dev", max_results=20)

    assert {item["service"] for item in result["results"]} == {
        "apigateway",
        "cloudwatch",
        "dynamodb",
        "eventbridge",
        "lambda",
        "s3",
        "stepfunctions",
    }


def test_search_aws_resources_rejects_unknown_services() -> None:
    with pytest.raises(ToolInputError, match="unsupported services"):
        search_aws_resources(FakeRuntime(), query="dev", services=["ec2"])


def test_search_aws_resources_by_tag_groups_tagged_resources() -> None:
    runtime = StatefulTagRuntime()

    result = search_aws_resources_by_tag(
        runtime,
        tag_key="Environment",
        tag_value="dev",
        max_results=10,
    )

    assert result["count"] == 2
    assert result["summary"]["by_service"] == {"lambda": 1, "sqs": 1}
    assert result["summary"]["by_resource_type"] == {"function": 1, "unknown": 1}
    assert result["resources"][0]["name"] == "dev-api"
    assert result["resources"][0]["tags"] == [{"key": "Environment", "value": "dev"}]
    assert runtime.tagging_client.last_request == {
        "ResourcesPerPage": 10,
        "TagFilters": [{"Key": "Environment", "Values": ["dev"]}],
    }


def test_search_aws_resources_by_tag_rejects_empty_key() -> None:
    with pytest.raises(ToolInputError, match="tag_key is required"):
        search_aws_resources_by_tag(FakeRuntime(), tag_key=" ")


def test_search_aws_resources_by_tag_reports_tagging_api_warning() -> None:
    runtime = StatefulTagRuntime()
    runtime.tagging_client = FailingTaggingClient()

    result = search_aws_resources_by_tag(runtime, tag_key="Environment")

    assert result["count"] == 0
    assert result["warnings"]


class StatefulTagRuntime(FakeRuntime):
    def __init__(self) -> None:
        self.tagging_client = FakeTaggingClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        if service_name == "resourcegroupstaggingapi":
            assert region == "eu-west-2"
            return self.tagging_client
        return super().client(service_name, region=region)


class FailingTaggingClient:
    def get_resources(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetResources",
        )
