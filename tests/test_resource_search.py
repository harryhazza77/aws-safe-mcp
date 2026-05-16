from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import ToolInputError
from aws_safe_mcp.tools import resource_search
from aws_safe_mcp.tools.resource_search import (
    build_log_signal_correlation_timeline,
    diagnose_region_partition_mismatches,
    export_application_dependency_graph,
    get_cross_service_incident_brief,
    get_risk_scored_dependency_health_summary,
    plan_end_to_end_transaction_trace,
    search_aws_resources,
    search_aws_resources_by_tag,
)


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


def test_get_cross_service_incident_brief_composes_existing_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_search(*_: Any, **__: Any) -> dict[str, Any]:
        return {
            "count": 1,
            "results": [{"service": "lambda", "name": "dev-api", "summary": {}}],
            "warnings": [],
        }

    def fake_alarms(*_: Any, **__: Any) -> dict[str, Any]:
        return {
            "alarms": [
                {
                    "alarm_name": "dev-api-errors",
                    "namespace": "AWS/Lambda",
                    "metric_name": "Errors",
                    "inferred_resources": [{"name": "dev-api"}],
                }
            ]
        }

    def fake_errors(*_: Any, **__: Any) -> dict[str, Any]:
        return {"count": 1, "groups": [{"fingerprint": "ERROR", "count": 1}]}

    def fake_dependencies(*_: Any, **__: Any) -> dict[str, Any]:
        return {"graph_summary": {"edge_count": 1}, "edges": [{"relationship": "writes_logs_to"}]}

    monkeypatch.setattr(resource_search, "search_aws_resources", fake_search)
    monkeypatch.setattr(resource_search, "list_cloudwatch_alarms", fake_alarms)
    monkeypatch.setattr(resource_search, "get_lambda_recent_errors", fake_errors)
    monkeypatch.setattr(resource_search, "explain_lambda_dependencies", fake_dependencies)

    result = get_cross_service_incident_brief(FakeRuntime(), "dev-api")

    assert result["matching_resources"]["count"] == 1
    assert result["alarm_matches"][0]["alarm_name"] == "dev-api-errors"
    assert result["lambda_context"][0]["recent_error_count"] == 1
    assert result["lambda_context"][0]["dependency_summary"] == {"edge_count": 1}
    assert any("CloudWatch alarms" in check for check in result["suggested_next_checks"])


def test_build_log_signal_correlation_timeline_orders_alarm_and_lambda_signals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_brief(*_: Any, **__: Any) -> dict[str, Any]:
        return {
            "alarm_matches": [
                {
                    "alarm_name": "dev-api-errors",
                    "namespace": "AWS/Lambda",
                    "metric_name": "Errors",
                    "state_value": "ALARM",
                    "inferred_resources": [{"name": "dev-api"}],
                }
            ],
            "lambda_context": [
                {
                    "function_name": "dev-api",
                    "recent_error_count": 2,
                    "recent_error_groups": [{"fingerprint": "ERROR", "count": 2}],
                }
            ],
            "warnings": [],
        }

    monkeypatch.setattr(resource_search, "get_cross_service_incident_brief", fake_brief)

    result = build_log_signal_correlation_timeline(FakeRuntime(), "dev-api")

    assert result["summary"] == {
        "symptom_count": 2,
        "likely_first_failure_point": "cloudwatch_alarm",
        "status": "signals_found",
    }
    assert result["timeline"][0]["name"] == "dev-api-errors"
    assert result["timeline"][1]["source"] == "lambda_logs"


def test_export_application_dependency_graph_uses_discovered_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_search(*_: Any, **__: Any) -> dict[str, Any]:
        return {
            "results": [{"service": "lambda", "name": "dev-api", "arn": "lambda-arn"}],
            "warnings": [],
        }

    def fake_dependencies(*_: Any, **__: Any) -> dict[str, Any]:
        return {"edges": [{"source": "lambda-arn", "target": "log-group"}]}

    monkeypatch.setattr(resource_search, "search_aws_resources", fake_search)
    monkeypatch.setattr(resource_search, "explain_lambda_dependencies", fake_dependencies)

    result = export_application_dependency_graph(FakeRuntime(), "dev")

    assert result["summary"] == {"node_count": 1, "edge_count": 1, "unresolved_count": 0}
    assert result["nodes"][0]["id"] == "lambda-arn"
    assert result["edges"][0]["target"] == "log-group"


def test_plan_end_to_end_transaction_trace_orders_probable_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_brief(*_: Any, **__: Any) -> dict[str, Any]:
        return {
            "matching_resources": {
                "results": [
                    {"service": "lambda", "name": "dev-handler"},
                    {"service": "apigateway", "name": "dev-api"},
                    {"service": "sqs", "name": "dev-queue"},
                ]
            },
            "alarm_matches": {"count": 1},
        }

    monkeypatch.setattr(resource_search, "get_cross_service_incident_brief", fake_brief)

    result = plan_end_to_end_transaction_trace(FakeRuntime(), "dev")

    assert [step["service"] for step in result["trace_plan"]] == [
        "apigateway",
        "lambda",
        "sqs",
    ]
    assert result["probable_breakpoints"][0] == {
        "stage": "cloudwatch",
        "reason": "matching alarms exist",
    }


def test_get_risk_scored_dependency_health_summary_scores_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_search(*_: Any, **__: Any) -> dict[str, Any]:
        return {
            "results": [
                {"service": "lambda", "name": "dev-handler"},
                {"service": "s3", "name": "dev-bucket"},
            ],
            "warnings": [],
        }

    monkeypatch.setattr(resource_search, "search_aws_resources", fake_search)

    result = get_risk_scored_dependency_health_summary(FakeRuntime(), "dev")

    assert result["resource_count"] == 2
    assert result["resources"][0]["score"] == 50
    assert result["average_risk_score"] == 25


def test_get_cross_service_incident_brief_rejects_empty_query() -> None:
    with pytest.raises(ToolInputError, match="query is required"):
        get_cross_service_incident_brief(FakeRuntime(), " ")


def test_diagnose_region_partition_mismatches_flags_arn_and_url_drift() -> None:
    result = diagnose_region_partition_mismatches(
        FakeRuntime(),
        resource_refs=[
            "arn:aws:lambda:eu-west-2:123456789012:function:dev-api",
            "arn:aws:sqs:us-east-1:123456789012:dev-queue",
            "https://sqs.us-east-1.amazonaws.com/123456789012/dev-queue",
            "dev-table",
        ],
    )

    assert result["expected_region"] == "eu-west-2"
    assert result["expected_partition"] == "aws"
    assert result["mismatch_count"] == 2
    assert result["unknown_count"] == 1
    assert result["summary"]["status"] == "mismatch"
    assert result["findings"][1]["mismatches"] == [
        {"field": "region", "expected": "eu-west-2", "observed": "us-east-1"}
    ]
    assert result["findings"][2]["kind"] == "url"


def test_diagnose_region_partition_mismatches_checks_endpoint_overrides() -> None:
    result = diagnose_region_partition_mismatches(
        EndpointRuntime(),
        resource_refs=["arn:aws-cn:s3:::dev-bucket"],
        expected_region="cn-north-1",
        expected_partition="aws-cn",
    )

    assert result["mismatch_count"] == 1
    assert result["findings"][0]["status"] == "ok"
    assert result["findings"][1]["source"] == "config_endpoint"
    assert result["findings"][1]["mismatches"] == [
        {"field": "partition", "expected": "aws-cn", "observed": "aws"}
    ]


def test_diagnose_region_partition_mismatches_rejects_blank_refs() -> None:
    with pytest.raises(ToolInputError, match="resource_refs must not contain blank values"):
        diagnose_region_partition_mismatches(FakeRuntime(), [" "])


class StatefulTagRuntime(FakeRuntime):
    def __init__(self) -> None:
        self.tagging_client = FakeTaggingClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        if service_name == "resourcegroupstaggingapi":
            assert region == "eu-west-2"
            return self.tagging_client
        return super().client(service_name, region=region)


class EndpointRuntime(FakeRuntime):
    config = AwsSafeConfig(
        allowed_account_ids=["123456789012"],
        service_endpoint_urls={"sqs": "https://sqs.cn-north-1.amazonaws.com"},
    )
    region = "cn-north-1"


class FailingTaggingClient:
    def get_resources(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetResources",
        )
