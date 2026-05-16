from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.cloudwatch import (
    cloudwatch_log_search,
    cloudwatch_logs_insights_query,
    get_cloudwatch_alarm_summary,
    list_cloudwatch_alarms,
    list_cloudwatch_log_groups,
)


class FakeLogsClient:
    def __init__(self) -> None:
        self.last_request: dict[str, Any] | None = None

    def filter_log_events(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "events": [
                {
                    "timestamp": 1_767_225_600_000,
                    "logStreamName": "stream-a",
                    "message": "ERROR something happened token=must-not-leak\nwith details "
                    + ("x" * 200),
                },
                {
                    "timestamp": 1_767_225_660_000,
                    "logStreamName": "stream-b",
                    "message": "ERROR another thing",
                },
            ]
        }

    def describe_log_groups(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "logGroups": [
                {
                    "logGroupName": "/aws/lambda/dev-api",
                    "arn": "arn:aws:logs:eu-west-2:123456789012:log-group:/aws/lambda/dev-api",
                    "creationTime": 1_767_225_600_000,
                    "retentionInDays": 14,
                    "storedBytes": 1234,
                }
            ]
        }

    def start_query(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {"queryId": "query-1"}

    def get_query_results(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "status": "Complete",
            "results": [
                [
                    {"field": "@timestamp", "value": "2026-01-01T00:00:00.000Z"},
                    {"field": "@message", "value": "ERROR token=must-not-leak"},
                    {"field": "@ptr", "value": "opaque-pointer"},
                ],
                [
                    {"field": "@timestamp", "value": "2026-01-01T00:01:00.000Z"},
                    {"field": "count", "value": "2"},
                ],
            ],
            "statistics": {
                "recordsMatched": 2.0,
                "recordsScanned": 10.0,
                "bytesScanned": 1000.0,
            },
        }


class FakeCloudWatchClient:
    def __init__(self) -> None:
        self.last_request: dict[str, Any] | None = None

    def describe_alarms(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        alarms = [
            {
                "AlarmName": "dev-api-errors",
                "AlarmArn": "arn:aws:cloudwatch:eu-west-2:123456789012:alarm:dev-api-errors",
                "StateValue": "ALARM",
                "StateUpdatedTimestamp": "2026-01-01T00:00:00+00:00",
                "ActionsEnabled": True,
                "AlarmActions": ["arn:aws:sns:eu-west-2:123456789012:ops"],
                "Namespace": "AWS/Lambda",
                "MetricName": "Errors",
                "Dimensions": [{"Name": "FunctionName", "Value": "dev-api"}],
                "Statistic": "Sum",
                "Period": 60,
                "EvaluationPeriods": 2,
                "DatapointsToAlarm": 2,
                "Threshold": 1.0,
                "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                "TreatMissingData": "notBreaching",
            },
            {
                "AlarmName": "dev-queue-depth",
                "AlarmArn": "arn:aws:cloudwatch:eu-west-2:123456789012:alarm:dev-queue-depth",
                "StateValue": "OK",
                "ActionsEnabled": False,
                "Namespace": "AWS/SQS",
                "MetricName": "ApproximateNumberOfMessagesVisible",
                "Dimensions": [{"Name": "QueueName", "Value": "dev-queue"}],
                "Statistic": "Average",
                "Period": 300,
                "EvaluationPeriods": 1,
                "Threshold": 10.0,
                "ComparisonOperator": "GreaterThanThreshold",
            },
        ]
        if "AlarmNames" in kwargs:
            names = set(kwargs["AlarmNames"])
            alarms = [alarm for alarm in alarms if alarm["AlarmName"] in names]
        return {
            "MetricAlarms": alarms,
            "CompositeAlarms": [
                {
                    "AlarmName": "dev-composite",
                    "AlarmArn": "arn:aws:cloudwatch:eu-west-2:123456789012:alarm:dev-composite",
                    "StateValue": "OK",
                    "ActionsEnabled": True,
                    "AlarmRule": 'ALARM("dev-api-errors")',
                }
            ]
            if "AlarmNames" not in kwargs
            else [],
        }


class FakeRuntime:
    def __init__(self) -> None:
        self.config = AwsSafeConfig(
            allowed_account_ids=["123456789012"],
            redaction={"max_string_length": 120},
            max_since_minutes=120,
            max_results=100,
        )
        self.region = "eu-west-2"
        self.logs_client = FakeLogsClient()
        self.cloudwatch_client = FakeCloudWatchClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert region == "eu-west-2"
        if service_name == "logs":
            return self.logs_client
        if service_name == "cloudwatch":
            return self.cloudwatch_client
        raise AssertionError(f"Unexpected service {service_name}")


def test_cloudwatch_log_search_returns_truncated_bounded_events() -> None:
    runtime = FakeRuntime()

    result = cloudwatch_log_search(
        runtime,
        "/aws/lambda/dev-api",
        query="ERROR",
        since_minutes=999,
        max_results=1,
    )

    assert result["count"] == 1
    assert result["window_minutes"] == 120
    assert result["events"][0]["timestamp"] == "2026-01-01T00:00:00+00:00"
    assert "chars omitted" in result["events"][0]["message"]
    assert "must-not-leak" not in result["events"][0]["message"]
    assert "token=[REDACTED]" in result["events"][0]["message"]
    assert result["events"][0]["truncated"] is True
    assert result["groups"][0]["count"] == 1
    assert result["groups"][0]["sample_message"] == result["events"][0]["message"]
    assert runtime.logs_client.last_request is not None
    assert runtime.logs_client.last_request["logGroupName"] == "/aws/lambda/dev-api"
    assert runtime.logs_client.last_request["filterPattern"] == "ERROR"
    assert runtime.logs_client.last_request["limit"] == 1


def test_cloudwatch_logs_insights_query_returns_redacted_bounded_rows() -> None:
    runtime = FakeRuntime()

    result = cloudwatch_logs_insights_query(
        runtime,
        "/aws/lambda/dev-api",
        "fields @timestamp, @message | filter @message like /ERROR/",
        since_minutes=999,
        max_results=1,
    )

    assert result["query_id"] == "query-1"
    assert result["status"] == "Complete"
    assert result["window_minutes"] == 120
    assert result["count"] == 1
    assert result["results"] == [
        {
            "@timestamp": "2026-01-01T00:00:00.000Z",
            "@message": "ERROR token=[REDACTED]",
        }
    ]
    assert "must-not-leak" not in str(result)
    assert result["statistics"]["records_matched"] == 2.0


def test_list_cloudwatch_log_groups_returns_metadata() -> None:
    runtime = FakeRuntime()

    result = list_cloudwatch_log_groups(runtime, name_prefix="/aws/lambda/dev", max_results=5)

    assert result["count"] == 1
    assert result["log_groups"][0]["log_group_name"] == "/aws/lambda/dev-api"
    assert result["log_groups"][0]["creation_time"] == "2026-01-01T00:00:00+00:00"
    assert runtime.logs_client.last_request is not None
    assert runtime.logs_client.last_request["logGroupNamePrefix"] == "/aws/lambda/dev"


def test_list_cloudwatch_alarms_returns_linked_resource_hints() -> None:
    runtime = FakeRuntime()

    result = list_cloudwatch_alarms(runtime, name_prefix="dev", max_results=5)

    assert result["count"] == 3
    assert result["summary"]["by_state"] == {"ALARM": 1, "OK": 2}
    assert result["summary"]["by_linked_service"] == {"lambda": 1, "sqs": 1}
    lambda_alarm = result["alarms"][0]
    assert lambda_alarm["alarm_name"] == "dev-api-errors"
    assert lambda_alarm["namespace"] == "AWS/Lambda"
    assert lambda_alarm["dimensions"] == [{"name": "FunctionName", "value": "dev-api"}]
    assert lambda_alarm["inferred_resources"] == [
        {"service": "lambda", "resource_type": "lambda_function", "name": "dev-api"}
    ]
    assert lambda_alarm["alarm_action_count"] == 1
    assert runtime.cloudwatch_client.last_request is not None
    assert runtime.cloudwatch_client.last_request["AlarmNamePrefix"] == "dev"


def test_get_cloudwatch_alarm_summary_returns_one_alarm() -> None:
    runtime = FakeRuntime()

    result = get_cloudwatch_alarm_summary(runtime, "dev-api-errors")

    assert result["found"] is True
    assert result["alarm"]["alarm_name"] == "dev-api-errors"
    assert result["alarm"]["state_value"] == "ALARM"
    assert result["alarm"]["inferred_resources"][0]["service"] == "lambda"
    assert runtime.cloudwatch_client.last_request == {"AlarmNames": ["dev-api-errors"]}


def test_cloudwatch_log_search_follows_next_token_until_limit() -> None:
    runtime = FakeRuntime()
    runtime.logs_client = PaginatedLogsClient()

    result = cloudwatch_log_search(
        runtime,
        "/aws/lambda/dev-api",
        query="ERROR",
        max_results=2,
    )

    assert result["count"] == 2
    assert len(result["groups"]) == 2
    assert runtime.logs_client.requests[1]["nextToken"] == "page-2"
    assert runtime.logs_client.requests[0]["limit"] == 2
    assert runtime.logs_client.requests[1]["limit"] == 1


def test_cloudwatch_log_search_rejects_empty_query() -> None:
    with pytest.raises(ToolInputError, match="query is required"):
        cloudwatch_log_search(FakeRuntime(), "/aws/lambda/dev-api", query=" ")


def test_cloudwatch_logs_insights_query_rejects_broad_or_unmasked_queries() -> None:
    with pytest.raises(ToolInputError, match="provided log_group_name"):
        cloudwatch_logs_insights_query(FakeRuntime(), "/aws/lambda/dev-api", query="SOURCE '*'")
    with pytest.raises(ToolInputError, match="must not use unmask"):
        cloudwatch_logs_insights_query(FakeRuntime(), "/aws/lambda/dev-api", query="fields unmask")


def test_get_cloudwatch_alarm_summary_rejects_empty_name() -> None:
    with pytest.raises(ToolInputError, match="alarm_name is required"):
        get_cloudwatch_alarm_summary(FakeRuntime(), " ")


def test_cloudwatch_log_search_rejects_invalid_limits() -> None:
    with pytest.raises(ToolInputError, match="since_minutes"):
        cloudwatch_log_search(FakeRuntime(), "/aws/lambda/dev-api", query="ERROR", since_minutes=0)
    with pytest.raises(ToolInputError, match="max_results"):
        cloudwatch_log_search(FakeRuntime(), "/aws/lambda/dev-api", query="ERROR", max_results=0)


def test_cloudwatch_log_search_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.logs_client = FailingLogsClient()

    with pytest.raises(AwsToolError, match="AWS logs.FilterLogEvents AccessDenied"):
        cloudwatch_log_search(runtime, "/aws/lambda/dev-api", query="ERROR")


def test_cloudwatch_logs_insights_query_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.logs_client = FailingLogsClient()

    with pytest.raises(AwsToolError, match="AWS logs.StartQuery AccessDenied"):
        cloudwatch_logs_insights_query(
            runtime,
            "/aws/lambda/dev-api",
            query="fields @timestamp",
        )


class FailingLogsClient:
    def describe_log_groups(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeLogGroups",
        )

    def filter_log_events(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "FilterLogEvents",
        )

    def start_query(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "StartQuery",
        )


def test_list_cloudwatch_log_groups_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.logs_client = FailingLogsClient()

    with pytest.raises(AwsToolError, match="AWS logs.DescribeLogGroups AccessDenied"):
        list_cloudwatch_log_groups(runtime)


def test_list_cloudwatch_alarms_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.cloudwatch_client = FailingCloudWatchClient()

    with pytest.raises(AwsToolError, match="AWS cloudwatch.DescribeAlarms AccessDenied"):
        list_cloudwatch_alarms(runtime)


class FailingCloudWatchClient:
    def describe_alarms(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeAlarms",
        )


class PaginatedLogsClient:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def filter_log_events(self, **kwargs: Any) -> dict[str, Any]:
        self.requests.append(kwargs)
        if "nextToken" not in kwargs:
            return {
                "events": [
                    {
                        "timestamp": 1_767_225_600_000,
                        "logStreamName": "stream-a",
                        "message": "ERROR first",
                    }
                ],
                "nextToken": "page-2",
            }
        return {
            "events": [
                {
                    "timestamp": 1_767_225_660_000,
                    "logStreamName": "stream-b",
                    "message": "ERROR second",
                }
            ]
        }
