from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.cloudwatch import cloudwatch_log_search, list_cloudwatch_log_groups


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

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert service_name == "logs"
        assert region == "eu-west-2"
        return self.logs_client


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


def test_list_cloudwatch_log_groups_returns_metadata() -> None:
    runtime = FakeRuntime()

    result = list_cloudwatch_log_groups(runtime, name_prefix="/aws/lambda/dev", max_results=5)

    assert result["count"] == 1
    assert result["log_groups"][0]["log_group_name"] == "/aws/lambda/dev-api"
    assert result["log_groups"][0]["creation_time"] == "2026-01-01T00:00:00+00:00"
    assert runtime.logs_client.last_request is not None
    assert runtime.logs_client.last_request["logGroupNamePrefix"] == "/aws/lambda/dev"


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


def test_list_cloudwatch_log_groups_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.logs_client = FailingLogsClient()

    with pytest.raises(AwsToolError, match="AWS logs.DescribeLogGroups AccessDenied"):
        list_cloudwatch_log_groups(runtime)


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
