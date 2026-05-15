from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.sqs import get_sqs_queue_summary, list_sqs_queues


class FakeSqsClient:
    def __init__(self) -> None:
        self.last_request: dict[str, Any] | None = None

    def list_queues(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "QueueUrls": [
                "https://sqs.eu-west-2.amazonaws.com/123456789012/dev-work",
                "https://sqs.eu-west-2.amazonaws.com/123456789012/dev-dlq.fifo",
            ]
        }

    def get_queue_attributes(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "Attributes": {
                "QueueArn": "arn:aws:sqs:eu-west-2:123456789012:dev-work",
                "VisibilityTimeout": "30",
                "MessageRetentionPeriod": "86400",
                "DelaySeconds": "0",
                "ReceiveMessageWaitTimeSeconds": "20",
                "MaximumMessageSize": "262144",
                "ApproximateNumberOfMessages": "4",
                "ApproximateNumberOfMessagesNotVisible": "1",
                "ApproximateNumberOfMessagesDelayed": "2",
                "RedrivePolicy": (
                    '{"deadLetterTargetArn":"arn:aws:sqs:eu-west-2:123456789012:dev-dlq",'
                    '"maxReceiveCount":"5"}'
                ),
                "SqsManagedSseEnabled": "true",
                "Policy": '{"Statement":[{"Effect":"Allow"}]}',
            }
        }


class FakeRuntime:
    def __init__(self) -> None:
        self.config = AwsSafeConfig(allowed_account_ids=["123456789012"], max_results=100)
        self.region = "eu-west-2"
        self.sqs_client = FakeSqsClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert service_name == "sqs"
        assert region == "eu-west-2"
        return self.sqs_client


def test_list_sqs_queues_returns_bounded_metadata() -> None:
    runtime = FakeRuntime()

    result = list_sqs_queues(runtime, name_prefix="dev-", max_results=1)

    assert result == {
        "region": "eu-west-2",
        "name_prefix": "dev-",
        "max_results": 1,
        "count": 1,
        "is_truncated": False,
        "queues": [
            {
                "queue_name": "dev-work",
                "queue_url": "https://sqs.eu-west-2.amazonaws.com/123456789012/dev-work",
                "fifo": False,
            }
        ],
    }
    assert runtime.sqs_client.last_request == {"MaxResults": 1, "QueueNamePrefix": "dev-"}


def test_get_sqs_queue_summary_returns_attributes_without_receiving_messages() -> None:
    runtime = FakeRuntime()
    queue_url = "https://sqs.eu-west-2.amazonaws.com/123456789012/dev-work"

    result = get_sqs_queue_summary(runtime, queue_url)

    assert result["queue_name"] == "dev-work"
    assert result["queue_url"] == queue_url
    assert result["queue_arn"] == "arn:aws:sqs:eu-west-2:123456789012:dev-work"
    assert result["visibility_timeout_seconds"] == 30
    assert result["message_counts"] == {"available": 4, "in_flight": 1, "delayed": 2}
    assert result["dead_letter"] == {
        "configured": True,
        "dead_letter_target_arn": "arn:aws:sqs:eu-west-2:123456789012:dev-dlq",
        "max_receive_count": 5,
    }
    assert result["encryption"]["sqs_managed_sse"] is True
    assert result["policy"] == {"available": True, "statement_count": 1}
    assert runtime.sqs_client.last_request == {
        "QueueUrl": queue_url,
        "AttributeNames": ["All"],
    }


def test_get_sqs_queue_summary_rejects_blank_url() -> None:
    with pytest.raises(ToolInputError, match="queue_url is required"):
        get_sqs_queue_summary(FakeRuntime(), " ")


def test_get_sqs_queue_summary_rejects_non_url() -> None:
    with pytest.raises(ToolInputError, match="queue_url must start"):
        get_sqs_queue_summary(FakeRuntime(), "dev-work")


class FailingSqsClient:
    def list_queues(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "ListQueues",
        )

    def get_queue_attributes(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetQueueAttributes",
        )


def test_list_sqs_queues_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.sqs_client = FailingSqsClient()

    with pytest.raises(AwsToolError, match="AWS sqs.ListQueues AccessDenied"):
        list_sqs_queues(runtime)


def test_get_sqs_queue_summary_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.sqs_client = FailingSqsClient()

    with pytest.raises(AwsToolError, match="AWS sqs.GetQueueAttributes AccessDenied"):
        get_sqs_queue_summary(
            runtime,
            "https://sqs.eu-west-2.amazonaws.com/123456789012/dev-work",
        )
