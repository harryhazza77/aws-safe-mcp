from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.sns import (
    explain_sns_topic_dependencies,
    get_sns_topic_summary,
    list_sns_topics,
)


class FakeSnsClient:
    def __init__(self) -> None:
        self.last_request: dict[str, Any] | None = None

    def list_topics(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "Topics": [
                {"TopicArn": "arn:aws:sns:eu-west-2:123456789012:dev-orders"},
                {"TopicArn": "arn:aws:sns:eu-west-2:123456789012:prod-orders"},
                {"TopicArn": "arn:aws:sns:eu-west-2:123456789012:dev-events.fifo"},
            ]
        }

    def get_topic_attributes(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "Attributes": {
                "TopicArn": "arn:aws:sns:eu-west-2:123456789012:dev-orders",
                "DisplayName": "Development orders",
                "SubscriptionsConfirmed": "2",
                "SubscriptionsPending": "1",
                "SubscriptionsDeleted": "0",
                "KmsMasterKeyId": "alias/aws/sns",
                "DeliveryPolicy": '{"healthyRetryPolicy":{}}',
                "Policy": '{"Statement":[{"Effect":"Allow"},{"Effect":"Deny"}]}',
            }
        }

    def list_subscriptions_by_topic(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "Subscriptions": [
                {
                    "SubscriptionArn": (
                        "arn:aws:sns:eu-west-2:123456789012:dev-orders:"
                        "11111111-1111-1111-1111-111111111111"
                    ),
                    "Owner": "123456789012",
                    "Protocol": "sqs",
                    "Endpoint": "arn:aws:sqs:eu-west-2:123456789012:dev-work",
                },
                {
                    "SubscriptionArn": "PendingConfirmation",
                    "Owner": "123456789012",
                    "Protocol": "https",
                    "Endpoint": "https://example.com/orders?token=secret",
                },
                {
                    "SubscriptionArn": (
                        "arn:aws:sns:eu-west-2:123456789012:dev-orders:"
                        "22222222-2222-2222-2222-222222222222"
                    ),
                    "Owner": "123456789012",
                    "Protocol": "lambda",
                    "Endpoint": "arn:aws:lambda:eu-west-2:123456789012:function:dev-handler",
                },
                {
                    "SubscriptionArn": (
                        "arn:aws:sns:eu-west-2:123456789012:dev-orders:"
                        "33333333-3333-3333-3333-333333333333"
                    ),
                    "Owner": "123456789012",
                    "Protocol": "email",
                    "Endpoint": "person@example.com",
                },
            ]
        }

    def get_subscription_attributes(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        if "11111111" not in str(kwargs.get("SubscriptionArn")):
            return {"Attributes": {}}
        return {
            "Attributes": {
                "RedrivePolicy": (
                    '{"deadLetterTargetArn":"arn:aws:sqs:eu-west-2:123456789012:dev-dlq"}'
                )
            }
        }


class FakeLambdaClient:
    def get_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "Policy": (
                '{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},'
                '"Action":"lambda:InvokeFunction",'
                '"Resource":"arn:aws:lambda:eu-west-2:123456789012:function:dev-handler",'
                '"Condition":{"ArnLike":{"AWS:SourceArn":'
                '"arn:aws:sns:eu-west-2:123456789012:dev-orders"}}}]}'
            )
        }


class FakeSqsClient:
    def get_queue_attributes(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "Attributes": {
                "Policy": (
                    '{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},'
                    '"Action":"sqs:SendMessage",'
                    '"Resource":"arn:aws:sqs:eu-west-2:123456789012:dev-work",'
                    '"Condition":{"ArnEquals":{"aws:SourceArn":'
                    '"arn:aws:sns:eu-west-2:123456789012:dev-orders"}}}]}'
                )
            }
        }


class FakeRuntime:
    def __init__(self) -> None:
        self.config = AwsSafeConfig(allowed_account_ids=["123456789012"], max_results=100)
        self.region = "eu-west-2"
        self.client_obj = FakeSnsClient()
        self.lambda_client = FakeLambdaClient()
        self.sqs_client = FakeSqsClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert region == "eu-west-2"
        if service_name == "sns":
            return self.client_obj
        if service_name == "lambda":
            return self.lambda_client
        if service_name == "sqs":
            return self.sqs_client
        raise AssertionError(f"unexpected service {service_name}")


def test_list_sns_topics_returns_bounded_metadata() -> None:
    runtime = FakeRuntime()

    result = list_sns_topics(runtime, name_prefix="dev-", max_results=1)

    assert result == {
        "region": "eu-west-2",
        "name_prefix": "dev-",
        "max_results": 1,
        "count": 1,
        "is_truncated": False,
        "topics": [
            {
                "topic_name": "dev-orders",
                "topic_arn": "arn:aws:sns:eu-west-2:123456789012:dev-orders",
                "fifo": False,
            }
        ],
    }
    assert runtime.client_obj.last_request == {}


def test_get_sns_topic_summary_summarizes_attributes_and_safe_subscriptions() -> None:
    runtime = FakeRuntime()
    topic_arn = "arn:aws:sns:eu-west-2:123456789012:dev-orders"

    result = get_sns_topic_summary(runtime, topic_arn, max_subscriptions=2)

    assert result["topic_name"] == "dev-orders"
    assert result["topic_arn"] == topic_arn
    assert result["display_name"] == "Development orders"
    assert result["subscription_counts"] == {
        "confirmed": 2,
        "pending": 1,
        "deleted": 0,
        "returned": 2,
        "is_truncated": False,
    }
    assert result["subscriptions"] == [
        {
            "subscription_arn": (
                "arn:aws:sns:eu-west-2:123456789012:dev-orders:"
                "11111111-1111-1111-1111-111111111111"
            ),
            "protocol": "sqs",
            "owner": "123456789012",
            "endpoint": {
                "type": "sqs",
                "arn": "arn:aws:sqs:eu-west-2:123456789012:dev-work",
                "name": "dev-work",
            },
        },
        {
            "subscription_arn": "PendingConfirmation",
            "protocol": "https",
            "owner": "123456789012",
            "endpoint": {
                "type": "https",
                "scheme": "https",
                "host": "example.com",
                "path_present": True,
            },
        },
    ]
    assert result["encryption"] == {"kms_master_key_id": "alias/aws/sns"}
    assert result["delivery_policy"] == {"available": True}
    assert result["policy"] == {"available": True, "statement_count": 2}
    assert runtime.client_obj.last_request == {
        "TopicArn": topic_arn,
    }


def test_explain_sns_topic_dependencies_maps_targets_dlq_and_permissions() -> None:
    runtime = FakeRuntime()
    topic_arn = "arn:aws:sns:eu-west-2:123456789012:dev-orders"

    result = explain_sns_topic_dependencies(runtime, topic_arn)

    assert result["topic_name"] == "dev-orders"
    assert result["nodes"]["sqs_targets"][0]["endpoint"]["arn"] == (
        "arn:aws:sqs:eu-west-2:123456789012:dev-work"
    )
    assert result["nodes"]["dead_letter_targets"][0] == {
        "configured": True,
        "arn": "arn:aws:sqs:eu-west-2:123456789012:dev-dlq",
        "name": "dev-dlq",
    }
    assert result["edges"][:3] == [
        {
            "source": topic_arn,
            "target": "arn:aws:sqs:eu-west-2:123456789012:dev-work",
            "relationship": "publishes_to",
            "target_type": "sqs",
        },
        {
            "source": (
                "arn:aws:sns:eu-west-2:123456789012:dev-orders:"
                "11111111-1111-1111-1111-111111111111"
            ),
            "target": "arn:aws:sqs:eu-west-2:123456789012:dev-dlq",
            "relationship": "dead_letters_to",
            "target_type": "sqs",
        },
        {
            "source": topic_arn,
            "target": "example.com",
            "relationship": "publishes_to",
            "target_type": "https",
        },
    ]
    assert result["permission_hints"][0]["action"] == "sqs:SendMessage"
    assert result["permission_checks"]["summary"] == {
        "allowed": 2,
        "denied": 0,
        "unknown": 0,
        "explicit_denies": 0,
    }
    assert result["graph_summary"]["target_types"] == ["https", "lambda", "sqs"]


def test_explain_sns_topic_dependencies_can_disable_permission_checks() -> None:
    result = explain_sns_topic_dependencies(
        FakeRuntime(),
        "arn:aws:sns:eu-west-2:123456789012:dev-orders",
        include_permission_checks=False,
    )

    assert result["permission_checks"]["enabled"] is False


def test_get_sns_topic_summary_rejects_blank_arn() -> None:
    with pytest.raises(ToolInputError, match="topic_arn is required"):
        get_sns_topic_summary(FakeRuntime(), " ")


def test_get_sns_topic_summary_rejects_non_sns_arn() -> None:
    with pytest.raises(ToolInputError, match="SNS topic ARN"):
        get_sns_topic_summary(FakeRuntime(), "arn:aws:sqs:eu-west-2:123456789012:queue")


class FailingSnsClient:
    def list_topics(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "ListTopics",
        )

    def get_topic_attributes(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "NotFound", "Message": "missing"}},
            "GetTopicAttributes",
        )


def test_list_sns_topics_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.client_obj = FailingSnsClient()

    with pytest.raises(AwsToolError, match="AWS sns.ListTopics AccessDenied"):
        list_sns_topics(runtime)


def test_get_sns_topic_summary_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.client_obj = FailingSnsClient()

    with pytest.raises(AwsToolError, match="AWS sns.GetTopicAttributes NotFound"):
        get_sns_topic_summary(runtime, "arn:aws:sns:eu-west-2:123456789012:missing")
