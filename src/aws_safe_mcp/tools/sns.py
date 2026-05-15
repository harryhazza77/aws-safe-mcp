from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.common import clamp_limit, resolve_region


def list_sns_topics(
    runtime: AwsRuntime,
    region: str | None = None,
    name_prefix: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    client = runtime.client("sns", region=resolved_region)
    topics: list[dict[str, Any]] = []
    token: str | None = None

    try:
        while len(topics) < limit:
            request: dict[str, Any] = {}
            if token:
                request["NextToken"] = token
            response = client.list_topics(**request)
            for topic in response.get("Topics", []):
                topic_arn = str(topic.get("TopicArn") or "")
                if not topic_arn:
                    continue
                item = _topic_list_item(topic_arn)
                if name_prefix and not str(item["topic_name"]).startswith(name_prefix):
                    continue
                topics.append(item)
                if len(topics) >= limit:
                    break
            token = response.get("NextToken")
            if not token:
                break
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "sns.ListTopics") from exc

    return {
        "region": resolved_region,
        "name_prefix": name_prefix,
        "max_results": limit,
        "count": len(topics),
        "is_truncated": token is not None and len(topics) >= limit,
        "topics": topics,
    }


def get_sns_topic_summary(
    runtime: AwsRuntime,
    topic_arn: str,
    region: str | None = None,
    max_subscriptions: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_arn = require_sns_topic_arn(topic_arn)
    limit = clamp_limit(
        max_subscriptions,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_subscriptions",
    )
    client = runtime.client("sns", region=resolved_region)

    try:
        attributes = client.get_topic_attributes(TopicArn=required_arn).get("Attributes", {})
        subscriptions, subscription_token = _list_subscriptions(client, required_arn, limit)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "sns.GetTopicAttributes") from exc

    return {
        "topic_name": _topic_name_from_arn(required_arn),
        "topic_arn": required_arn,
        "region": resolved_region,
        "display_name": attributes.get("DisplayName") or None,
        "fifo": required_arn.endswith(".fifo"),
        "subscription_counts": {
            "confirmed": _optional_int(attributes.get("SubscriptionsConfirmed")),
            "pending": _optional_int(attributes.get("SubscriptionsPending")),
            "deleted": _optional_int(attributes.get("SubscriptionsDeleted")),
            "returned": len(subscriptions),
            "is_truncated": subscription_token is not None and len(subscriptions) >= limit,
        },
        "subscriptions": [_subscription_summary(item) for item in subscriptions],
        "encryption": {
            "kms_master_key_id": attributes.get("KmsMasterKeyId"),
        },
        "delivery_policy": {
            "available": bool(attributes.get("DeliveryPolicy")),
        },
        "policy": _policy_summary(attributes.get("Policy")),
    }


def require_sns_topic_arn(topic_arn: str) -> str:
    value = topic_arn.strip()
    if not value:
        raise ToolInputError("topic_arn is required")
    if ":sns:" not in value or not value.startswith("arn:"):
        raise ToolInputError("topic_arn must be a valid SNS topic ARN")
    return value


def _list_subscriptions(
    client: Any,
    topic_arn: str,
    limit: int,
) -> tuple[list[dict[str, Any]], str | None]:
    subscriptions: list[dict[str, Any]] = []
    token: str | None = None
    while len(subscriptions) < limit:
        request = {"TopicArn": topic_arn}
        if token:
            request["NextToken"] = token
        response = client.list_subscriptions_by_topic(**request)
        subscriptions.extend(response.get("Subscriptions", [])[: limit - len(subscriptions)])
        token = response.get("NextToken")
        if not token:
            break
    return subscriptions, token


def _topic_list_item(topic_arn: str) -> dict[str, Any]:
    return {
        "topic_name": _topic_name_from_arn(topic_arn),
        "topic_arn": topic_arn,
        "fifo": topic_arn.endswith(".fifo"),
    }


def _topic_name_from_arn(topic_arn: str) -> str:
    return topic_arn.rsplit(":", 1)[-1]


def _subscription_summary(subscription: dict[str, Any]) -> dict[str, Any]:
    protocol = subscription.get("Protocol")
    endpoint = subscription.get("Endpoint")
    return {
        "subscription_arn": _subscription_arn_summary(subscription.get("SubscriptionArn")),
        "protocol": protocol,
        "owner": subscription.get("Owner"),
        "endpoint": _safe_endpoint_summary(protocol, endpoint),
    }


def _subscription_arn_summary(value: Any) -> str | None:
    if value is None:
        return None
    if value == "PendingConfirmation":
        return "PendingConfirmation"
    return str(value)


def _safe_endpoint_summary(protocol: Any, endpoint: Any) -> dict[str, Any]:
    if endpoint is None:
        return {"type": protocol, "value": None}
    value = str(endpoint)
    if protocol in {"lambda", "sqs", "firehose", "application"} or value.startswith("arn:"):
        return {
            "type": protocol,
            "arn": value,
            "name": value.rsplit(":", 1)[-1],
        }
    if protocol in {"http", "https"}:
        parsed = urlparse(value)
        return {
            "type": protocol,
            "scheme": parsed.scheme,
            "host": parsed.netloc,
            "path_present": bool(parsed.path and parsed.path != "/"),
        }
    if protocol == "email":
        return {"type": protocol, "redacted": True}
    return {"type": protocol, "redacted": True}


def _policy_summary(raw_policy: Any) -> dict[str, Any]:
    if not raw_policy:
        return {"available": False, "statement_count": 0}
    try:
        policy = json.loads(str(raw_policy))
    except json.JSONDecodeError:
        return {
            "available": False,
            "statement_count": 0,
            "warning": "Topic policy was not valid JSON",
        }
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        statements = []
    return {
        "available": True,
        "statement_count": len(statements),
    }


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value))
    except ValueError:
        return None
