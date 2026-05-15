from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.common import clamp_limit, resolve_region


def list_sqs_queues(
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
    client = runtime.client("sqs", region=resolved_region)
    queues: list[dict[str, Any]] = []
    token: str | None = None

    try:
        while len(queues) < limit:
            request: dict[str, Any] = {"MaxResults": min(limit, 1000)}
            if name_prefix:
                request["QueueNamePrefix"] = name_prefix
            if token:
                request["NextToken"] = token
            response = client.list_queues(**request)
            for queue_url in response.get("QueueUrls", []):
                queues.append(_queue_list_item(str(queue_url)))
                if len(queues) >= limit:
                    break
            token = response.get("NextToken")
            if not token:
                break
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "sqs.ListQueues") from exc

    return {
        "region": resolved_region,
        "name_prefix": name_prefix,
        "max_results": limit,
        "count": len(queues),
        "is_truncated": token is not None and len(queues) >= limit,
        "queues": queues,
    }


def get_sqs_queue_summary(
    runtime: AwsRuntime,
    queue_url: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_url = require_sqs_queue_url(queue_url)
    client = runtime.client("sqs", region=resolved_region)

    try:
        response = client.get_queue_attributes(
            QueueUrl=required_url,
            AttributeNames=["All"],
        )
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "sqs.GetQueueAttributes") from exc

    attributes = response.get("Attributes", {})
    return {
        "queue_name": _queue_name_from_url(required_url),
        "queue_url": required_url,
        "queue_arn": attributes.get("QueueArn"),
        "region": resolved_region,
        "fifo": required_url.endswith(".fifo"),
        "visibility_timeout_seconds": _int_attribute(attributes, "VisibilityTimeout"),
        "message_retention_seconds": _int_attribute(attributes, "MessageRetentionPeriod"),
        "delay_seconds": _int_attribute(attributes, "DelaySeconds"),
        "receive_wait_time_seconds": _int_attribute(attributes, "ReceiveMessageWaitTimeSeconds"),
        "max_message_size_bytes": _int_attribute(attributes, "MaximumMessageSize"),
        "message_counts": {
            "available": _int_attribute(attributes, "ApproximateNumberOfMessages"),
            "in_flight": _int_attribute(attributes, "ApproximateNumberOfMessagesNotVisible"),
            "delayed": _int_attribute(attributes, "ApproximateNumberOfMessagesDelayed"),
        },
        "dead_letter": _dead_letter_summary(attributes),
        "encryption": _encryption_summary(attributes),
        "policy": _policy_summary(attributes.get("Policy")),
    }


def require_sqs_queue_url(queue_url: str) -> str:
    value = queue_url.strip()
    if not value:
        raise ToolInputError("queue_url is required")
    if not value.startswith(("http://", "https://")):
        raise ToolInputError("queue_url must start with http:// or https://")
    return value


def _queue_list_item(queue_url: str) -> dict[str, Any]:
    return {
        "queue_name": _queue_name_from_url(queue_url),
        "queue_url": queue_url,
        "fifo": queue_url.endswith(".fifo"),
    }


def _queue_name_from_url(queue_url: str) -> str:
    return queue_url.rstrip("/").rsplit("/", 1)[-1]


def _int_attribute(attributes: dict[str, Any], name: str) -> int | None:
    value = attributes.get(name)
    if value is None:
        return None
    try:
        return int(str(value))
    except ValueError:
        return None


def _dead_letter_summary(attributes: dict[str, Any]) -> dict[str, Any]:
    raw_policy = attributes.get("RedrivePolicy")
    if not raw_policy:
        return {
            "configured": False,
            "dead_letter_target_arn": None,
            "max_receive_count": None,
        }
    try:
        policy = json.loads(str(raw_policy))
    except json.JSONDecodeError:
        return {
            "configured": True,
            "dead_letter_target_arn": None,
            "max_receive_count": None,
            "warning": "RedrivePolicy was not valid JSON",
        }
    return {
        "configured": True,
        "dead_letter_target_arn": policy.get("deadLetterTargetArn"),
        "max_receive_count": _optional_int(policy.get("maxReceiveCount")),
    }


def _encryption_summary(attributes: dict[str, Any]) -> dict[str, Any]:
    return {
        "sqs_managed_sse": _optional_bool(attributes.get("SqsManagedSseEnabled")),
        "kms_master_key_id": attributes.get("KmsMasterKeyId"),
        "kms_data_key_reuse_period_seconds": _int_attribute(
            attributes,
            "KmsDataKeyReusePeriodSeconds",
        ),
    }


def _policy_summary(raw_policy: Any) -> dict[str, Any]:
    if not raw_policy:
        return {"available": False, "statement_count": 0}
    try:
        policy = json.loads(str(raw_policy))
    except json.JSONDecodeError:
        return {
            "available": False,
            "statement_count": 0,
            "warning": "Queue policy was not valid JSON",
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


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).lower() == "true"
