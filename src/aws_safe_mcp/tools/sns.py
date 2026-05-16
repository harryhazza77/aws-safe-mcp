from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.common import clamp_limit, resolve_region
from aws_safe_mcp.tools.graph import dependency_graph_summary, empty_permission_checks


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


def explain_sns_topic_dependencies(
    runtime: AwsRuntime,
    topic_arn: str,
    region: str | None = None,
    include_permission_checks: bool = True,
    max_permission_checks: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_arn = require_sns_topic_arn(topic_arn)
    limit = clamp_limit(
        max_permission_checks,
        default=20,
        configured_max=runtime.config.max_results,
        label="max_permission_checks",
    )
    warnings: list[str] = []
    topic = get_sns_topic_summary(
        runtime,
        required_arn,
        region=resolved_region,
        max_subscriptions=limit,
    )
    subscriptions = _subscription_dependency_nodes(runtime, resolved_region, topic, warnings)
    nodes = {
        "topic": topic,
        "subscriptions": subscriptions,
        "lambda_targets": [
            item for item in subscriptions if item.get("protocol") == "lambda"
        ],
        "sqs_targets": [item for item in subscriptions if item.get("protocol") == "sqs"],
        "dead_letter_targets": [
            item["dead_letter"]
            for item in subscriptions
            if isinstance(item.get("dead_letter"), dict) and item["dead_letter"].get("arn")
        ],
    }
    edges = _sns_dependency_edges(required_arn, subscriptions)
    permission_hints = _sns_permission_hints(required_arn, subscriptions)
    permission_checks = (
        _sns_permission_checks(
            runtime,
            resolved_region,
            required_arn,
            subscriptions,
            limit,
            warnings,
        )
        if include_permission_checks
        else empty_permission_checks()
    )

    return {
        "topic_arn": required_arn,
        "topic_name": topic["topic_name"],
        "region": resolved_region,
        "nodes": nodes,
        "edges": edges,
        "permission_hints": permission_hints,
        "permission_checks": permission_checks,
        "warnings": warnings,
        "graph_summary": dependency_graph_summary(
            nodes=nodes,
            edges=edges,
            permission_checks=permission_checks,
            warnings=warnings,
        ),
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


def _subscription_dependency_nodes(
    runtime: AwsRuntime,
    region: str,
    topic: dict[str, Any],
    warnings: list[str],
) -> list[dict[str, Any]]:
    client = runtime.client("sns", region=region)
    nodes = []
    for subscription in topic.get("subscriptions", []):
        node = dict(subscription)
        node["dead_letter"] = _subscription_dead_letter(client, subscription, warnings)
        nodes.append(node)
    return nodes


def _subscription_dead_letter(
    client: Any,
    subscription: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any] | None:
    subscription_arn = subscription.get("subscription_arn")
    if not subscription_arn or subscription_arn == "PendingConfirmation":
        return None
    try:
        response = client.get_subscription_attributes(SubscriptionArn=subscription_arn)
    except (BotoCoreError, ClientError) as exc:
        warning = normalize_aws_error(exc, "sns.GetSubscriptionAttributes")
        warnings.append(f"Unable to read SNS subscription attributes: {warning}")
        return None
    raw_policy = response.get("Attributes", {}).get("RedrivePolicy")
    if not raw_policy:
        return None
    try:
        policy = json.loads(str(raw_policy))
    except json.JSONDecodeError:
        warnings.append("SNS subscription RedrivePolicy was not valid JSON")
        return {"configured": True, "arn": None}
    target_arn = policy.get("deadLetterTargetArn")
    return {
        "configured": True,
        "arn": target_arn,
        "name": target_arn.rsplit(":", 1)[-1] if isinstance(target_arn, str) else None,
    }


def _sns_dependency_edges(
    topic_arn: str,
    subscriptions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    edges = []
    for subscription in subscriptions:
        endpoint = subscription.get("endpoint") or {}
        target = endpoint.get("arn") or endpoint.get("host")
        protocol = subscription.get("protocol")
        if target:
            edges.append(
                {
                    "source": topic_arn,
                    "target": target,
                    "relationship": "publishes_to",
                    "target_type": protocol,
                }
            )
        dead_letter = subscription.get("dead_letter")
        if isinstance(dead_letter, dict) and dead_letter.get("arn"):
            edges.append(
                {
                    "source": subscription.get("subscription_arn"),
                    "target": dead_letter["arn"],
                    "relationship": "dead_letters_to",
                    "target_type": "sqs",
                }
            )
    return edges


def _sns_permission_hints(
    topic_arn: str,
    subscriptions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    hints = []
    for subscription in subscriptions:
        endpoint = subscription.get("endpoint") or {}
        protocol = subscription.get("protocol")
        if protocol == "lambda" and endpoint.get("arn"):
            hints.append(
                {
                    "principal": "sns.amazonaws.com",
                    "action": "lambda:InvokeFunction",
                    "resource": endpoint["arn"],
                    "source": topic_arn,
                    "reason": "SNS needs Lambda resource-policy permission to invoke the function.",
                }
            )
        if protocol == "sqs" and endpoint.get("arn"):
            hints.append(
                {
                    "principal": "sns.amazonaws.com",
                    "action": "sqs:SendMessage",
                    "resource": endpoint["arn"],
                    "source": topic_arn,
                    "reason": (
                        "SNS needs the SQS queue policy to allow SendMessage from this topic."
                    ),
                }
            )
    return hints


def _sns_permission_checks(
    runtime: AwsRuntime,
    region: str,
    topic_arn: str,
    subscriptions: list[dict[str, Any]],
    limit: int,
    warnings: list[str],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for subscription in subscriptions:
        if len(checks) >= limit:
            break
        endpoint = subscription.get("endpoint") or {}
        protocol = subscription.get("protocol")
        if protocol == "lambda" and endpoint.get("arn"):
            checks.append(
                _lambda_policy_check(runtime, region, topic_arn, endpoint["arn"], warnings)
            )
        elif protocol == "sqs" and endpoint.get("arn"):
            checks.append(_sqs_policy_check(runtime, region, topic_arn, endpoint["arn"], warnings))
    return {
        "enabled": True,
        "checked_count": len(checks),
        "checks": checks,
        "summary": _permission_summary(checks),
    }


def _lambda_policy_check(
    runtime: AwsRuntime,
    region: str,
    topic_arn: str,
    function_arn: str,
    warnings: list[str],
) -> dict[str, Any]:
    base = {
        "principal": "sns.amazonaws.com",
        "action": "lambda:InvokeFunction",
        "resource": function_arn,
        "source": topic_arn,
        "source_type": "lambda_resource_policy",
    }
    client = runtime.client("lambda", region=region)
    try:
        response = client.get_policy(FunctionName=function_arn)
    except (BotoCoreError, ClientError) as exc:
        warning = normalize_aws_error(exc, "lambda.GetPolicy")
        warnings.append(f"Unable to read Lambda policy for SNS subscription: {warning}")
        return {**base, "decision": "unknown"}
    policy = _json_policy(response.get("Policy"))
    return {
        **base,
        "decision": _resource_policy_decision(
            policy,
            "sns.amazonaws.com",
            "lambda:InvokeFunction",
            function_arn,
            topic_arn,
        ),
    }


def _sqs_policy_check(
    runtime: AwsRuntime,
    region: str,
    topic_arn: str,
    queue_arn: str,
    warnings: list[str],
) -> dict[str, Any]:
    base = {
        "principal": "sns.amazonaws.com",
        "action": "sqs:SendMessage",
        "resource": queue_arn,
        "source": topic_arn,
        "source_type": "sqs_queue_policy",
    }
    queue_url = _queue_url_from_arn(queue_arn)
    if queue_url is None:
        return {**base, "decision": "unknown"}
    client = runtime.client("sqs", region=region)
    try:
        response = client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])
    except (BotoCoreError, ClientError) as exc:
        warning = normalize_aws_error(exc, "sqs.GetQueueAttributes")
        warnings.append(f"Unable to read SQS queue policy for SNS subscription: {warning}")
        return {**base, "decision": "unknown"}
    policy = _json_policy(response.get("Attributes", {}).get("Policy"))
    return {
        **base,
        "decision": _resource_policy_decision(
            policy,
            "sns.amazonaws.com",
            "sqs:SendMessage",
            queue_arn,
            topic_arn,
        ),
    }


def _json_policy(value: Any) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _resource_policy_decision(
    policy: dict[str, Any] | None,
    service: str,
    action: str,
    resource: str,
    source_arn: str,
) -> str:
    if policy is None:
        return "unknown"
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements if isinstance(statements, list) else []:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if not _principal_matches(statement.get("Principal"), service):
            continue
        if not _action_matches(statement.get("Action"), action):
            continue
        if not _resource_matches(statement.get("Resource"), resource):
            continue
        if not _source_matches(statement.get("Condition"), source_arn):
            continue
        return "allowed"
    return "unknown"


def _principal_matches(principal: Any, service: str) -> bool:
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    service_principal = principal.get("Service")
    if isinstance(service_principal, str):
        return service_principal == service
    if isinstance(service_principal, list):
        return service in service_principal
    return False


def _action_matches(actions: Any, action: str) -> bool:
    if isinstance(actions, str):
        return actions in {action, "*"} or actions.endswith(":*")
    if isinstance(actions, list):
        return any(_action_matches(item, action) for item in actions)
    return False


def _resource_matches(resources: Any, resource: str) -> bool:
    if resources in {None, "*"}:
        return True
    if isinstance(resources, str):
        return resources == resource
    if isinstance(resources, list):
        return resource in resources or "*" in resources
    return False


def _source_matches(condition: Any, source_arn: str) -> bool:
    if not isinstance(condition, dict):
        return True
    for operator in ("ArnEquals", "ArnLike", "StringEquals"):
        values = condition.get(operator)
        if isinstance(values, dict):
            source = values.get("AWS:SourceArn") or values.get("aws:SourceArn")
            if source is None:
                continue
            if source == source_arn or source == "*":
                return True
            return isinstance(source, list) and source_arn in source
    return True


def _permission_summary(checks: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "allowed": sum(1 for check in checks if check["decision"] == "allowed"),
        "denied": sum(1 for check in checks if check["decision"] == "denied"),
        "unknown": sum(1 for check in checks if check["decision"] == "unknown"),
        "explicit_denies": sum(1 for check in checks if check["decision"] == "explicit_deny"),
    }


def _queue_url_from_arn(queue_arn: str) -> str | None:
    parts = queue_arn.split(":")
    if len(parts) < 6 or parts[2] != "sqs":
        return None
    _, _, _, region, account, queue_name = parts[:6]
    return f"https://sqs.{region}.amazonaws.com/{account}/{queue_name}"
