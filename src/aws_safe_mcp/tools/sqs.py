from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.common import clamp_limit, resolve_region
from aws_safe_mcp.tools.graph import dependency_graph_summary, empty_permission_checks


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


def explain_sqs_queue_dependencies(
    runtime: AwsRuntime,
    queue_url: str,
    region: str | None = None,
    include_permission_checks: bool = True,
    max_permission_checks: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    queue = get_sqs_queue_summary(runtime, queue_url, region=resolved_region)
    queue_arn = queue.get("queue_arn")
    if not isinstance(queue_arn, str) or not queue_arn:
        raise ToolInputError("queue does not expose QueueArn")

    limit = clamp_limit(
        max_permission_checks,
        default=20,
        configured_max=runtime.config.max_results,
        label="max_permission_checks",
    )
    warnings: list[str] = []
    eventbridge_targets = _eventbridge_targets_for_queue(
        runtime,
        resolved_region,
        queue_arn,
        limit,
        warnings,
    )
    lambda_mappings = _lambda_mappings_for_queue(
        runtime,
        resolved_region,
        queue_arn,
        limit,
        warnings,
    )
    queue_policy = _queue_policy_document(
        runtime,
        resolved_region,
        str(queue["queue_url"]),
        warnings,
    )

    nodes = {
        "queue": queue,
        "dead_letter_queue": _dead_letter_node(queue),
        "eventbridge_rules": eventbridge_targets,
        "lambda_event_source_mappings": lambda_mappings,
    }
    edges = _sqs_dependency_edges(queue, eventbridge_targets, lambda_mappings)
    permission_hints = _sqs_permission_hints(queue_arn, eventbridge_targets, lambda_mappings)
    permission_checks = (
        _sqs_permission_checks(queue_arn, queue_policy, eventbridge_targets, limit)
        if include_permission_checks
        else empty_permission_checks()
    )

    return {
        "queue_url": queue["queue_url"],
        "queue_name": queue["queue_name"],
        "queue_arn": queue_arn,
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


def _dead_letter_node(queue: dict[str, Any]) -> dict[str, Any] | None:
    dead_letter = queue.get("dead_letter")
    if not isinstance(dead_letter, dict) or not dead_letter.get("configured"):
        return None
    arn = dead_letter.get("dead_letter_target_arn")
    return {
        "queue_arn": arn,
        "queue_name": _queue_name_from_arn(arn) if isinstance(arn, str) else None,
        "max_receive_count": dead_letter.get("max_receive_count"),
    }


def _eventbridge_targets_for_queue(
    runtime: AwsRuntime,
    region: str,
    queue_arn: str,
    limit: int,
    warnings: list[str],
) -> list[dict[str, Any]]:
    client = runtime.client("events", region=region)
    try:
        bus_response = client.list_event_buses(Limit=min(limit, 100))
    except (BotoCoreError, ClientError) as exc:
        warning = normalize_aws_error(exc, "events.ListEventBuses")
        warnings.append(f"Unable to list EventBridge buses: {warning}")
        return []

    matches: list[dict[str, Any]] = []
    for bus in bus_response.get("EventBuses", []):
        if len(matches) >= limit:
            break
        bus_name = str(bus.get("Name") or "default")
        try:
            rule_response = client.list_rules(EventBusName=bus_name, Limit=min(limit, 100))
        except (BotoCoreError, ClientError) as exc:
            warning = normalize_aws_error(exc, "events.ListRules")
            warnings.append(f"Unable to list EventBridge rules on {bus_name}: {warning}")
            continue
        for rule in rule_response.get("Rules", []):
            if len(matches) >= limit:
                break
            rule_name = str(rule.get("Name") or "")
            if not rule_name:
                continue
            try:
                target_response = client.list_targets_by_rule(
                    Rule=rule_name,
                    EventBusName=bus_name,
                    Limit=min(limit, 100),
                )
            except (BotoCoreError, ClientError) as exc:
                warning = normalize_aws_error(exc, "events.ListTargetsByRule")
                warnings.append(f"Unable to list EventBridge targets for {rule_name}: {warning}")
                continue
            for target in target_response.get("Targets", []):
                if target.get("Arn") == queue_arn:
                    matches.append(_eventbridge_target_node(bus_name, rule, target))
                    if len(matches) >= limit:
                        break
    return matches


def _eventbridge_target_node(
    bus_name: str,
    rule: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    return {
        "event_bus_name": bus_name,
        "rule_name": rule.get("Name"),
        "rule_arn": rule.get("Arn"),
        "state": rule.get("State"),
        "target_id": target.get("Id"),
        "target_arn": target.get("Arn"),
        "role_arn": target.get("RoleArn"),
        "dead_letter_arn": (target.get("DeadLetterConfig") or {}).get("Arn"),
    }


def _lambda_mappings_for_queue(
    runtime: AwsRuntime,
    region: str,
    queue_arn: str,
    limit: int,
    warnings: list[str],
) -> list[dict[str, Any]]:
    client = runtime.client("lambda", region=region)
    try:
        response = client.list_event_source_mappings(
            EventSourceArn=queue_arn,
            MaxItems=min(limit, 100),
        )
    except (BotoCoreError, ClientError) as exc:
        warning = normalize_aws_error(exc, "lambda.ListEventSourceMappings")
        warnings.append(f"Unable to list Lambda event source mappings: {warning}")
        return []
    return [
        {
            "uuid": mapping.get("UUID"),
            "state": mapping.get("State"),
            "function_arn": mapping.get("FunctionArn"),
            "function_name": _lambda_name_from_arn(mapping.get("FunctionArn")),
            "event_source_arn": mapping.get("EventSourceArn"),
            "batch_size": mapping.get("BatchSize"),
        }
        for mapping in response.get("EventSourceMappings", [])[:limit]
    ]


def _queue_policy_document(
    runtime: AwsRuntime,
    region: str,
    queue_url: str,
    warnings: list[str],
) -> dict[str, Any] | None:
    client = runtime.client("sqs", region=region)
    try:
        response = client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["Policy"],
        )
    except (BotoCoreError, ClientError) as exc:
        warning = normalize_aws_error(exc, "sqs.GetQueueAttributes")
        warnings.append(f"Unable to read queue policy for permission checks: {warning}")
        return None
    raw_policy = response.get("Attributes", {}).get("Policy")
    if not raw_policy:
        return None
    try:
        policy = json.loads(str(raw_policy))
    except json.JSONDecodeError:
        warnings.append("Unable to parse queue policy for permission checks")
        return None
    return policy if isinstance(policy, dict) else None


def _sqs_dependency_edges(
    queue: dict[str, Any],
    eventbridge_targets: list[dict[str, Any]],
    lambda_mappings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    queue_arn = str(queue["queue_arn"])
    edges: list[dict[str, Any]] = []
    dead_letter = queue.get("dead_letter")
    if isinstance(dead_letter, dict) and dead_letter.get("dead_letter_target_arn"):
        edges.append(
            {
                "source": queue_arn,
                "target": dead_letter["dead_letter_target_arn"],
                "relationship": "redrives_to",
                "target_type": "sqs",
            }
        )
    for target in eventbridge_targets:
        edges.append(
            {
                "source": target.get("rule_arn") or target.get("rule_name"),
                "target": queue_arn,
                "relationship": "routes_to",
                "target_type": "sqs",
            }
        )
    for mapping in lambda_mappings:
        edges.append(
            {
                "source": queue_arn,
                "target": mapping.get("function_arn") or mapping.get("function_name"),
                "relationship": "triggers",
                "target_type": "lambda",
            }
        )
    return edges


def _sqs_permission_hints(
    queue_arn: str,
    eventbridge_targets: list[dict[str, Any]],
    lambda_mappings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for target in eventbridge_targets:
        hints.append(
            {
                "principal": target.get("role_arn") or "events.amazonaws.com",
                "action": "sqs:SendMessage",
                "resource": queue_arn,
                "reason": "EventBridge target delivery to SQS requires SendMessage.",
            }
        )
    for mapping in lambda_mappings:
        hints.append(
            {
                "principal": "lambda_execution_role",
                "actions": [
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                ],
                "resource": queue_arn,
                "reason": f"Lambda event source mapping {mapping.get('uuid')} polls this queue.",
            }
        )
    return hints


def _sqs_permission_checks(
    queue_arn: str,
    policy: dict[str, Any] | None,
    eventbridge_targets: list[dict[str, Any]],
    limit: int,
) -> dict[str, Any]:
    checks = []
    for target in eventbridge_targets[:limit]:
        checks.append(
            {
                "principal": target.get("role_arn") or "events.amazonaws.com",
                "action": "sqs:SendMessage",
                "resource": queue_arn,
                "decision": _queue_policy_decision(
                    policy,
                    "events.amazonaws.com",
                    "sqs:SendMessage",
                ),
                "source": "queue_policy",
                "context": {
                    "rule_name": target.get("rule_name"),
                    "event_bus_name": target.get("event_bus_name"),
                },
            }
        )
    return {
        "enabled": True,
        "checked_count": len(checks),
        "checks": checks,
        "summary": _permission_summary(checks),
    }
def _queue_policy_decision(policy: dict[str, Any] | None, service: str, action: str) -> str:
    if policy is None:
        return "unknown"
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements if isinstance(statements, list) else []:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if _principal_matches(statement.get("Principal"), service) and _action_matches(
            statement.get("Action"),
            action,
        ):
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
        return actions in {action, "sqs:*", "*"}
    if isinstance(actions, list):
        return action in actions or "sqs:*" in actions or "*" in actions
    return False


def _permission_summary(checks: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "allowed": sum(1 for check in checks if check["decision"] == "allowed"),
        "denied": sum(1 for check in checks if check["decision"] == "denied"),
        "unknown": sum(1 for check in checks if check["decision"] == "unknown"),
        "explicit_denies": sum(1 for check in checks if check["decision"] == "explicit_deny"),
    }


def _queue_name_from_arn(value: str) -> str:
    return value.rsplit(":", 1)[-1]


def _lambda_name_from_arn(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return value.rsplit(":", 1)[-1]


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
