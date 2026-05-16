from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
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
            "oldest_age_seconds": _int_attribute(attributes, "ApproximateAgeOfOldestMessage"),
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


def investigate_sqs_backlog_stall(
    runtime: AwsRuntime,
    queue_url: str,
    region: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    queue = get_sqs_queue_summary(runtime, queue_url, region=resolved_region)
    queue_arn = queue.get("queue_arn")
    if not isinstance(queue_arn, str) or not queue_arn:
        raise ToolInputError("queue does not expose QueueArn")
    limit = clamp_limit(
        max_results,
        default=20,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    warnings: list[str] = []
    mappings = _lambda_mappings_for_queue(runtime, resolved_region, queue_arn, limit, warnings)
    diagnostics = [
        _sqs_lambda_mapping_delivery_diagnostic(runtime, resolved_region, queue, mapping, warnings)
        for mapping in mappings
    ]
    throttles = [
        _lambda_throttle_signal(runtime, resolved_region, diagnostic, warnings)
        for diagnostic in diagnostics
    ]
    signals = _sqs_backlog_stall_signals(queue, diagnostics, throttles)
    return {
        "queue_url": queue["queue_url"],
        "queue_name": queue["queue_name"],
        "queue_arn": queue_arn,
        "region": resolved_region,
        "summary": _sqs_backlog_stall_summary(signals),
        "queue": queue,
        "lambda_mappings": diagnostics,
        "lambda_throttle_signals": throttles,
        "signals": signals,
        "suggested_next_checks": _sqs_backlog_stall_next_checks(signals),
        "warnings": warnings,
    }


def check_sqs_to_lambda_delivery(
    runtime: AwsRuntime,
    queue_url: str,
    region: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    queue = get_sqs_queue_summary(runtime, queue_url, region=resolved_region)
    queue_arn = queue.get("queue_arn")
    if not isinstance(queue_arn, str) or not queue_arn:
        raise ToolInputError("queue does not expose QueueArn")
    limit = clamp_limit(
        max_results,
        default=20,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    warnings: list[str] = []
    mappings = _lambda_mappings_for_queue(runtime, resolved_region, queue_arn, limit, warnings)
    diagnostics = [
        _sqs_lambda_mapping_delivery_diagnostic(runtime, resolved_region, queue, mapping, warnings)
        for mapping in mappings
    ]
    signals = _sqs_lambda_delivery_signals(queue, diagnostics)
    return {
        "queue_url": queue["queue_url"],
        "queue_name": queue["queue_name"],
        "queue_arn": queue_arn,
        "region": resolved_region,
        "summary": _sqs_lambda_delivery_summary(signals),
        "queue": queue,
        "mappings": diagnostics,
        "signals": signals,
        "suggested_next_checks": _sqs_lambda_delivery_next_checks(signals),
        "warnings": warnings,
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
            "maximum_batching_window_seconds": mapping.get("MaximumBatchingWindowInSeconds"),
            "function_response_types": mapping.get("FunctionResponseTypes", []),
            "scaling_config": mapping.get("ScalingConfig") or {},
            "destination_config": mapping.get("DestinationConfig") or {},
        }
        for mapping in response.get("EventSourceMappings", [])[:limit]
    ]


def _sqs_lambda_mapping_delivery_diagnostic(
    runtime: AwsRuntime,
    region: str,
    queue: dict[str, Any],
    mapping: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    function_name = str(mapping.get("function_name") or mapping.get("function_arn") or "")
    function_config = _lambda_function_config(runtime, region, function_name, warnings)
    lambda_timeout = _optional_int(function_config.get("Timeout"))
    visibility_timeout = queue.get("visibility_timeout_seconds")
    timeout_ratio_ok = (
        None
        if lambda_timeout is None or visibility_timeout is None
        else visibility_timeout >= lambda_timeout * 6
    )
    partial_batch_response = "ReportBatchItemFailures" in (
        mapping.get("function_response_types") or []
    )
    return {
        **mapping,
        "lambda_timeout_seconds": lambda_timeout,
        "timeout_ratio_ok": timeout_ratio_ok,
        "partial_batch_response_enabled": partial_batch_response,
        "failure_destination_configured": bool(mapping.get("destination_config")),
        "maximum_concurrency": (mapping.get("scaling_config") or {}).get("MaximumConcurrency"),
        "delivery_risks": _sqs_lambda_mapping_risks(
            mapping,
            timeout_ratio_ok=timeout_ratio_ok,
            partial_batch_response=partial_batch_response,
            queue=queue,
        ),
    }


def _lambda_function_config(
    runtime: AwsRuntime,
    region: str,
    function_name: str,
    warnings: list[str],
) -> dict[str, Any]:
    if not function_name:
        return {}
    client = runtime.client("lambda", region=region)
    try:
        response = client.get_function_configuration(FunctionName=function_name)
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "lambda.GetFunctionConfiguration")))
        return {}
    return response if isinstance(response, dict) else {}


def _sqs_lambda_mapping_risks(
    mapping: dict[str, Any],
    *,
    timeout_ratio_ok: bool | None,
    partial_batch_response: bool,
    queue: dict[str, Any],
) -> list[str]:
    risks = []
    if str(mapping.get("state") or "").lower() != "enabled":
        risks.append("event_source_mapping_not_enabled")
    if timeout_ratio_ok is False:
        risks.append("visibility_timeout_too_low_for_lambda_timeout")
    if not partial_batch_response and (mapping.get("batch_size") or 0) > 1:
        risks.append("partial_batch_response_not_enabled")
    dead_letter = queue.get("dead_letter")
    if not isinstance(dead_letter, dict) or not dead_letter.get("configured"):
        risks.append("queue_redrive_not_configured")
    return risks


def _sqs_lambda_delivery_signals(
    queue: dict[str, Any],
    diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    risks = [risk for diagnostic in diagnostics for risk in diagnostic["delivery_risks"]]
    return {
        "mapping_count": len(diagnostics),
        "enabled_mapping_count": sum(
            1
            for diagnostic in diagnostics
            if str(diagnostic.get("state") or "").lower() == "enabled"
        ),
        "queue_redrive_configured": bool((queue.get("dead_letter") or {}).get("configured")),
        "visibility_timeout_seconds": queue.get("visibility_timeout_seconds"),
        "risk_count": len(risks),
        "risks": sorted(set(risks)),
    }


def _sqs_lambda_delivery_summary(signals: dict[str, Any]) -> dict[str, Any]:
    if signals["mapping_count"] == 0:
        status = "no_lambda_mapping"
    elif signals["risk_count"]:
        status = "needs_attention"
    else:
        status = "ready"
    return {
        "status": status,
        "mapping_count": signals["mapping_count"],
        "risk_count": signals["risk_count"],
    }


def _sqs_lambda_delivery_next_checks(signals: dict[str, Any]) -> list[str]:
    checks = []
    if signals["mapping_count"] == 0:
        checks.append("Create or enable a Lambda event source mapping for this queue.")
    if "visibility_timeout_too_low_for_lambda_timeout" in signals["risks"]:
        checks.append("Increase queue visibility timeout or reduce Lambda timeout.")
    if "partial_batch_response_not_enabled" in signals["risks"]:
        checks.append("Consider ReportBatchItemFailures for batched SQS Lambda consumers.")
    if "queue_redrive_not_configured" in signals["risks"]:
        checks.append("Configure a DLQ/redrive policy for poison messages.")
    if not checks:
        checks.append("No obvious static SQS-to-Lambda delivery blocker found.")
    return checks


def _lambda_throttle_signal(
    runtime: AwsRuntime,
    region: str,
    diagnostic: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    function_name = str(diagnostic.get("function_name") or "")
    if not function_name:
        return {"function_name": None, "throttles_last_hour": None}
    try:
        cloudwatch = runtime.client("cloudwatch", region=region)
        end = datetime.now(UTC)
        start = end - timedelta(hours=1)
        response = cloudwatch.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "throttles",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/Lambda",
                            "MetricName": "Throttles",
                            "Dimensions": [{"Name": "FunctionName", "Value": function_name}],
                        },
                        "Period": 300,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                }
            ],
            StartTime=start,
            EndTime=end,
        )
    except Exception as exc:  # noqa: BLE001 - stall analysis is best-effort
        warnings.append(f"cloudwatch lambda throttles unavailable for {function_name}: {exc}")
        return {"function_name": function_name, "throttles_last_hour": None}
    values = [
        float(value)
        for item in response.get("MetricDataResults", [])
        for value in item.get("Values", [])
    ]
    return {"function_name": function_name, "throttles_last_hour": sum(values)}


def _sqs_backlog_stall_signals(
    queue: dict[str, Any],
    diagnostics: list[dict[str, Any]],
    throttles: list[dict[str, Any]],
) -> dict[str, Any]:
    counts = queue.get("message_counts") or {}
    available = int(counts.get("available") or 0)
    in_flight = int(counts.get("in_flight") or 0)
    oldest_age = int(counts.get("oldest_age_seconds") or 0)
    risks = [risk for diagnostic in diagnostics for risk in diagnostic["delivery_risks"]]
    if available > 0 and not diagnostics:
        risks.append("messages_available_but_no_lambda_mapping")
    if oldest_age >= 300:
        risks.append("oldest_message_age_high")
    if any((item.get("throttles_last_hour") or 0) > 0 for item in throttles):
        risks.append("lambda_throttles_observed")
    return {
        "available_messages": available,
        "in_flight_messages": in_flight,
        "oldest_message_age_seconds": oldest_age,
        "mapping_count": len(diagnostics),
        "enabled_mapping_count": sum(
            1
            for diagnostic in diagnostics
            if str(diagnostic.get("state") or "").lower() == "enabled"
        ),
        "risk_count": len(risks),
        "risks": sorted(set(risks)),
    }


def _sqs_backlog_stall_summary(signals: dict[str, Any]) -> dict[str, Any]:
    first = _first_sqs_backlog_bottleneck(signals["risks"])
    return {
        "status": "stall_signals_detected" if signals["risk_count"] else "no_stall_signals",
        "first_likely_bottleneck": first,
        "risk_count": signals["risk_count"],
    }


def _first_sqs_backlog_bottleneck(risks: list[str]) -> str | None:
    priority = [
        "messages_available_but_no_lambda_mapping",
        "event_source_mapping_not_enabled",
        "lambda_throttles_observed",
        "visibility_timeout_too_low_for_lambda_timeout",
        "oldest_message_age_high",
        "partial_batch_response_not_enabled",
        "queue_redrive_not_configured",
    ]
    risk_set = set(risks)
    for risk in priority:
        if risk in risk_set:
            return risk
    return risks[0] if risks else None


def _sqs_backlog_stall_next_checks(signals: dict[str, Any]) -> list[str]:
    checks = []
    if "messages_available_but_no_lambda_mapping" in signals["risks"]:
        checks.append("Create or enable a Lambda event source mapping for the queue.")
    if "event_source_mapping_not_enabled" in signals["risks"]:
        checks.append("Enable or repair disabled Lambda event source mappings.")
    if "oldest_message_age_high" in signals["risks"]:
        checks.append("Inspect queue age/backlog and consumer throughput.")
    if "lambda_throttles_observed" in signals["risks"]:
        checks.append("Inspect Lambda concurrency limits and throttles.")
    if "visibility_timeout_too_low_for_lambda_timeout" in signals["risks"]:
        checks.append("Increase visibility timeout or reduce Lambda timeout.")
    if not checks:
        checks.append("No static SQS backlog stall signal found.")
    return checks


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
