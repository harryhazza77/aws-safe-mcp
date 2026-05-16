from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.config import RedactionConfig
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.redaction import redact_text
from aws_safe_mcp.tools.common import (
    bounded_filter_log_events,
    clamp_limit,
    clamp_since_minutes,
    compact_log_message,
    isoformat,
    log_event_groups,
    page_size,
    require_log_group_name,
    resolve_region,
)


def list_cloudwatch_log_groups(
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
    client = runtime.client("logs", region=resolved_region)
    request: dict[str, Any] = {"limit": page_size("logs.DescribeLogGroups", limit)}
    if name_prefix:
        request["logGroupNamePrefix"] = name_prefix

    groups: list[dict[str, Any]] = []
    next_token: str | None = None
    try:
        while len(groups) < limit:
            page_request = dict(request)
            if next_token:
                page_request["nextToken"] = next_token
            response = client.describe_log_groups(**page_request)
            for item in response.get("logGroups", []):
                groups.append(_log_group_summary(item))
                if len(groups) >= limit:
                    break
            next_token = response.get("nextToken")
            if not next_token:
                break
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "logs.DescribeLogGroups") from exc

    return {
        "region": resolved_region,
        "name_prefix": name_prefix,
        "max_results": limit,
        "count": len(groups),
        "is_truncated": bool(next_token),
        "log_groups": groups,
    }


def search_cloudwatch_logs(
    runtime: AwsRuntime,
    log_group_name: str,
    query: str,
    since_minutes: int | None = 60,
    max_results: int | None = 50,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_log_group = require_log_group_name(log_group_name)
    filter_pattern = _require_query(query)
    window_minutes = clamp_since_minutes(
        since_minutes,
        default=60,
        configured_max=runtime.config.max_since_minutes,
    )
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    client = runtime.client("logs", region=resolved_region)
    end = datetime.now(UTC)
    start = end - timedelta(minutes=window_minutes)
    request = {
        "logGroupName": required_log_group,
        "startTime": int(start.timestamp() * 1000),
        "endTime": int(end.timestamp() * 1000),
        "filterPattern": filter_pattern,
    }

    try:
        raw_events = bounded_filter_log_events(client, request, limit)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "logs.FilterLogEvents") from exc

    events = [
        _event_summary(event, runtime.config.redaction.max_string_length) for event in raw_events
    ]
    return {
        "log_group_name": required_log_group,
        "region": resolved_region,
        "query": filter_pattern,
        "window_minutes": window_minutes,
        "count": len(events),
        "groups": log_event_groups(events),
        "events": events,
    }


def query_cloudwatch_logs_insights(
    runtime: AwsRuntime,
    log_group_name: str,
    query: str,
    since_minutes: int | None = 60,
    max_results: int | None = 50,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_log_group = require_log_group_name(log_group_name)
    query_string = _require_logs_insights_query(query)
    window_minutes = clamp_since_minutes(
        since_minutes,
        default=60,
        configured_max=runtime.config.max_since_minutes,
    )
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    client = runtime.client("logs", region=resolved_region)
    end = datetime.now(UTC)
    start = end - timedelta(minutes=window_minutes)
    try:
        started = client.start_query(
            logGroupName=required_log_group,
            startTime=int(start.timestamp()),
            endTime=int(end.timestamp()),
            queryString=query_string,
            limit=limit,
        )
        query_id = str(started.get("queryId") or "")
        response = (
            _poll_logs_insights_query(client, query_id) if query_id else {}
        )
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "logs.StartQuery") from exc

    results = _logs_insights_results(
        response.get("results", []),
        runtime.config.redaction.max_string_length,
        limit,
    )
    return {
        "log_group_name": required_log_group,
        "region": resolved_region,
        "query": query_string,
        "query_id": query_id,
        "status": response.get("status", "Unknown"),
        "window_minutes": window_minutes,
        "count": len(results),
        "results": results,
        "statistics": _logs_insights_statistics(response.get("statistics")),
    }


# Bounded poll budget for `query_cloudwatch_logs_insights`. We sleep up to
# ~6 seconds (12 * 0.5s) so most short queries return a terminal status
# (Complete / Failed / Cancelled / Timeout) in one tool call; longer
# queries return the most recent intermediate status and the `query_id`
# so callers can re-poll without re-issuing the query.
_LOGS_INSIGHTS_POLL_INTERVAL_SECONDS = 0.5
_LOGS_INSIGHTS_POLL_MAX_ATTEMPTS = 12
_LOGS_INSIGHTS_TERMINAL_STATUSES = {"Complete", "Failed", "Cancelled", "Timeout"}


def _poll_logs_insights_query(client: Any, query_id: str) -> dict[str, Any]:
    response: dict[str, Any] = {}
    for attempt in range(_LOGS_INSIGHTS_POLL_MAX_ATTEMPTS):
        response = client.get_query_results(queryId=query_id)
        status = str(response.get("status") or "")
        if status in _LOGS_INSIGHTS_TERMINAL_STATUSES:
            return response
        if attempt < _LOGS_INSIGHTS_POLL_MAX_ATTEMPTS - 1:
            time.sleep(_LOGS_INSIGHTS_POLL_INTERVAL_SECONDS)
    return response


def check_cloudwatch_logs_writeability(
    runtime: AwsRuntime,
    log_group_name: str,
    role_arn: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_log_group = require_log_group_name(log_group_name)
    required_role_arn = _require_role_arn(role_arn)
    logs = runtime.client("logs", region=resolved_region)
    warnings: list[str] = []
    log_group = _find_log_group(logs, required_log_group, warnings)
    log_group_arn = _log_group_write_arn(log_group, required_log_group, resolved_region)
    permission_checks = _logs_write_permission_checks(
        runtime=runtime,
        role_arn=required_role_arn,
        log_group_arn=log_group_arn,
        warnings=warnings,
    )
    return {
        "log_group_name": required_log_group,
        "region": resolved_region,
        "role_arn": required_role_arn,
        "summary": {
            "log_group_exists": log_group is not None,
            "retention_days": log_group.get("retention_days") if log_group else None,
            "kms_key_configured": bool(log_group.get("kms_key_id")) if log_group else None,
            "write_allowed": _logs_write_allowed(permission_checks),
        },
        "log_group": log_group,
        "permission_checks": permission_checks,
        "warnings": warnings,
    }


def list_cloudwatch_alarms(
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
    client = runtime.client("cloudwatch", region=resolved_region)
    request: dict[str, Any] = {"MaxRecords": page_size("cloudwatch.DescribeAlarms", limit)}
    if name_prefix:
        request["AlarmNamePrefix"] = name_prefix

    alarms: list[dict[str, Any]] = []
    next_token: str | None = None
    try:
        while len(alarms) < limit:
            page_request = dict(request)
            if next_token:
                page_request["NextToken"] = next_token
            response = client.describe_alarms(**page_request)
            for item in response.get("MetricAlarms", []):
                alarms.append(_metric_alarm_summary(item))
                if len(alarms) >= limit:
                    break
            if len(alarms) < limit:
                for item in response.get("CompositeAlarms", []):
                    alarms.append(_composite_alarm_summary(item))
                    if len(alarms) >= limit:
                        break
            next_token = response.get("NextToken")
            if not next_token:
                break
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "cloudwatch.DescribeAlarms") from exc

    return {
        "region": resolved_region,
        "name_prefix": name_prefix,
        "max_results": limit,
        "count": len(alarms),
        "is_truncated": bool(next_token),
        "summary": _alarm_inventory_summary(alarms),
        "alarms": alarms,
    }


def get_cloudwatch_alarm_summary(
    runtime: AwsRuntime,
    alarm_name: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_alarm_name = _require_alarm_name(alarm_name)
    client = runtime.client("cloudwatch", region=resolved_region)
    try:
        response = client.describe_alarms(AlarmNames=[required_alarm_name])
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "cloudwatch.DescribeAlarms") from exc

    alarm: dict[str, Any] | None
    metric_alarms = response.get("MetricAlarms", [])
    if metric_alarms:
        alarm = _metric_alarm_summary(metric_alarms[0])
    else:
        composite_alarms = response.get("CompositeAlarms", [])
        alarm = _composite_alarm_summary(composite_alarms[0]) if composite_alarms else None

    return {
        "region": resolved_region,
        "alarm_name": required_alarm_name,
        "found": alarm is not None,
        "alarm": alarm,
    }


def find_cloudwatch_alarm_coverage_gaps(
    runtime: AwsRuntime,
    resource_type: str,
    resource_name: str,
    region: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    normalized_type = _require_alarm_coverage_resource_type(resource_type)
    normalized_name = _require_alarm_coverage_resource_name(resource_name)
    limit = clamp_limit(
        max_results,
        default=100,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    alarms = _list_metric_alarms_for_coverage(runtime, resolved_region, limit)
    expected = _expected_alarm_coverages(normalized_type, normalized_name)
    coverage = [
        _alarm_coverage_item(requirement, alarms)
        for requirement in expected
    ]
    missing = [item for item in coverage if not item["covered"]]
    weak = [item for item in coverage if item["covered"] and item["actionless_alarm_names"]]
    return {
        "resource_type": normalized_type,
        "resource_name": normalized_name,
        "region": resolved_region,
        "summary": {
            "status": "gaps_found" if missing else "covered",
            "expected_count": len(expected),
            "covered_count": len(expected) - len(missing),
            "missing_count": len(missing),
            "weak_action_count": len(weak),
        },
        "coverage": coverage,
        "missing": missing,
        "suggested_next_checks": _alarm_coverage_next_checks(missing, weak),
    }


def _require_query(query: str) -> str:
    normalized = query.strip()
    if not normalized:
        raise ToolInputError("query is required")
    return normalized


def _require_logs_insights_query(query: str) -> str:
    normalized = _require_query(query)
    lowered = normalized.lower()
    if "source " in lowered or lowered.startswith("source"):
        raise ToolInputError("query must target the provided log_group_name, not SOURCE")
    if "unmask" in lowered:
        raise ToolInputError("query must not use unmask")
    return normalized


def _require_alarm_name(alarm_name: str) -> str:
    normalized = alarm_name.strip()
    if not normalized:
        raise ToolInputError("alarm_name is required")
    return normalized


def _require_alarm_coverage_resource_type(resource_type: str) -> str:
    normalized = resource_type.strip().lower().replace("-", "_")
    allowed = {"lambda", "sqs", "eventbridge_rule", "apigateway_route"}
    if normalized not in allowed:
        raise ToolInputError(
            "resource_type must be one of lambda, sqs, eventbridge_rule, apigateway_route"
        )
    return normalized


def _require_alarm_coverage_resource_name(resource_name: str) -> str:
    normalized = resource_name.strip()
    if not normalized:
        raise ToolInputError("resource_name is required")
    return normalized


def _require_role_arn(role_arn: str) -> str:
    normalized = role_arn.strip()
    if not normalized:
        raise ToolInputError("role_arn is required")
    if not re.fullmatch(r"arn:aws[a-zA-Z-]*:iam::\d{12}:role/.+", normalized):
        raise ToolInputError("role_arn must be an IAM role ARN")
    return normalized


def _log_group_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "log_group_name": item.get("logGroupName"),
        "arn": item.get("arn"),
        "creation_time": isoformat(_millis_to_datetime(item.get("creationTime"))),
        "retention_days": item.get("retentionInDays"),
        "kms_key_id": item.get("kmsKeyId") or None,
        "stored_bytes": item.get("storedBytes"),
    }


def _find_log_group(
    client: Any,
    log_group_name: str,
    warnings: list[str],
) -> dict[str, Any] | None:
    try:
        response = client.describe_log_groups(logGroupNamePrefix=log_group_name, limit=5)
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "logs.DescribeLogGroups")))
        return None
    for item in response.get("logGroups", []):
        if item.get("logGroupName") == log_group_name:
            return _log_group_summary(item)
    return None


def _log_group_write_arn(
    log_group: dict[str, Any] | None,
    log_group_name: str,
    region: str,
) -> str:
    arn = str((log_group or {}).get("arn") or "")
    if arn:
        return arn if arn.endswith(":*") else f"{arn}:*"
    return f"arn:aws:logs:{region}:*:log-group:{log_group_name}:*"


def _logs_write_permission_checks(
    runtime: AwsRuntime,
    role_arn: str,
    log_group_arn: str,
    warnings: list[str],
) -> dict[str, Any]:
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    checks = []
    try:
        iam = runtime.client("iam", region=runtime.region)
        response = iam.simulate_principal_policy(
            PolicySourceArn=role_arn,
            ActionNames=actions,
            ResourceArns=[log_group_arn],
        )
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "iam.SimulatePrincipalPolicy")))
        return {
            "enabled": True,
            "checked_count": len(actions),
            "summary": {"allowed": 0, "denied": 0, "unknown": len(actions)},
            "checks": [
                {
                    "principal": role_arn,
                    "action": action,
                    "resource": log_group_arn,
                    "decision": "unknown",
                }
                for action in actions
            ],
        }
    for result in response.get("EvaluationResults", []):
        decision = str(result.get("EvalDecision") or "unknown").lower()
        checks.append(
            {
                "principal": role_arn,
                "action": result.get("EvalActionName"),
                "resource": log_group_arn,
                "decision": "allowed" if decision == "allowed" else decision,
            }
        )
    return {
        "enabled": True,
        "checked_count": len(checks),
        "summary": _permission_summary(checks),
        "checks": checks,
    }


def _permission_summary(checks: list[dict[str, Any]]) -> dict[str, int]:
    allowed = sum(1 for check in checks if check.get("decision") == "allowed")
    unknown = sum(1 for check in checks if check.get("decision") == "unknown")
    return {"allowed": allowed, "denied": len(checks) - allowed - unknown, "unknown": unknown}


def _logs_write_allowed(permission_checks: dict[str, Any]) -> bool | None:
    summary = permission_checks.get("summary", {})
    if summary.get("unknown"):
        return None
    return bool(permission_checks.get("checked_count")) and summary.get("denied") == 0


def _event_summary(event: dict[str, Any], max_string_length: int) -> dict[str, Any]:
    message = compact_log_message(str(event.get("message", "")))
    redacted = redact_text(message, RedactionConfig(max_string_length=max_string_length))
    return {
        "timestamp": isoformat(_millis_to_datetime(event.get("timestamp"))),
        "log_stream_name": event.get("logStreamName"),
        "message": redacted,
        "truncated": len(message) > max_string_length or len(redacted) > max_string_length,
    }


def _logs_insights_results(
    rows: Any,
    max_string_length: int,
    limit: int,
) -> list[dict[str, str]]:
    if not isinstance(rows, list):
        return []
    results = []
    for row in rows[:limit]:
        if not isinstance(row, list):
            continue
        result: dict[str, str] = {}
        for cell in row:
            if not isinstance(cell, dict):
                continue
            field = str(cell.get("field") or "")
            if not field or field.startswith("@ptr"):
                continue
            value = compact_log_message(str(cell.get("value") or ""))
            result[field] = redact_text(value, RedactionConfig(max_string_length=max_string_length))
        results.append(result)
    return results


def _logs_insights_statistics(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "records_matched": value.get("recordsMatched"),
        "records_scanned": value.get("recordsScanned"),
        "bytes_scanned": value.get("bytesScanned"),
    }


def _metric_alarm_summary(item: dict[str, Any]) -> dict[str, Any]:
    dimensions = _metric_dimensions(item.get("Dimensions"))
    return {
        "type": "metric",
        "alarm_name": item.get("AlarmName"),
        "alarm_arn": item.get("AlarmArn"),
        "state_value": item.get("StateValue"),
        "state_updated": isoformat(item.get("StateUpdatedTimestamp")),
        "actions_enabled": item.get("ActionsEnabled"),
        "alarm_action_count": len(item.get("AlarmActions", [])),
        "ok_action_count": len(item.get("OKActions", [])),
        "insufficient_data_action_count": len(item.get("InsufficientDataActions", [])),
        "namespace": item.get("Namespace"),
        "metric_name": item.get("MetricName"),
        "dimensions": dimensions,
        "statistic": item.get("Statistic") or item.get("ExtendedStatistic"),
        "period_seconds": item.get("Period"),
        "evaluation_periods": item.get("EvaluationPeriods"),
        "datapoints_to_alarm": item.get("DatapointsToAlarm"),
        "threshold": item.get("Threshold"),
        "comparison_operator": item.get("ComparisonOperator"),
        "treat_missing_data": item.get("TreatMissingData"),
        "inferred_resources": _alarm_inferred_resources(item.get("Namespace"), dimensions),
    }


def _composite_alarm_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "composite",
        "alarm_name": item.get("AlarmName"),
        "alarm_arn": item.get("AlarmArn"),
        "state_value": item.get("StateValue"),
        "state_updated": isoformat(item.get("StateUpdatedTimestamp")),
        "actions_enabled": item.get("ActionsEnabled"),
        "alarm_action_count": len(item.get("AlarmActions", [])),
        "ok_action_count": len(item.get("OKActions", [])),
        "insufficient_data_action_count": len(item.get("InsufficientDataActions", [])),
        "alarm_rule_present": bool(item.get("AlarmRule")),
        "inferred_resources": [],
    }


def _metric_dimensions(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    dimensions = []
    for item in value:
        if not isinstance(item, dict):
            continue
        dimensions.append(
            {"name": str(item.get("Name") or ""), "value": str(item.get("Value") or "")}
        )
    return dimensions


def _alarm_inferred_resources(
    namespace: Any,
    dimensions: list[dict[str, str]],
) -> list[dict[str, str]]:
    service = _alarm_namespace_service(namespace)
    resources = []
    for dimension in dimensions:
        resource_type = _dimension_resource_type(service, dimension["name"])
        if resource_type:
            resources.append(
                {
                    "service": service,
                    "resource_type": resource_type,
                    "name": dimension["value"],
                }
            )
    return resources


def _alarm_namespace_service(namespace: Any) -> str:
    mapping = {
        "AWS/Lambda": "lambda",
        "AWS/ApiGateway": "apigateway",
        "AWS/States": "stepfunctions",
        "AWS/SQS": "sqs",
        "AWS/Events": "eventbridge",
    }
    return mapping.get(str(namespace), "unknown")


def _dimension_resource_type(service: str, dimension_name: str) -> str | None:
    by_service = {
        "lambda": {"FunctionName": "lambda_function"},
        "apigateway": {"ApiName": "api", "ApiId": "api", "Stage": "stage"},
        "stepfunctions": {"StateMachineArn": "state_machine", "ActivityArn": "activity"},
        "sqs": {"QueueName": "queue"},
        "eventbridge": {"RuleName": "rule"},
    }
    return by_service.get(service, {}).get(dimension_name)


def _alarm_inventory_summary(alarms: list[dict[str, Any]]) -> dict[str, Any]:
    states: dict[str, int] = {}
    services: dict[str, int] = {}
    for alarm in alarms:
        state = str(alarm.get("state_value") or "UNKNOWN")
        states[state] = states.get(state, 0) + 1
        for resource in alarm.get("inferred_resources", []):
            service = str(resource.get("service") or "unknown")
            services[service] = services.get(service, 0) + 1
    return {
        "by_state": states,
        "by_linked_service": services,
        "alarm_count": len(alarms),
    }


def _list_metric_alarms_for_coverage(
    runtime: AwsRuntime,
    region: str,
    limit: int,
) -> list[dict[str, Any]]:
    client = runtime.client("cloudwatch", region=region)
    alarms: list[dict[str, Any]] = []
    next_token: str | None = None
    try:
        while len(alarms) < limit:
            request: dict[str, Any] = {"MaxRecords": min(limit - len(alarms), 100)}
            if next_token:
                request["NextToken"] = next_token
            response = client.describe_alarms(**request)
            for item in response.get("MetricAlarms", []):
                alarms.append(_metric_alarm_summary(item))
                if len(alarms) >= limit:
                    break
            next_token = response.get("NextToken")
            if not next_token:
                break
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "cloudwatch.DescribeAlarms") from exc
    return alarms


def _expected_alarm_coverages(resource_type: str, resource_name: str) -> list[dict[str, Any]]:
    by_type = {
        "lambda": [
            ("errors", "AWS/Lambda", "Errors", {"FunctionName": resource_name}),
            ("throttles", "AWS/Lambda", "Throttles", {"FunctionName": resource_name}),
            ("duration", "AWS/Lambda", "Duration", {"FunctionName": resource_name}),
        ],
        "sqs": [
            (
                "backlog",
                "AWS/SQS",
                "ApproximateNumberOfMessagesVisible",
                {"QueueName": resource_name},
            ),
            (
                "oldest_message_age",
                "AWS/SQS",
                "ApproximateAgeOfOldestMessage",
                {"QueueName": resource_name},
            ),
            (
                "dlq_depth",
                "AWS/SQS",
                "ApproximateNumberOfMessagesVisible",
                {"QueueName": f"{resource_name}-dlq"},
            ),
        ],
        "eventbridge_rule": [
            ("failed_invocations", "AWS/Events", "FailedInvocations", {"RuleName": resource_name}),
            (
                "failed_to_dlq",
                "AWS/Events",
                "InvocationsFailedToBeSentToDLQ",
                {"RuleName": resource_name},
            ),
        ],
        "apigateway_route": [
            ("5xx_errors", "AWS/ApiGateway", "5XXError", {"ApiId": resource_name}),
            ("4xx_errors", "AWS/ApiGateway", "4XXError", {"ApiId": resource_name}),
            ("latency", "AWS/ApiGateway", "Latency", {"ApiId": resource_name}),
        ],
    }
    return [
        {
            "coverage": coverage,
            "namespace": namespace,
            "metric_name": metric_name,
            "suggested_dimensions": [
                {"name": name, "value": value} for name, value in dimensions.items()
            ],
        }
        for coverage, namespace, metric_name, dimensions in by_type[resource_type]
    ]


def _alarm_coverage_item(
    requirement: dict[str, Any],
    alarms: list[dict[str, Any]],
) -> dict[str, Any]:
    matches = [
        alarm
        for alarm in alarms
        if alarm.get("namespace") == requirement["namespace"]
        and alarm.get("metric_name") == requirement["metric_name"]
        and _alarm_has_dimensions(alarm, requirement["suggested_dimensions"])
    ]
    return {
        **requirement,
        "covered": bool(matches),
        "alarm_names": [str(alarm.get("alarm_name")) for alarm in matches],
        "actionless_alarm_names": [
            str(alarm.get("alarm_name"))
            for alarm in matches
            if not alarm.get("actions_enabled") or not alarm.get("alarm_action_count")
        ],
    }


def _alarm_has_dimensions(alarm: dict[str, Any], dimensions: list[dict[str, str]]) -> bool:
    alarm_dimensions = {
        str(item.get("name")): str(item.get("value")) for item in alarm.get("dimensions", [])
    }
    return all(alarm_dimensions.get(item["name"]) == item["value"] for item in dimensions)


def _alarm_coverage_next_checks(
    missing: list[dict[str, Any]],
    weak: list[dict[str, Any]],
) -> list[str]:
    checks = [
        f"Consider {item['coverage']} alarm on {item['namespace']} {item['metric_name']} "
        f"with dimensions {item['suggested_dimensions']}."
        for item in missing
    ]
    checks.extend(
        f"Review actions for existing {item['coverage']} alarm(s): "
        f"{', '.join(item['actionless_alarm_names'])}."
        for item in weak
    )
    if not checks:
        checks.append("No alarm coverage gaps found for the selected resource metadata.")
    return checks


def _millis_to_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value) / 1000, tz=UTC)
    except (TypeError, ValueError, OSError):
        return None
