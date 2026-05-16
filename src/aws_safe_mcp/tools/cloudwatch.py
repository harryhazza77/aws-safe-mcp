from __future__ import annotations

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
    request: dict[str, Any] = {"limit": min(limit, 50)}
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


def cloudwatch_log_search(
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


def cloudwatch_logs_insights_query(
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
        response = client.get_query_results(queryId=query_id) if query_id else {}
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
    request: dict[str, Any] = {"MaxRecords": min(limit, 100)}
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


def _log_group_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "log_group_name": item.get("logGroupName"),
        "arn": item.get("arn"),
        "creation_time": isoformat(_millis_to_datetime(item.get("creationTime"))),
        "retention_days": item.get("retentionInDays"),
        "stored_bytes": item.get("storedBytes"),
    }


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


def _millis_to_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value) / 1000, tz=UTC)
    except (TypeError, ValueError, OSError):
        return None
