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


def _require_query(query: str) -> str:
    normalized = query.strip()
    if not normalized:
        raise ToolInputError("query is required")
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


def _millis_to_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value) / 1000, tz=UTC)
    except (TypeError, ValueError, OSError):
        return None
