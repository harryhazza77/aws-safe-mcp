from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.config import ConfigError
from aws_safe_mcp.errors import ToolInputError
from aws_safe_mcp.redaction import truncate_string


def resolve_region(runtime: AwsRuntime, region: str | None) -> str:
    return region or runtime.region


def clamp_limit(value: int | None, default: int, configured_max: int, label: str) -> int:
    if value is None:
        return min(default, configured_max)
    if value < 1:
        raise ToolInputError(f"{label} must be at least 1")
    return min(value, configured_max)


def clamp_since_minutes(value: int | None, default: int, configured_max: int) -> int:
    if value is None:
        return min(default, configured_max)
    if value < 1:
        raise ToolInputError("since_minutes must be at least 1")
    return min(value, configured_max)


def bounded_filter_log_events(
    client: Any,
    request: dict[str, Any],
    limit: int,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    next_token: str | None = None
    while len(events) < limit:
        page_request = dict(request)
        page_request["limit"] = limit - len(events)
        if next_token:
            page_request["nextToken"] = next_token
        response = client.filter_log_events(**page_request)
        events.extend(response.get("events", [])[: limit - len(events)])
        next_token = response.get("nextToken")
        if not next_token:
            break
    return events


def compact_log_message(message: str) -> str:
    return re.sub(r"\s+", " ", message).strip()


def log_event_groups(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for event in events:
        message = str(event.get("message") or "")
        fingerprint = log_message_fingerprint(message)
        group = grouped.setdefault(
            fingerprint,
            {
                "fingerprint": fingerprint,
                "count": 0,
                "first_timestamp": event.get("timestamp"),
                "last_timestamp": event.get("timestamp"),
                "sample_message": message,
            },
        )
        group["count"] += 1
        group["last_timestamp"] = event.get("timestamp")
    return sorted(grouped.values(), key=lambda item: int(item["count"]), reverse=True)


def log_message_fingerprint(message: str) -> str:
    compact = compact_log_message(message)
    compact = re.sub(r"\s+Traceback\b.*$", "", compact, flags=re.IGNORECASE)
    compact = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", compact, flags=re.IGNORECASE)
    compact = re.sub(r"\b\d+\b", "<num>", compact)
    return compact[:240]


def require_lambda_name(function_name: str) -> str:
    if not function_name.strip():
        raise ToolInputError("function_name is required")
    return function_name


def require_log_group_name(log_group_name: str) -> str:
    if not log_group_name.strip():
        raise ToolInputError("log_group_name is required")
    return log_group_name


def require_bucket_name(bucket: str) -> str:
    if not bucket.strip():
        raise ToolInputError("bucket is required")
    return bucket


def require_dynamodb_table_name(table_name: str) -> str:
    if not table_name.strip():
        raise ToolInputError("table_name is required")
    return table_name


def require_step_function_name(state_machine_name: str) -> str:
    if not state_machine_name.strip():
        raise ToolInputError("state_machine_name is required")
    return state_machine_name


def parse_step_functions_execution_arn(execution_arn: str) -> dict[str, str]:
    match = re.fullmatch(
        r"arn:aws[a-zA-Z-]*:states:(?P<region>[^:]+):(?P<account>\d{12}):"
        r"execution:(?P<state_machine_name>[^:]+):(?P<execution_name>.+)",
        execution_arn,
    )
    if not match:
        raise ToolInputError("execution_arn must be a valid Step Functions execution ARN")
    return match.groupdict()


def require_step_functions_execution(
    runtime: AwsRuntime,
    execution_arn: str,
) -> dict[str, str]:
    parsed = parse_step_functions_execution_arn(execution_arn)
    try:
        runtime.config.require_account_allowed(parsed["account"])
    except ConfigError as exc:
        raise ToolInputError(str(exc)) from exc
    require_step_function_name(parsed["state_machine_name"])
    return parsed


def isoformat(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        formatted: str = value.isoformat()
        return formatted
    return str(value)


def truncate_optional(value: Any, max_length: int) -> str | None:
    if value is None:
        return None
    return truncate_string(str(value), max_length)
