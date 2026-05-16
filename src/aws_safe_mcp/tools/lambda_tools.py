from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

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
    require_lambda_name,
    require_log_group_name,
    resolve_region,
    truncate_optional,
)
from aws_safe_mcp.tools.graph import dependency_graph_summary, empty_permission_checks

ERROR_FILTER_PATTERN = '?ERROR ?Error ?error ?Exception ?exception ?Traceback ?"Task timed out"'


def list_lambda_functions(
    runtime: AwsRuntime,
    region: str | None = None,
    name_prefix: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    """Explain Lambda dependencies without exposing environment values.

    The result combines Lambda configuration, execution role metadata, inferred
    dependency edges, unresolved hints from safe names, and optional IAM
    simulation checks into the shared dependency graph contract.
    """

    resolved_region = resolve_region(runtime, region)
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    client = runtime.client("lambda", region=resolved_region)

    functions: list[dict[str, Any]] = []
    try:
        paginator = client.get_paginator("list_functions")
        for page in paginator.paginate(PaginationConfig={"PageSize": min(limit, 50)}):
            for item in page.get("Functions", []):
                function_name = str(item.get("FunctionName", ""))
                if name_prefix and not function_name.startswith(name_prefix):
                    continue
                functions.append(_lambda_list_item(item))
                if len(functions) >= limit:
                    return {
                        "region": resolved_region,
                        "count": len(functions),
                        "functions": functions,
                    }
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "lambda.ListFunctions") from exc

    return {"region": resolved_region, "count": len(functions), "functions": functions}


def get_lambda_summary(
    runtime: AwsRuntime,
    function_name: str,
    region: str | None = None,
) -> dict[str, Any]:
    """Simulate whether a Lambda execution role can perform one action.

    This is a focused diagnostic helper rather than a generic IAM simulator: the
    principal is always the Lambda's execution role, and failures to run
    simulation are returned as an unknown decision with warnings.
    """

    resolved_region = resolve_region(runtime, region)
    required_name = require_lambda_name(function_name)
    lambda_client = runtime.client("lambda", region=resolved_region)

    try:
        response = lambda_client.get_function_configuration(FunctionName=required_name)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "lambda.GetFunctionConfiguration") from exc

    summary = _lambda_summary(response, runtime.config.redaction.max_string_length)
    summary["region"] = resolved_region
    summary["recent_metrics"] = _lambda_recent_metrics(runtime, required_name, resolved_region)
    return summary


def get_lambda_event_source_mapping_diagnostics(
    runtime: AwsRuntime,
    function_name: str,
    region: str | None = None,
    max_results: int | None = None,
    include_permission_checks: bool = True,
    max_permission_checks: int | None = None,
) -> dict[str, Any]:
    """Summarize Lambda event source mappings without reading source payloads."""

    resolved_region = resolve_region(runtime, region)
    required_name = require_lambda_name(function_name)
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    client = runtime.client("lambda", region=resolved_region)
    try:
        response = client.list_event_source_mappings(
            FunctionName=required_name,
            MaxItems=min(limit, 100),
        )
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "lambda.ListEventSourceMappings") from exc

    mappings = [
        _event_source_mapping_diagnostic(item)
        for item in response.get("EventSourceMappings", [])[:limit]
    ]
    permission_hints = _event_source_mapping_permission_hints(mappings)
    role_arn, warnings = _lambda_execution_role_arn(
        runtime=runtime,
        function_name=required_name,
        region=resolved_region,
    )
    check_limit = clamp_limit(
        max_permission_checks,
        default=20,
        configured_max=runtime.config.max_results,
        label="max_permission_checks",
    )

    return {
        "function_name": required_name,
        "region": resolved_region,
        "summary": _event_source_mapping_summary(mappings, warnings),
        "mappings": mappings,
        "permission_hints": permission_hints,
        "permission_checks": _event_source_mapping_permission_checks(
            runtime=runtime,
            function_name=required_name,
            region=resolved_region,
            role_arn=role_arn,
            permission_hints=permission_hints,
            include_permission_checks=include_permission_checks,
            limit=check_limit,
            warnings=warnings,
        ),
        "warnings": warnings,
    }


def get_lambda_alias_version_summary(
    runtime: AwsRuntime,
    function_name: str,
    region: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    """Summarize Lambda aliases and published versions without fetching code."""

    resolved_region = resolve_region(runtime, region)
    required_name = require_lambda_name(function_name)
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    client = runtime.client("lambda", region=resolved_region)
    aliases, alias_warnings = _lambda_aliases_for_summary(client, required_name, limit)
    versions, version_warnings = _lambda_versions_for_summary(client, required_name, limit)
    concurrency = _lambda_provisioned_concurrency_summary(client, required_name, aliases, versions)
    policy = _lambda_resource_policy_summary(client, required_name)
    warnings = [*alias_warnings, *version_warnings, *concurrency["warnings"], *policy["warnings"]]

    return {
        "function_name": required_name,
        "region": resolved_region,
        "summary": {
            "alias_count": len(aliases),
            "published_version_count": len(versions),
            "weighted_alias_count": sum(
                1 for alias in aliases if alias["additional_version_weights"]
            ),
            "provisioned_concurrency_configured": concurrency["configured"],
            "policy_statement_count": policy["statement_count"],
            "warning_count": len(warnings),
        },
        "aliases": aliases,
        "versions": versions,
        "provisioned_concurrency": concurrency,
        "policy_hints": policy,
        "warnings": warnings,
    }


def get_lambda_recent_errors(
    runtime: AwsRuntime,
    function_name: str,
    since_minutes: int | None = 60,
    region: str | None = None,
    max_events: int | None = 50,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_name = require_lambda_name(function_name)
    window_minutes = clamp_since_minutes(
        since_minutes,
        default=60,
        configured_max=runtime.config.max_since_minutes,
    )
    limit = clamp_limit(
        max_events,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_events",
    )
    log_group_name = require_log_group_name(f"/aws/lambda/{required_name}")
    logs = runtime.client("logs", region=resolved_region)
    end = datetime.now(UTC)
    start = end - timedelta(minutes=window_minutes)
    request = {
        "logGroupName": log_group_name,
        "startTime": int(start.timestamp() * 1000),
        "endTime": int(end.timestamp() * 1000),
        "filterPattern": ERROR_FILTER_PATTERN,
    }

    try:
        raw_events = bounded_filter_log_events(logs, request, limit)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "logs.FilterLogEvents") from exc

    events = [
        _log_event_summary(event, runtime.config.redaction.max_string_length)
        for event in raw_events
    ]
    groups = log_event_groups(events)

    return {
        "function_name": required_name,
        "region": resolved_region,
        "log_group_name": log_group_name,
        "window_minutes": window_minutes,
        "count": len(events),
        "groups": groups,
        "events": events,
    }


def investigate_lambda_failure(
    runtime: AwsRuntime,
    function_name: str,
    since_minutes: int | None = 60,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_name = require_lambda_name(function_name)
    summary = get_lambda_summary(runtime, required_name, region=resolved_region)
    recent_errors = get_lambda_recent_errors(
        runtime,
        required_name,
        since_minutes=since_minutes,
        region=resolved_region,
        max_events=50,
    )
    signals = _lambda_failure_signals(summary, recent_errors)

    return {
        "function_name": required_name,
        "region": resolved_region,
        "diagnostic_summary": _lambda_diagnostic_summary(signals),
        "warnings": _lambda_summary_warnings(summary),
        "signals": signals,
        "recent_error_groups": recent_errors["groups"],
        "recent_error_count": recent_errors["count"],
        "configuration": {
            "runtime": summary.get("runtime"),
            "handler": summary.get("handler"),
            "memory_mb": summary.get("memory_mb"),
            "timeout_seconds": summary.get("timeout_seconds"),
            "vpc": summary.get("vpc"),
            "dead_letter": summary.get("dead_letter"),
            "state": summary.get("state"),
            "last_update_status": summary.get("last_update_status"),
            "aliases": _lambda_alias_summary(runtime, required_name, resolved_region),
            "event_sources": _lambda_event_source_summary(runtime, required_name, resolved_region),
        },
        "suggested_next_checks": _lambda_suggested_next_checks(signals),
    }


def audit_async_lambda_failure_path(
    runtime: AwsRuntime,
    function_name: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_name = require_lambda_name(function_name)
    summary = get_lambda_summary(runtime, required_name, region=resolved_region)
    client = runtime.client("lambda", region=resolved_region)
    async_config, warnings = _lambda_async_invoke_config(client, required_name)
    concurrency = _lambda_reserved_concurrency(client, required_name, warnings)
    signals = _async_lambda_failure_signals(summary, async_config, concurrency)
    return {
        "function_name": required_name,
        "region": resolved_region,
        "diagnostic_summary": _async_lambda_failure_summary(signals),
        "async_invoke_config": async_config,
        "dead_letter": summary.get("dead_letter"),
        "reserved_concurrency": concurrency,
        "recent_metrics": summary.get("recent_metrics"),
        "signals": signals,
        "suggested_next_checks": _async_lambda_failure_next_checks(signals),
        "warnings": [*_lambda_summary_warnings(summary), *warnings],
    }


def explain_lambda_dependencies(
    runtime: AwsRuntime,
    function_name: str,
    region: str | None = None,
    include_permission_checks: bool = True,
    max_permission_checks: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_name = require_lambda_name(function_name)
    permission_check_limit = clamp_limit(
        max_permission_checks,
        default=12,
        configured_max=runtime.config.max_results,
        label="max_permission_checks",
    )
    summary = get_lambda_summary(runtime, required_name, region=resolved_region)
    role_arn = str(summary.get("role_arn") or "")
    event_sources = _lambda_event_source_summary(runtime, required_name, resolved_region)
    aliases = _lambda_alias_summary(runtime, required_name, resolved_region)
    iam_role = _lambda_iam_role_summary(runtime, role_arn)
    log_group_name = f"/aws/lambda/{required_name}"
    edges = _lambda_dependency_edges(
        summary=summary,
        event_sources=event_sources,
        log_group_name=log_group_name,
        iam_role=iam_role,
    )
    permission_checks = _lambda_dependency_permission_checks(
        runtime=runtime,
        function_name=required_name,
        region=resolved_region,
        role_arn=role_arn,
        dependencies={
            "permission_hints": _lambda_permission_hints(edges, iam_role),
            "nodes": {"event_sources": event_sources},
        },
        include_permission_checks=include_permission_checks,
        limit=permission_check_limit,
    )

    permission_hints = _lambda_permission_hints(edges, iam_role)
    warnings = _lambda_dependency_warnings(summary, aliases, event_sources, iam_role)
    unresolved_resource_hints = _lambda_unresolved_resource_hints(summary, iam_role)
    nodes = {
        "lambda": {
            "name": required_name,
            "arn": summary.get("function_arn"),
        },
        "execution_role": iam_role,
        "log_group": {
            "name": log_group_name,
            "expected": True,
        },
        "vpc": summary.get("vpc"),
        "dead_letter": summary.get("dead_letter"),
        "aliases": aliases,
        "event_sources": event_sources,
        "unresolved_resource_hints": unresolved_resource_hints,
        "environment_dependency_hints": summary.get("environment_dependency_hints", []),
    }

    return {
        "name": required_name,
        "arn": summary.get("function_arn"),
        "function_name": required_name,
        "function_arn": summary.get("function_arn"),
        "region": resolved_region,
        "resource_type": "lambda",
        "summary": {
            "runtime": summary.get("runtime"),
            "handler": summary.get("handler"),
            "memory_mb": summary.get("memory_mb"),
            "timeout_seconds": summary.get("timeout_seconds"),
            "state": summary.get("state"),
            "last_update_status": summary.get("last_update_status"),
            "environment_variable_keys": summary.get("environment_variable_keys", []),
            "environment_dependency_hint_count": len(
                summary.get("environment_dependency_hints", [])
            ),
        },
        "graph_summary": dependency_graph_summary(
            nodes=nodes,
            edges=edges,
            permission_checks=permission_checks,
            warnings=warnings,
        ),
        "nodes": nodes,
        "edges": edges,
        "unresolved_resource_hints": unresolved_resource_hints,
        "environment_dependency_hints": summary.get("environment_dependency_hints", []),
        "permission_hints": permission_hints,
        "permission_checks": permission_checks,
        "warnings": warnings,
    }


def explain_lambda_network_access(
    runtime: AwsRuntime,
    function_name: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_name = require_lambda_name(function_name)
    lambda_client = runtime.client("lambda", region=resolved_region)

    try:
        config = lambda_client.get_function_configuration(FunctionName=required_name)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "lambda.GetFunctionConfiguration") from exc

    vpc_config = config.get("VpcConfig", {})
    subnet_ids = list(vpc_config.get("SubnetIds", [])) if isinstance(vpc_config, dict) else []
    security_group_ids = (
        list(vpc_config.get("SecurityGroupIds", [])) if isinstance(vpc_config, dict) else []
    )
    vpc_id = str(vpc_config.get("VpcId") or "") if isinstance(vpc_config, dict) else ""

    if not vpc_id:
        return _lambda_non_vpc_network_access(required_name, resolved_region, config)

    ec2_client = runtime.client("ec2", region=resolved_region)
    try:
        subnets = ec2_client.describe_subnets(SubnetIds=subnet_ids).get("Subnets", [])
        security_groups = ec2_client.describe_security_groups(GroupIds=security_group_ids).get(
            "SecurityGroups", []
        )
        route_tables = ec2_client.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("RouteTables", [])
        network_acls = ec2_client.describe_network_acls(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("NetworkAcls", [])
        endpoints = ec2_client.describe_vpc_endpoints(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("VpcEndpoints", [])
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "ec2.DescribeLambdaNetworkAccess") from exc

    return _lambda_vpc_network_access(
        function_name=required_name,
        region=resolved_region,
        config=config,
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        security_group_ids=security_group_ids,
        subnets=subnets,
        security_groups=security_groups,
        route_tables=route_tables,
        network_acls=network_acls,
        endpoints=endpoints,
    )


def check_lambda_permission_path(
    runtime: AwsRuntime,
    function_name: str,
    action: str,
    resource_arn: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_name = require_lambda_name(function_name)
    required_action = _require_iam_action(action)
    required_resource = _require_arn(resource_arn, "resource_arn")
    summary = get_lambda_summary(runtime, required_name, region=resolved_region)
    role_arn = str(summary.get("role_arn") or "")
    role_name = _role_name_from_arn(role_arn)
    warnings: list[str] = _lambda_summary_warnings(summary)

    if not role_name:
        return _permission_path_unknown_result(
            function_name=required_name,
            region=resolved_region,
            action=required_action,
            resource_arn=required_resource,
            role_arn=role_arn or None,
            warnings=[
                *warnings,
                "Lambda configuration did not include a parseable execution role ARN",
            ],
        )

    return _simulate_lambda_role_permission(
        runtime=runtime,
        function_name=required_name,
        region=resolved_region,
        role_arn=role_arn,
        action=required_action,
        resource=required_resource,
        warnings=warnings,
    )


def check_lambda_to_sqs_sendability(
    runtime: AwsRuntime,
    function_name: str,
    queue_url: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_name = require_lambda_name(function_name)
    required_queue_url = _require_queue_url(queue_url)
    summary = get_lambda_summary(runtime, required_name, region=resolved_region)
    role_arn = str(summary.get("role_arn") or "")
    role_name = _role_name_from_arn(role_arn)
    warnings: list[str] = _lambda_summary_warnings(summary)
    queue = _sqs_queue_context(runtime, required_queue_url, resolved_region, warnings)
    queue_arn = str(queue.get("queue_arn") or "")
    identity_check = (
        _simulate_lambda_role_permission(
            runtime=runtime,
            function_name=required_name,
            region=resolved_region,
            role_arn=role_arn,
            action="sqs:SendMessage",
            resource=queue_arn,
            warnings=warnings,
        )
        if role_name and queue_arn
        else _permission_path_unknown_result(
            function_name=required_name,
            region=resolved_region,
            action="sqs:SendMessage",
            resource_arn=queue_arn or required_queue_url,
            role_arn=role_arn or None,
            warnings=[*warnings, "Lambda role or queue ARN was unavailable."],
        )
    )
    queue_policy_check = _lambda_sqs_queue_policy_check(queue, role_arn)
    signals = _lambda_sqs_sendability_signals(
        summary=summary,
        queue=queue,
        identity_check=identity_check,
        queue_policy_check=queue_policy_check,
        region=resolved_region,
    )
    return {
        "function_name": required_name,
        "queue_url": required_queue_url,
        "region": resolved_region,
        "lambda": {
            "function_arn": summary.get("function_arn"),
            "role_arn": role_arn or None,
        },
        "queue": queue,
        "identity_permission_check": identity_check,
        "queue_policy_check": queue_policy_check,
        "signals": signals,
        "diagnostic_summary": _lambda_sqs_sendability_summary(signals),
        "suggested_next_checks": _lambda_sqs_sendability_next_checks(signals),
        "warnings": warnings,
    }


def _lambda_list_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "function_name": item.get("FunctionName"),
        "runtime": item.get("Runtime"),
        "last_modified": item.get("LastModified"),
        "memory_mb": item.get("MemorySize"),
        "timeout_seconds": item.get("Timeout"),
        "role_arn": item.get("Role"),
        "description": item.get("Description") or None,
    }


def _lambda_summary(item: dict[str, Any], max_string_length: int) -> dict[str, Any]:
    environment = item.get("Environment", {})
    variables = environment.get("Variables", {}) if isinstance(environment, dict) else {}
    vpc_config = item.get("VpcConfig", {})
    dead_letter_config = item.get("DeadLetterConfig", {})

    return {
        "function_name": item.get("FunctionName"),
        "function_arn": item.get("FunctionArn"),
        "runtime": item.get("Runtime"),
        "handler": item.get("Handler"),
        "last_modified": item.get("LastModified"),
        "memory_mb": item.get("MemorySize"),
        "timeout_seconds": item.get("Timeout"),
        "role_arn": item.get("Role"),
        "description": truncate_optional(item.get("Description"), max_string_length),
        "environment_variable_keys": sorted(str(key) for key in variables),
        "environment_dependency_hints": _lambda_environment_dependency_hints(variables),
        "vpc": {
            "enabled": bool(vpc_config.get("VpcId")),
            "vpc_id": vpc_config.get("VpcId") or None,
            "subnet_count": len(vpc_config.get("SubnetIds", [])),
            "security_group_count": len(vpc_config.get("SecurityGroupIds", [])),
        },
        "dead_letter": {
            "configured": bool(dead_letter_config.get("TargetArn")),
            "target_arn": dead_letter_config.get("TargetArn") or None,
        },
        "state": item.get("State"),
        "state_reason": truncate_optional(item.get("StateReason"), max_string_length),
        "last_update_status": item.get("LastUpdateStatus"),
    }


def _lambda_environment_dependency_hints(variables: dict[Any, Any]) -> list[dict[str, Any]]:
    hints = []
    for raw_key, raw_value in variables.items():
        key = str(raw_key)
        value = str(raw_value or "")
        key_service = _likely_service_from_name(key)
        value_hint = _environment_value_hint(value)
        service = value_hint.get("service") or key_service
        if not service:
            continue
        confidence = "high" if value_hint.get("value_shape") in {"arn", "queue_url"} else "medium"
        if value_hint.get("value_shape") == "unknown":
            confidence = "low"
        hints.append(
            {
                "source": "environment_variable",
                "key": key,
                "likely_service": service,
                "value_shape": value_hint["value_shape"],
                "confidence": confidence,
                "target": {
                    "service": service,
                    "partition": value_hint.get("partition"),
                    "region": value_hint.get("region"),
                    "account_id": value_hint.get("account_id"),
                    "resource_type": value_hint.get("resource_type"),
                    "host_kind": value_hint.get("host_kind"),
                },
                "reason": _environment_dependency_reason(key, service, value_hint),
            }
        )
    return _dedupe_unresolved_resource_hints(hints)


def _environment_value_hint(value: str) -> dict[str, str | None]:
    arn = _environment_arn_hint(value)
    if arn:
        return arn
    queue_url = _environment_queue_url_hint(value)
    if queue_url:
        return queue_url
    url = _environment_url_hint(value)
    if url:
        return url
    return {"value_shape": "name_or_literal"}


def _environment_arn_hint(value: str) -> dict[str, str | None] | None:
    parts = value.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return None
    resource = parts[5]
    resource_type = None
    if "/" in resource:
        resource_type = resource.split("/", 1)[0]
    elif ":" in resource:
        resource_type = resource.split(":", 1)[0]
    return {
        "value_shape": "arn",
        "service": parts[2] or None,
        "partition": parts[1] or None,
        "region": parts[3] or None,
        "account_id": parts[4] or None,
        "resource_type": resource_type,
    }


def _environment_queue_url_hint(value: str) -> dict[str, str | None] | None:
    match = re.fullmatch(
        r"https?://sqs[.-](?P<region>[^./]+)\.amazonaws\.com(?:\.cn)?/"
        r"(?P<account_id>\d{12})/(?P<name>[^/?]+)",
        value,
    )
    if not match:
        return None
    return {
        "value_shape": "queue_url",
        "service": "sqs",
        "partition": "aws-cn" if ".amazonaws.com.cn/" in value else "aws",
        "region": match.group("region"),
        "account_id": match.group("account_id"),
        "resource_type": "queue",
    }


def _environment_url_hint(value: str) -> dict[str, str | None] | None:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return None
    host = parsed.hostname or ""
    parts = host.split(".")
    return {
        "value_shape": "url",
        "service": parts[0] if host.endswith(".amazonaws.com") else "http",
        "partition": _environment_partition_from_host(host),
        "region": _environment_region_from_host(parts),
        "account_id": None,
        "resource_type": None,
        "host_kind": _environment_host_kind(host),
    }


def _environment_region_from_host(parts: list[str]) -> str | None:
    for part in parts:
        if re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", part):
            return part
    return None


def _environment_partition_from_host(host: str) -> str | None:
    if host.endswith(".amazonaws.com.cn"):
        return "aws-cn"
    if host.endswith(".amazonaws.com"):
        return "aws"
    return None


def _environment_host_kind(host: str) -> str:
    if host.endswith((".amazonaws.com", ".amazonaws.com.cn")):
        return "aws_service_endpoint"
    if host.endswith((".local", ".internal")):
        return "private_dns"
    return "external_url"


def _environment_dependency_reason(
    key: str,
    service: str,
    value_hint: dict[str, str | None],
) -> str:
    shape = value_hint["value_shape"]
    if shape in {"arn", "queue_url", "url"}:
        return (
            f"Environment key {key} contains a redacted {shape} that appears to target "
            f"{service}."
        )
    return f"Environment key {key} suggests a {service} dependency."


def _lambda_non_vpc_network_access(
    function_name: str,
    region: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    return {
        "resource_type": "lambda",
        "name": function_name,
        "arn": config.get("FunctionArn"),
        "region": region,
        "summary": {
            "network_mode": "aws_managed",
            "internet_access": "yes",
            "private_network_access": "not_applicable",
            "aws_private_service_access": "unknown",
            "main_risks": [],
        },
        "scope": {
            "analysis_type": "static_configuration",
            "protocols": ["tcp", "udp", "icmp", "-1"],
            "ip_families": ["ipv4", "ipv6"],
        },
        "network_context": {
            "vpc_id": None,
            "subnet_ids": [],
            "security_group_ids": [],
        },
        "egress": {
            "internet": {
                "verdict": "yes",
                "ipv4": "reachable",
                "ipv6": "unknown",
                "via": [],
            },
            "private_networks": [],
            "aws_services": [],
            "blocked_or_unknown": [],
        },
        "controls": {
            "security_groups": [],
            "route_tables": [],
            "network_acls": [],
            "endpoints": [],
        },
        "paths": [],
        "warnings": [
            "Lambda is not VPC-attached; security groups and subnet routes do not apply.",
            "Static analysis cannot prove application-layer destinations or DNS behavior.",
        ],
        "confidence": "medium",
    }


def _lambda_vpc_network_access(
    *,
    function_name: str,
    region: str,
    config: dict[str, Any],
    vpc_id: str,
    subnet_ids: list[str],
    security_group_ids: list[str],
    subnets: list[dict[str, Any]],
    security_groups: list[dict[str, Any]],
    route_tables: list[dict[str, Any]],
    network_acls: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
) -> dict[str, Any]:
    subnet_route_tables = {
        subnet_id: _route_table_for_subnet(subnet_id, route_tables) for subnet_id in subnet_ids
    }
    paths: list[dict[str, Any]] = []
    blocked_or_unknown: list[dict[str, Any]] = []
    private_networks: list[dict[str, Any]] = []
    warnings = ["Static analysis cannot prove application-layer destinations or DNS behavior."]

    for subnet_id in subnet_ids:
        route_table = subnet_route_tables.get(subnet_id)
        default_route = _default_ipv4_route(route_table)
        internet_path = _internet_path_for_subnet(
            subnet_id=subnet_id,
            route_table=route_table,
            default_route=default_route,
            security_groups=security_groups,
        )
        paths.append(internet_path)
        if internet_path["verdict"] != "reachable":
            blocked_or_unknown.append(
                {
                    "destination": "0.0.0.0/0",
                    "from_subnet": subnet_id,
                    "reason": internet_path["limited_by"][0]
                    if internet_path["limited_by"]
                    else "unknown",
                }
            )

        for private_path in _private_paths_for_subnet(
            subnet_id=subnet_id,
            route_table=route_table,
            security_groups=security_groups,
        ):
            paths.append(private_path)
            private_networks.append(
                {
                    "cidr": private_path["destination"],
                    "via": private_path["via"][-1] if private_path["via"] else None,
                    "verdict": private_path["verdict"],
                    "confidence": private_path["confidence"],
                }
            )

    internet_verdict = _summary_verdict(
        path["verdict"] for path in paths if path["destination_class"] == "internet"
    )
    private_verdict = _summary_verdict(
        path["verdict"] for path in paths if path["destination_class"] == "private_network"
    )
    aws_services = _aws_service_endpoint_summaries(endpoints)
    aws_service_verdict = "yes" if aws_services else "no"
    main_risks = _lambda_network_risks(paths)

    return {
        "resource_type": "lambda",
        "name": function_name,
        "arn": config.get("FunctionArn"),
        "region": region,
        "summary": {
            "network_mode": "vpc",
            "internet_access": internet_verdict,
            "private_network_access": private_verdict,
            "aws_private_service_access": aws_service_verdict,
            "main_risks": main_risks,
        },
        "scope": {
            "analysis_type": "static_configuration",
            "protocols": ["tcp", "udp", "icmp", "-1"],
            "ip_families": ["ipv4", "ipv6"],
        },
        "network_context": {
            "vpc_id": vpc_id,
            "subnet_ids": subnet_ids,
            "security_group_ids": security_group_ids,
        },
        "egress": {
            "internet": {
                "verdict": internet_verdict,
                "ipv4": _internet_ipv4_verdict(internet_verdict),
                "ipv6": "not_evaluated",
                "via": _internet_route_targets(paths),
            },
            "private_networks": private_networks,
            "aws_services": aws_services,
            "blocked_or_unknown": blocked_or_unknown,
        },
        "controls": {
            "security_groups": [_security_group_summary(group) for group in security_groups],
            "route_tables": [_route_table_summary(table) for table in route_tables],
            "network_acls": [_network_acl_summary(acl) for acl in network_acls],
            "endpoints": aws_services,
        },
        "paths": paths,
        "warnings": warnings,
        "confidence": _lambda_network_confidence(paths, network_acls),
    }


def _internet_path_for_subnet(
    *,
    subnet_id: str,
    route_table: dict[str, Any] | None,
    default_route: dict[str, Any] | None,
    security_groups: list[dict[str, Any]],
) -> dict[str, Any]:
    allowed_by = _matching_egress_rules(security_groups, "0.0.0.0/0", 443)
    via = _route_via(route_table, default_route)
    limited_by: list[str] = []
    verdict = "reachable"
    confidence = "high"

    if not allowed_by:
        verdict = "blocked"
        limited_by.append("no security group egress rule allows tcp/443 to 0.0.0.0/0")
    if default_route is None:
        verdict = "blocked"
        limited_by.append(f"{_route_table_id(route_table)} has no ipv4 default route")
    elif default_route.get("NatGatewayId"):
        pass
    elif str(default_route.get("GatewayId") or "").startswith("igw-"):
        verdict = "blocked"
        limited_by.append("Lambda VPC ENIs do not receive public IPv4 addresses for IGW egress")
    else:
        verdict = "unknown" if verdict == "reachable" else verdict
        confidence = "medium"
        limited_by.append("default route target is not classified as NAT internet egress")

    return _network_path(
        destination_class="internet",
        destination="0.0.0.0/0",
        verdict=verdict,
        from_subnet=subnet_id,
        via=via,
        allowed_by=allowed_by,
        limited_by=limited_by,
        confidence=confidence,
    )


def _private_paths_for_subnet(
    *,
    subnet_id: str,
    route_table: dict[str, Any] | None,
    security_groups: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not route_table:
        return []

    paths: list[dict[str, Any]] = []
    for route in route_table.get("Routes", []):
        destination = str(route.get("DestinationCidrBlock") or "")
        if not destination or destination == "0.0.0.0/0" or not _is_private_cidr(destination):
            continue
        allowed_by = _matching_egress_rules(security_groups, destination, 443)
        limited_by = [] if allowed_by else ["no security group egress rule allows tcp/443"]
        verdict = "reachable" if allowed_by else "blocked"
        confidence = "high"
        if route.get("TransitGatewayId") or route.get("GatewayId") or route.get("InstanceId"):
            confidence = "medium"
        paths.append(
            _network_path(
                destination_class="private_network",
                destination=destination,
                verdict=verdict,
                from_subnet=subnet_id,
                via=_route_via(route_table, route) or ["local-vpc"],
                allowed_by=allowed_by,
                limited_by=limited_by,
                confidence=confidence,
            )
        )
    return paths


def _network_path(
    *,
    destination_class: str,
    destination: str,
    verdict: str,
    from_subnet: str,
    via: list[str],
    allowed_by: list[str],
    limited_by: list[str],
    confidence: str,
) -> dict[str, Any]:
    return {
        "destination_class": destination_class,
        "destination": destination,
        "ip_family": "ipv4",
        "protocol": "tcp",
        "ports": [443],
        "verdict": verdict,
        "from_subnet": from_subnet,
        "via": via,
        "allowed_by": allowed_by,
        "limited_by": limited_by,
        "confidence": confidence,
    }


def _route_table_for_subnet(
    subnet_id: str,
    route_tables: list[dict[str, Any]],
) -> dict[str, Any] | None:
    main_route_table = None
    for route_table in route_tables:
        for association in route_table.get("Associations", []):
            if association.get("SubnetId") == subnet_id:
                return route_table
            if association.get("Main"):
                main_route_table = route_table
    return main_route_table


def _default_ipv4_route(route_table: dict[str, Any] | None) -> dict[str, Any] | None:
    if not route_table:
        return None
    for route in route_table.get("Routes", []):
        if isinstance(route, dict) and route.get("DestinationCidrBlock") == "0.0.0.0/0":
            return route
    return None


def _matching_egress_rules(
    security_groups: list[dict[str, Any]],
    destination_cidr: str,
    port: int,
) -> list[str]:
    matches: list[str] = []
    for group in security_groups:
        group_id = str(group.get("GroupId") or "unknown-security-group")
        for rule in group.get("IpPermissionsEgress", []):
            if not _permission_allows_port(rule, port):
                continue
            for ip_range in rule.get("IpRanges", []):
                cidr = str(ip_range.get("CidrIp") or "")
                if cidr and _cidr_allows_destination(cidr, destination_cidr):
                    matches.append(f"{group_id} {rule.get('IpProtocol')} {cidr}")
    return matches


def _permission_allows_port(permission: dict[str, Any], port: int) -> bool:
    protocol = str(permission.get("IpProtocol") or "")
    if protocol == "-1":
        return True
    if protocol not in {"tcp", "6"}:
        return False
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return True
    return int(from_port) <= port <= int(to_port)


def _cidr_allows_destination(rule_cidr: str, destination_cidr: str) -> bool:
    try:
        rule_network = ipaddress.ip_network(rule_cidr, strict=False)
        destination_network = ipaddress.ip_network(destination_cidr, strict=False)
    except ValueError:
        return rule_cidr == destination_cidr
    if isinstance(rule_network, ipaddress.IPv4Network) and isinstance(
        destination_network, ipaddress.IPv4Network
    ):
        return destination_network.subnet_of(rule_network)
    if isinstance(rule_network, ipaddress.IPv6Network) and isinstance(
        destination_network, ipaddress.IPv6Network
    ):
        return destination_network.subnet_of(rule_network)
    return False


def _is_private_cidr(cidr: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return network.is_private


def _route_via(
    route_table: dict[str, Any] | None,
    route: dict[str, Any] | None,
) -> list[str]:
    if not route:
        return []
    via = [_route_table_id(route_table)]
    for key in [
        "NatGatewayId",
        "GatewayId",
        "TransitGatewayId",
        "VpcPeeringConnectionId",
        "InstanceId",
        "NetworkInterfaceId",
        "EgressOnlyInternetGatewayId",
    ]:
        value = route.get(key)
        if value and value != "local":
            via.append(str(value))
    return via


def _route_table_id(route_table: dict[str, Any] | None) -> str:
    if not route_table:
        return "unknown-route-table"
    return str(route_table.get("RouteTableId") or "unknown-route-table")


def _summary_verdict(verdicts: Any) -> str:
    values = list(verdicts)
    if not values:
        return "no"
    if all(value == "reachable" for value in values):
        return "yes"
    if all(value == "blocked" for value in values):
        return "no"
    if any(value == "unknown" for value in values):
        return "unknown"
    return "partial"


def _internet_ipv4_verdict(summary_verdict: str) -> str:
    if summary_verdict == "yes":
        return "reachable"
    if summary_verdict == "no":
        return "blocked"
    return summary_verdict


def _internet_route_targets(paths: list[dict[str, Any]]) -> list[str]:
    targets: list[str] = []
    for path in paths:
        if path["destination_class"] != "internet":
            continue
        for target in path["via"][1:]:
            if target not in targets:
                targets.append(target)
    return targets


def _aws_service_endpoint_summaries(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for endpoint in endpoints:
        service_name = str(endpoint.get("ServiceName") or "")
        service = service_name.rsplit(".", maxsplit=1)[-1] if service_name else None
        summaries.append(
            {
                "service": service,
                "service_name": service_name or None,
                "endpoint_type": endpoint.get("VpcEndpointType"),
                "via": endpoint.get("VpcEndpointId"),
                "verdict": "reachable" if endpoint.get("State") == "available" else "unknown",
            }
        )
    return summaries


def _lambda_network_risks(paths: list[dict[str, Any]]) -> list[str]:
    risks: list[str] = []
    if any("0.0.0.0/0" in allowed for path in paths for allowed in path["allowed_by"]):
        risks.append("wide_ipv4_egress")
    internet_verdicts = {
        path["verdict"] for path in paths if path["destination_class"] == "internet"
    }
    if internet_verdicts == {"reachable", "blocked"}:
        risks.append("subnet_route_mismatch")
    return risks


def _lambda_network_confidence(
    paths: list[dict[str, Any]],
    network_acls: list[dict[str, Any]],
) -> str:
    if any(path["confidence"] == "low" for path in paths):
        return "low"
    if network_acls or any(path["confidence"] == "medium" for path in paths):
        return "medium"
    return "high"


def _security_group_summary(group: dict[str, Any]) -> dict[str, Any]:
    return {
        "group_id": group.get("GroupId"),
        "group_name": group.get("GroupName"),
        "egress_rule_count": len(group.get("IpPermissionsEgress", [])),
    }


def _route_table_summary(route_table: dict[str, Any]) -> dict[str, Any]:
    return {
        "route_table_id": route_table.get("RouteTableId"),
        "route_count": len(route_table.get("Routes", [])),
        "association_count": len(route_table.get("Associations", [])),
    }


def _network_acl_summary(acl: dict[str, Any]) -> dict[str, Any]:
    return {
        "network_acl_id": acl.get("NetworkAclId"),
        "entry_count": len(acl.get("Entries", [])),
        "association_count": len(acl.get("Associations", [])),
        "verdict": "not_evaluated",
    }


def _lambda_recent_metrics(
    runtime: AwsRuntime,
    function_name: str,
    region: str,
) -> dict[str, Any]:
    cloudwatch = runtime.client("cloudwatch", region=region)
    end = datetime.now(UTC)
    start = end - timedelta(hours=1)
    try:
        response = cloudwatch.get_metric_data(
            MetricDataQueries=_lambda_metric_data_queries(function_name),
            StartTime=start,
            EndTime=end,
        )
    except (BotoCoreError, ClientError) as exc:
        warning = str(normalize_aws_error(exc, "cloudwatch.GetMetricData"))
        return _empty_lambda_metrics(warning)

    metrics = {
        str(item.get("Id")): _summarize_metric_data_result(item)
        for item in response.get("MetricDataResults", [])
    }

    return {
        "available": True,
        "warnings": _metric_data_warnings(response.get("MetricDataResults", [])),
        "window_minutes": 60,
        "errors": metrics.get("errors", _empty_metric_summary()),
        "throttles": metrics.get("throttles", _empty_metric_summary()),
        "invocations": metrics.get("invocations", _empty_metric_summary()),
        "max_duration_ms": metrics.get("duration", _empty_metric_summary()),
    }


def _lambda_alias_summary(
    runtime: AwsRuntime,
    function_name: str,
    region: str,
) -> dict[str, Any]:
    client = runtime.client("lambda", region=region)
    try:
        response = client.list_aliases(FunctionName=function_name, MaxItems=10)
    except (BotoCoreError, ClientError) as exc:
        warning = str(normalize_aws_error(exc, "lambda.ListAliases"))
        return {"available": False, "warnings": [warning]}

    aliases = [
        {
            "name": item.get("Name"),
            "function_version": item.get("FunctionVersion"),
            "description": item.get("Description") or None,
        }
        for item in response.get("Aliases", [])
    ]
    return {"available": True, "count": len(aliases), "aliases": aliases, "warnings": []}


def _lambda_aliases_for_summary(
    client: Any,
    function_name: str,
    limit: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        response = client.list_aliases(FunctionName=function_name, MaxItems=min(limit, 100))
    except (BotoCoreError, ClientError) as exc:
        return [], [str(normalize_aws_error(exc, "lambda.ListAliases"))]

    aliases = [
        {
            "name": item.get("Name"),
            "function_version": item.get("FunctionVersion"),
            "description": item.get("Description") or None,
            "revision_id": item.get("RevisionId"),
            "additional_version_weights": _alias_routing_weights(item.get("RoutingConfig")),
        }
        for item in response.get("Aliases", [])[:limit]
    ]
    return aliases, []


def _alias_routing_weights(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    weights = value.get("AdditionalVersionWeights") or {}
    if not isinstance(weights, dict):
        return []
    return [
        {"function_version": str(version), "weight": weight}
        for version, weight in sorted(weights.items())
    ]


def _lambda_versions_for_summary(
    client: Any,
    function_name: str,
    limit: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        response = client.list_versions_by_function(
            FunctionName=function_name,
            MaxItems=min(limit, 100),
        )
    except (BotoCoreError, ClientError) as exc:
        return [], [str(normalize_aws_error(exc, "lambda.ListVersionsByFunction"))]

    versions = [
        _lambda_version_item(item)
        for item in response.get("Versions", [])
        if item.get("Version") != "$LATEST"
    ][:limit]
    return versions, []


def _lambda_version_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": item.get("Version"),
        "runtime": item.get("Runtime"),
        "description": item.get("Description") or None,
        "last_modified": item.get("LastModified"),
        "memory_mb": item.get("MemorySize"),
        "timeout_seconds": item.get("Timeout"),
        "state": item.get("State"),
        "last_update_status": item.get("LastUpdateStatus"),
        "code_size_bytes": item.get("CodeSize"),
    }


def _lambda_provisioned_concurrency_summary(
    client: Any,
    function_name: str,
    aliases: list[dict[str, Any]],
    versions: list[dict[str, Any]],
) -> dict[str, Any]:
    qualifiers = [str(alias["name"]) for alias in aliases if alias.get("name")]
    qualifiers.extend(str(version["version"]) for version in versions if version.get("version"))
    configs: list[dict[str, Any]] = []
    warnings: list[str] = []
    for qualifier in qualifiers:
        try:
            response = client.get_provisioned_concurrency_config(
                FunctionName=function_name,
                Qualifier=qualifier,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in {
                "ProvisionedConcurrencyConfigNotFoundException",
                "ResourceNotFoundException",
            }:
                continue
            warnings.append(str(normalize_aws_error(exc, "lambda.GetProvisionedConcurrencyConfig")))
            continue
        except BotoCoreError as exc:
            warnings.append(str(normalize_aws_error(exc, "lambda.GetProvisionedConcurrencyConfig")))
            continue
        configs.append(
            {
                "qualifier": qualifier,
                "requested": response.get("RequestedProvisionedConcurrentExecutions"),
                "available": response.get("AvailableProvisionedConcurrentExecutions"),
                "allocated": response.get("AllocatedProvisionedConcurrentExecutions"),
                "status": response.get("Status"),
                "status_reason": response.get("StatusReason"),
            }
        )
    return {
        "configured": bool(configs),
        "count": len(configs),
        "configs": configs,
        "warnings": warnings,
    }


def _lambda_resource_policy_summary(client: Any, function_name: str) -> dict[str, Any]:
    try:
        response = client.get_policy(FunctionName=function_name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in {"ResourceNotFoundException", "PolicyNotFoundException"}:
            return _empty_lambda_policy_summary()
        summary = _empty_lambda_policy_summary()
        summary["warnings"] = [str(normalize_aws_error(exc, "lambda.GetPolicy"))]
        return summary
    except BotoCoreError as exc:
        summary = _empty_lambda_policy_summary()
        summary["warnings"] = [str(normalize_aws_error(exc, "lambda.GetPolicy"))]
        return summary

    policy = _parse_policy_document(response.get("Policy"))
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    service_principals: set[str] = set()
    actions: set[str] = set()
    for statement in statements if isinstance(statements, list) else []:
        if not isinstance(statement, dict):
            continue
        service_principals.update(_policy_service_principals(statement.get("Principal")))
        actions.update(_policy_actions(statement.get("Action")))
    return {
        "available": True,
        "statement_count": len(statements) if isinstance(statements, list) else 0,
        "service_principals": sorted(service_principals),
        "actions": sorted(actions),
        "warnings": [],
    }


def _lambda_async_invoke_config(
    client: Any,
    function_name: str,
) -> tuple[dict[str, Any], list[str]]:
    try:
        response = client.get_function_event_invoke_config(FunctionName=function_name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in {"ResourceNotFoundException", "EventInvokeConfigNotFoundException"}:
            return _default_async_invoke_config(), []
        return _default_async_invoke_config(), [
            str(normalize_aws_error(exc, "lambda.GetFunctionEventInvokeConfig"))
        ]
    except BotoCoreError as exc:
        return _default_async_invoke_config(), [
            str(normalize_aws_error(exc, "lambda.GetFunctionEventInvokeConfig"))
        ]
    return {
        "available": True,
        "maximum_retry_attempts": response.get("MaximumRetryAttempts"),
        "maximum_event_age_seconds": response.get("MaximumEventAgeInSeconds"),
        "on_success_arn": ((response.get("DestinationConfig") or {}).get("OnSuccess") or {}).get(
            "Destination"
        ),
        "on_failure_arn": ((response.get("DestinationConfig") or {}).get("OnFailure") or {}).get(
            "Destination"
        ),
    }, []


def _default_async_invoke_config() -> dict[str, Any]:
    return {
        "available": False,
        "maximum_retry_attempts": 2,
        "maximum_event_age_seconds": 21600,
        "on_success_arn": None,
        "on_failure_arn": None,
    }


def _lambda_reserved_concurrency(
    client: Any,
    function_name: str,
    warnings: list[str],
) -> dict[str, Any]:
    try:
        response = client.get_function_concurrency(FunctionName=function_name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in {"ResourceNotFoundException", "ResourceConflictException"}:
            return {"configured": False, "reserved_concurrent_executions": None}
        warnings.append(str(normalize_aws_error(exc, "lambda.GetFunctionConcurrency")))
        return {"configured": False, "reserved_concurrent_executions": None}
    except BotoCoreError as exc:
        warnings.append(str(normalize_aws_error(exc, "lambda.GetFunctionConcurrency")))
        return {"configured": False, "reserved_concurrent_executions": None}
    value = response.get("ReservedConcurrentExecutions")
    return {"configured": value is not None, "reserved_concurrent_executions": value}


def _async_lambda_failure_signals(
    summary: dict[str, Any],
    async_config: dict[str, Any],
    concurrency: dict[str, Any],
) -> dict[str, Any]:
    recent_metrics = summary.get("recent_metrics") or {}
    throttles = _metric_value(recent_metrics, "throttles")
    dead_letter = summary.get("dead_letter") or {}
    return {
        "retry_attempts": async_config.get("maximum_retry_attempts"),
        "max_event_age_seconds": async_config.get("maximum_event_age_seconds"),
        "failure_destination_configured": bool(async_config.get("on_failure_arn")),
        "dead_letter_configured": bool(dead_letter.get("configured")),
        "reserved_concurrency_zero": concurrency.get("reserved_concurrent_executions") == 0,
        "throttles_last_hour": throttles,
    }


def _async_lambda_failure_summary(signals: dict[str, Any]) -> dict[str, Any]:
    risks = []
    if not signals["failure_destination_configured"] and not signals["dead_letter_configured"]:
        risks.append("no_failure_destination_or_dlq")
    if signals["reserved_concurrency_zero"]:
        risks.append("reserved_concurrency_zero")
    if signals["throttles_last_hour"] > 0:
        risks.append("recent_throttles")
    return {"status": "needs_attention" if risks else "covered", "risks": risks}


def _async_lambda_failure_next_checks(signals: dict[str, Any]) -> list[str]:
    checks = []
    if not signals["failure_destination_configured"] and not signals["dead_letter_configured"]:
        checks.append("Configure async on-failure destination or Lambda DLQ.")
    if signals["reserved_concurrency_zero"]:
        checks.append("Increase reserved concurrency above zero before async invokes arrive.")
    if signals["throttles_last_hour"] > 0:
        checks.append("Inspect throttles and async event age for delayed retries.")
    if not checks:
        checks.append("Async failure path has a configured destination or DLQ.")
    return checks


def _empty_lambda_policy_summary() -> dict[str, Any]:
    return {
        "available": False,
        "statement_count": 0,
        "service_principals": [],
        "actions": [],
        "warnings": [],
    }


def _parse_policy_document(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _policy_service_principals(value: Any) -> set[str]:
    if isinstance(value, dict):
        service = value.get("Service")
        if isinstance(service, str):
            return {service}
        if isinstance(service, list):
            return {str(item) for item in service}
    return set()


def _policy_actions(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()


def _lambda_event_source_summary(
    runtime: AwsRuntime,
    function_name: str,
    region: str,
) -> dict[str, Any]:
    client = runtime.client("lambda", region=region)
    try:
        response = client.list_event_source_mappings(FunctionName=function_name, MaxItems=10)
    except (BotoCoreError, ClientError) as exc:
        warning = str(normalize_aws_error(exc, "lambda.ListEventSourceMappings"))
        return {"available": False, "warnings": [warning]}

    mappings = [
        {
            "uuid": item.get("UUID"),
            "state": item.get("State"),
            "event_source_arn": item.get("EventSourceArn"),
            "batch_size": item.get("BatchSize"),
        }
        for item in response.get("EventSourceMappings", [])
    ]
    return {"available": True, "count": len(mappings), "event_sources": mappings, "warnings": []}


def _event_source_mapping_diagnostic(item: dict[str, Any]) -> dict[str, Any]:
    source_arn = item.get("EventSourceArn")
    return {
        "uuid": item.get("UUID"),
        "state": item.get("State"),
        "enabled": item.get("State") == "Enabled",
        "state_transition_reason": item.get("StateTransitionReason"),
        "last_processing_result": item.get("LastProcessingResult"),
        "event_source_arn": source_arn,
        "source_type": _arn_service(source_arn),
        "function_arn": item.get("FunctionArn"),
        "batch_size": item.get("BatchSize"),
        "maximum_batching_window_seconds": item.get("MaximumBatchingWindowInSeconds"),
        "parallelization_factor": item.get("ParallelizationFactor"),
        "maximum_retry_attempts": item.get("MaximumRetryAttempts"),
        "maximum_record_age_seconds": item.get("MaximumRecordAgeInSeconds"),
        "bisect_batch_on_function_error": item.get("BisectBatchOnFunctionError"),
        "destination_config": _event_source_destination_config(item.get("DestinationConfig")),
        "function_response_types": item.get("FunctionResponseTypes", []),
        "scaling_config": _event_source_scaling_config(item.get("ScalingConfig")),
        "starting_position": item.get("StartingPosition"),
        "tumbling_window_seconds": item.get("TumblingWindowInSeconds"),
        "filter_criteria_configured": bool(item.get("FilterCriteria")),
    }


def _event_source_mapping_summary(
    mappings: list[dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any]:
    enabled_count = sum(1 for mapping in mappings if mapping.get("state") == "Enabled")
    disabled_count = sum(1 for mapping in mappings if mapping.get("state") == "Disabled")
    source_types = sorted(
        {str(mapping["source_type"]) for mapping in mappings if mapping.get("source_type")}
    )
    return {
        "mapping_count": len(mappings),
        "enabled_count": enabled_count,
        "disabled_count": disabled_count,
        "source_types": source_types,
        "warning_count": len(warnings),
    }


def _event_source_destination_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"on_failure_arn": None, "on_success_arn": None}
    return {
        "on_failure_arn": (value.get("OnFailure") or {}).get("Destination"),
        "on_success_arn": (value.get("OnSuccess") or {}).get("Destination"),
    }


def _event_source_scaling_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"maximum_concurrency": None}
    return {"maximum_concurrency": value.get("MaximumConcurrency")}


def _event_source_mapping_permission_hints(
    mappings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    hints = []
    for mapping in mappings:
        source_type = mapping.get("source_type")
        source_arn = mapping.get("event_source_arn")
        actions = {
            "sqs": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "dynamodb": [
                "dynamodb:DescribeStream",
                "dynamodb:GetRecords",
                "dynamodb:GetShardIterator",
            ],
            "kinesis": ["kinesis:DescribeStream", "kinesis:GetRecords", "kinesis:GetShardIterator"],
        }.get(str(source_type), [])
        if actions:
            hints.append(
                {
                    "mapping_uuid": mapping.get("uuid"),
                    "source_type": source_type,
                    "resource": source_arn,
                    "actions_to_check": actions,
                    "reason": (
                        "Lambda event source mappings poll the source using the execution role."
                    ),
                }
            )
    return hints


def _lambda_execution_role_arn(
    *,
    runtime: AwsRuntime,
    function_name: str,
    region: str,
) -> tuple[str, list[str]]:
    client = runtime.client("lambda", region=region)
    try:
        response = client.get_function_configuration(FunctionName=function_name)
    except (BotoCoreError, ClientError) as exc:
        return "", [str(normalize_aws_error(exc, "lambda.GetFunctionConfiguration"))]
    return str(response.get("Role") or ""), []


def _event_source_mapping_permission_checks(
    *,
    runtime: AwsRuntime,
    function_name: str,
    region: str,
    role_arn: str,
    permission_hints: list[dict[str, Any]],
    include_permission_checks: bool,
    limit: int,
    warnings: list[str],
) -> dict[str, Any]:
    if not include_permission_checks:
        return empty_permission_checks()

    candidates = _dedupe_permission_candidates(
        [
            {
                "action": action,
                "resource": str(hint["resource"]),
                "source": "event_source_mapping",
                "reason": hint.get("reason"),
                "mapping_uuid": hint.get("mapping_uuid"),
            }
            for hint in permission_hints
            if _simulatable_resource(hint.get("resource"))
            for action in hint.get("actions_to_check", [])
        ]
    )[:limit]
    checks = [
        _event_source_mapping_permission_check(
            runtime=runtime,
            function_name=function_name,
            region=region,
            role_arn=role_arn,
            candidate=candidate,
            warnings=warnings,
        )
        for candidate in candidates
    ]
    return {
        "enabled": True,
        "checked_count": len(checks),
        "checks": checks,
        "summary": _lambda_permission_investigation_summary(checks),
    }


def _event_source_mapping_permission_check(
    *,
    runtime: AwsRuntime,
    function_name: str,
    region: str,
    role_arn: str,
    candidate: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    result = _simulate_lambda_role_permission(
        runtime=runtime,
        function_name=function_name,
        region=region,
        role_arn=role_arn,
        action=str(candidate["action"]),
        resource=str(candidate["resource"]),
        warnings=warnings,
    )
    result["source"] = candidate.get("source")
    result["reason"] = candidate.get("reason")
    result["mapping_uuid"] = candidate.get("mapping_uuid")
    return result


def _lambda_iam_role_summary(runtime: AwsRuntime, role_arn: str) -> dict[str, Any]:
    role_name = _role_name_from_arn(role_arn)
    if not role_name:
        return {
            "available": False,
            "role_arn": role_arn or None,
            "role_name": None,
            "warnings": ["Lambda configuration did not include a parseable execution role ARN"],
        }

    client = runtime.client("iam", region=runtime.region)
    warnings: list[str] = []
    role: dict[str, Any] = {}
    attached_policies: list[dict[str, Any]] = []
    inline_policy_names: list[str] = []

    try:
        response = client.get_role(RoleName=role_name)
        role = response.get("Role", {})
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "iam.GetRole")))

    try:
        paginator = client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name, PaginationConfig={"PageSize": 50}):
            for item in page.get("AttachedPolicies", []):
                attached_policies.append(
                    {
                        "policy_name": item.get("PolicyName"),
                        "policy_arn": item.get("PolicyArn"),
                    }
                )
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "iam.ListAttachedRolePolicies")))

    try:
        paginator = client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name, PaginationConfig={"PageSize": 50}):
            inline_policy_names.extend(str(name) for name in page.get("PolicyNames", []))
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "iam.ListRolePolicies")))

    return {
        "available": not warnings,
        "role_arn": role_arn,
        "role_name": role_name,
        "path": role.get("Path"),
        "created_at": isoformat(role.get("CreateDate")),
        "attached_policy_count": len(attached_policies),
        "attached_policies": attached_policies,
        "inline_policy_count": len(inline_policy_names),
        "inline_policy_names": sorted(inline_policy_names),
        "warnings": warnings,
    }


def _role_name_from_arn(role_arn: str) -> str | None:
    match = re.fullmatch(r"arn:aws[a-zA-Z-]*:iam::\d{12}:role/(.+)", role_arn)
    if not match:
        return None
    return match.group(1).rsplit("/", maxsplit=1)[-1]


def _lambda_unresolved_resource_hints(
    summary: dict[str, Any],
    iam_role: dict[str, Any],
) -> list[dict[str, Any]]:
    """Infer likely hidden dependencies from names only.

    Environment values and IAM policy documents are intentionally not returned
    here; hints are based on safe metadata such as environment variable keys and
    policy names.
    """

    hints: list[dict[str, Any]] = []
    for key in summary.get("environment_variable_keys", []):
        service = _likely_service_from_name(str(key))
        if service is None:
            continue
        hints.append(
            {
                "source": "environment_variable_key",
                "key": str(key),
                "likely_service": service,
                "reason": (
                    f"Environment key {key} suggests a {service} dependency, "
                    "but environment values are not returned."
                ),
            }
        )

    for policy_name in iam_role.get("inline_policy_names", []):
        service = _likely_service_from_name(str(policy_name))
        if service is None:
            continue
        hints.append(
            {
                "source": "inline_policy_name",
                "name": str(policy_name),
                "likely_service": service,
                "reason": f"Inline policy name {policy_name} suggests {service} access.",
            }
        )

    for policy in iam_role.get("attached_policies", []):
        policy_name = str(policy.get("policy_name") or "")
        service = _likely_service_from_name(policy_name)
        if service is None:
            continue
        hints.append(
            {
                "source": "attached_policy_name",
                "name": policy_name,
                "likely_service": service,
                "reason": f"Attached policy name {policy_name} suggests {service} access.",
            }
        )
    return _dedupe_unresolved_resource_hints(hints)


def _likely_service_from_name(value: str) -> str | None:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.lower())
    tokens = {token for token in normalized.split("_") if token}
    compact = "".join(tokens)
    if tokens & {"bucket", "s3"} or "bucket" in compact:
        return "s3"
    if tokens & {"table", "ddb", "dynamodb"} or "dynamo" in compact:
        return "dynamodb"
    if tokens & {"queue", "sqs"} or "queue" in compact:
        return "sqs"
    if tokens & {"topic", "sns"} or "topic" in compact:
        return "sns"
    if tokens & {"eventbridge", "events", "event", "bus"} or "eventbus" in compact:
        return "eventbridge"
    if tokens & {"parameter", "parameters", "param", "ssm"} or "parameter" in compact:
        return "ssm"
    if tokens & {"secret", "secrets", "secretsmanager"} or "secret" in compact:
        return "secretsmanager"
    if tokens & {"key", "kms"}:
        return "kms"
    return None


def _dedupe_unresolved_resource_hints(
    hints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for hint in hints:
        identifier = str(hint.get("key") or hint.get("name") or "")
        key = (str(hint.get("source")), identifier, str(hint.get("likely_service")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hint)
    return deduped


def _require_iam_action(action: str) -> str:
    normalized = action.strip()
    if not normalized:
        raise ToolInputError("action is required")
    if ":" not in normalized:
        raise ToolInputError("action must be an IAM action like dynamodb:PutItem")
    return normalized


def _require_arn(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ToolInputError(f"{label} is required")
    if not normalized.startswith("arn:"):
        raise ToolInputError(f"{label} must be an AWS ARN")
    return normalized


def _require_queue_url(queue_url: str) -> str:
    normalized = queue_url.strip()
    if not normalized:
        raise ToolInputError("queue_url is required")
    if not normalized.startswith(("http://", "https://")):
        raise ToolInputError("queue_url must start with http:// or https://")
    return normalized


def _sqs_queue_context(
    runtime: AwsRuntime,
    queue_url: str,
    region: str,
    warnings: list[str],
) -> dict[str, Any]:
    sqs = runtime.client("sqs", region=region)
    try:
        response = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "sqs.GetQueueAttributes")))
        return {
            "available": False,
            "queue_url": queue_url,
            "queue_name": queue_url.rstrip("/").rsplit("/", 1)[-1],
        }
    attributes = response.get("Attributes", {})
    queue_arn = str(attributes.get("QueueArn") or "")
    return {
        "available": True,
        "queue_url": queue_url,
        "queue_name": queue_url.rstrip("/").rsplit("/", 1)[-1],
        "queue_arn": queue_arn or None,
        "fifo": queue_url.endswith(".fifo") or queue_arn.endswith(".fifo"),
        "region": _arn_region(queue_arn),
        "account_id": _arn_account(queue_arn),
        "encryption": {
            "kms_master_key_id": attributes.get("KmsMasterKeyId") or None,
            "sqs_managed_sse": _optional_bool(attributes.get("SqsManagedSseEnabled")),
        },
        "policy": {
            "available": bool(attributes.get("Policy")),
            "statement_count": _policy_statement_count(attributes.get("Policy")),
        },
        "policy_document": _parse_policy_document(attributes.get("Policy")),
    }


def _lambda_sqs_queue_policy_check(queue: dict[str, Any], role_arn: str) -> dict[str, Any]:
    policy = queue.get("policy_document")
    queue_arn = str(queue.get("queue_arn") or "")
    if not isinstance(policy, dict) or not policy:
        return {
            "enabled": True,
            "source": "queue_policy",
            "decision": "not_present",
            "allows_lambda_role": None,
            "reason": "Queue policy is not present; same-account IAM may still allow SendMessage.",
        }
    decision = _resource_policy_decision(policy, role_arn, "sqs:SendMessage", queue_arn)
    return {
        "enabled": True,
        "source": "queue_policy",
        "decision": decision,
        "allows_lambda_role": decision == "allowed",
        "reason": "Queue policy was checked for Lambda execution role SendMessage access.",
    }


def _lambda_sqs_sendability_signals(
    *,
    summary: dict[str, Any],
    queue: dict[str, Any],
    identity_check: dict[str, Any],
    queue_policy_check: dict[str, Any],
    region: str,
) -> dict[str, Any]:
    lambda_arn = str(summary.get("function_arn") or "")
    return {
        "identity_allows_send_message": identity_check.get("allowed"),
        "queue_policy_allows_role": queue_policy_check.get("allows_lambda_role"),
        "queue_policy_decision": queue_policy_check.get("decision"),
        "region_matches": not queue.get("region") or queue.get("region") == region,
        "account_matches": not _arn_account(lambda_arn)
        or not queue.get("account_id")
        or _arn_account(lambda_arn) == queue.get("account_id"),
        "fifo_queue": bool(queue.get("fifo")),
        "kms_key_configured": bool((queue.get("encryption") or {}).get("kms_master_key_id")),
        "queue_available": bool(queue.get("available")),
    }


def _lambda_sqs_sendability_summary(signals: dict[str, Any]) -> dict[str, Any]:
    blockers = []
    if signals.get("queue_available") is False:
        blockers.append("queue_unavailable")
    if signals.get("identity_allows_send_message") is False:
        blockers.append("identity_policy_denies_send_message")
    if signals.get("queue_policy_decision") in {"denied", "explicit_deny"}:
        blockers.append("queue_policy_does_not_allow_lambda_role")
    if signals.get("region_matches") is False:
        blockers.append("region_mismatch")
    if signals.get("account_matches") is False:
        blockers.append("account_mismatch")
    return {
        "status": "blocked" if blockers else "likely_sendable",
        "blockers": blockers,
        "caution_count": sum(1 for key in ["fifo_queue", "kms_key_configured"] if signals.get(key)),
    }


def _lambda_sqs_sendability_next_checks(signals: dict[str, Any]) -> list[str]:
    checks = []
    if signals.get("identity_allows_send_message") is not True:
        checks.append("Confirm Lambda execution role allows sqs:SendMessage on the queue ARN.")
    if signals.get("queue_policy_decision") in {"denied", "explicit_deny", "unknown"}:
        checks.append("Inspect the queue resource policy for the Lambda execution role.")
    if signals.get("kms_key_configured"):
        checks.append("Check KMS key policy and role permissions for encrypted queue sends.")
    if signals.get("fifo_queue"):
        checks.append("Confirm function code supplies MessageGroupId for FIFO sends.")
    if not checks:
        checks.append("No obvious static blocker found for Lambda to send SQS messages.")
    return checks


def _resource_policy_decision(
    policy: dict[str, Any],
    principal_arn: str,
    action: str,
    resource_arn: str,
) -> str:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    decision = "unknown"
    for statement in statements if isinstance(statements, list) else []:
        if not isinstance(statement, dict):
            continue
        if not _policy_principal_matches(statement.get("Principal"), principal_arn):
            continue
        if not _policy_action_matches(statement.get("Action"), action):
            continue
        if not _policy_resource_matches(statement.get("Resource"), resource_arn):
            continue
        if statement.get("Effect") == "Deny":
            return "explicit_deny"
        if statement.get("Effect") == "Allow":
            decision = "allowed"
    return decision


def _policy_statement_count(raw_policy: Any) -> int:
    policy = _parse_policy_document(raw_policy)
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    if isinstance(statements, dict):
        return 1
    return len(statements) if isinstance(statements, list) else 0


def _policy_principal_matches(principal: Any, principal_arn: str) -> bool:
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    aws_principal = principal.get("AWS")
    if isinstance(aws_principal, str):
        return aws_principal in {principal_arn, "*"}
    if isinstance(aws_principal, list):
        return principal_arn in aws_principal or "*" in aws_principal
    return False


def _policy_action_matches(actions: Any, action: str) -> bool:
    if isinstance(actions, str):
        return actions in {action, "sqs:*", "*"}
    if isinstance(actions, list):
        return action in actions or "sqs:*" in actions or "*" in actions
    return False


def _policy_resource_matches(resources: Any, resource_arn: str) -> bool:
    if not resources:
        return True
    if isinstance(resources, str):
        return resources in {resource_arn, "*"}
    if isinstance(resources, list):
        return resource_arn in resources or "*" in resources
    return False


def _arn_region(value: str) -> str | None:
    parts = value.split(":")
    return parts[3] if len(parts) >= 6 and parts[0] == "arn" else None


def _arn_account(value: str) -> str | None:
    parts = value.split(":")
    return parts[4] if len(parts) >= 6 and parts[0] == "arn" else None


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    return str(value).lower() == "true"


def _permission_path_unknown_result(
    *,
    function_name: str,
    region: str,
    action: str,
    resource_arn: str,
    role_arn: str | None,
    warnings: list[str],
) -> dict[str, Any]:
    role_name = _role_name_from_arn(role_arn or "")
    return {
        "function_name": function_name,
        "region": region,
        "principal": {
            "type": "lambda_execution_role",
            "role_name": role_name,
            "role_arn": role_arn,
        },
        "action": action,
        "resource_arn": resource_arn,
        "decision": "unknown",
        "allowed": None,
        "explicit_deny": None,
        "matched_statements": [],
        "missing_context_values": [],
        "warnings": warnings,
    }


def _simulate_lambda_role_permission(
    *,
    runtime: AwsRuntime,
    function_name: str,
    region: str,
    role_arn: str,
    action: str,
    resource: str,
    warnings: list[str],
) -> dict[str, Any]:
    role_name = _role_name_from_arn(role_arn)
    if not role_name:
        return _permission_path_unknown_result(
            function_name=function_name,
            region=region,
            action=action,
            resource_arn=resource,
            role_arn=role_arn or None,
            warnings=[
                *warnings,
                "Lambda configuration did not include a parseable execution role ARN",
            ],
        )

    iam = runtime.client("iam", region=runtime.region)
    try:
        response = iam.simulate_principal_policy(
            PolicySourceArn=role_arn,
            ActionNames=[action],
            ResourceArns=[resource],
        )
    except (BotoCoreError, ClientError) as exc:
        return _permission_path_unknown_result(
            function_name=function_name,
            region=region,
            action=action,
            resource_arn=resource,
            role_arn=role_arn,
            warnings=[
                *warnings,
                str(normalize_aws_error(exc, "iam.SimulatePrincipalPolicy")),
            ],
        )

    evaluation = _simulation_evaluation(response)
    return {
        "function_name": function_name,
        "region": region,
        "principal": {
            "type": "lambda_execution_role",
            "role_name": role_name,
            "role_arn": role_arn,
        },
        "action": action,
        "resource_arn": resource,
        "decision": evaluation["decision"],
        "allowed": evaluation["allowed"],
        "explicit_deny": evaluation["explicit_deny"],
        "matched_statements": evaluation["matched_statements"],
        "missing_context_values": evaluation["missing_context_values"],
        "warnings": warnings,
    }


def _simulation_evaluation(response: dict[str, Any]) -> dict[str, Any]:
    results = response.get("EvaluationResults", [])
    result = results[0] if results else {}
    decision = str(result.get("EvalDecision") or "unknown")
    return {
        "decision": decision,
        "allowed": decision == "allowed",
        "explicit_deny": decision == "explicitDeny",
        "matched_statements": [
            {
                "source_policy_id": statement.get("SourcePolicyId"),
                "source_policy_type": statement.get("SourcePolicyType"),
                "start_position": statement.get("StartPosition"),
                "end_position": statement.get("EndPosition"),
            }
            for statement in result.get("MatchedStatements", [])
        ],
        "missing_context_values": [str(value) for value in result.get("MissingContextValues", [])],
    }


def _lambda_dependency_permission_checks(
    *,
    runtime: AwsRuntime,
    function_name: str,
    region: str,
    role_arn: str,
    dependencies: dict[str, Any],
    include_permission_checks: bool,
    limit: int,
) -> dict[str, Any]:
    """Run bounded IAM simulations for dependency-derived permission hints."""

    if not include_permission_checks:
        return empty_permission_checks()

    candidates = _dedupe_permission_candidates(_lambda_permission_candidates(dependencies))[:limit]
    checks = [
        _permission_check_from_candidate(
            runtime=runtime,
            function_name=function_name,
            region=region,
            role_arn=role_arn,
            candidate=candidate,
        )
        for candidate in candidates
    ]
    return {
        "enabled": True,
        "checked_count": len(checks),
        "checks": checks,
        "summary": _lambda_permission_investigation_summary(checks),
    }


def _lambda_permission_candidates(dependencies: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for hint in dependencies.get("permission_hints", []):
        resource = hint.get("resource")
        if not _simulatable_resource(resource):
            continue
        for action in hint.get("actions_to_check", []):
            candidates.append(
                {
                    "action": str(action),
                    "resource": str(resource),
                    "source": "dependency_hint",
                    "reason": hint.get("reason"),
                }
            )

    nodes = dependencies.get("nodes", {})
    event_sources = (nodes.get("event_sources") or {}).get("event_sources", [])
    for mapping in event_sources:
        source_arn = mapping.get("event_source_arn")
        for action in _event_source_actions(source_arn):
            candidates.append(
                {
                    "action": action,
                    "resource": str(source_arn),
                    "source": "event_source_mapping",
                    "reason": "Lambda event source mappings require poll/read permissions.",
                }
            )
    return candidates


def _dedupe_permission_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for candidate in candidates:
        key = (str(candidate.get("action")), str(candidate.get("resource")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _permission_check_from_candidate(
    *,
    runtime: AwsRuntime,
    function_name: str,
    region: str,
    role_arn: str,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    result = _simulate_lambda_role_permission(
        runtime=runtime,
        function_name=function_name,
        region=region,
        role_arn=role_arn,
        action=str(candidate["action"]),
        resource=str(candidate["resource"]),
        warnings=[],
    )
    result["source"] = candidate.get("source")
    result["reason"] = candidate.get("reason")
    if "evidence" in candidate:
        result["evidence"] = candidate["evidence"]
    return result


def _lambda_permission_investigation_summary(checks: list[dict[str, Any]]) -> dict[str, Any]:
    allowed = sum(1 for check in checks if check.get("allowed") is True)
    denied = sum(1 for check in checks if check.get("allowed") is False)
    unknown = sum(1 for check in checks if check.get("allowed") is None)
    explicit_denies = sum(1 for check in checks if check.get("explicit_deny") is True)
    return {
        "allowed": allowed,
        "denied": denied,
        "unknown": unknown,
        "explicit_denies": explicit_denies,
        "headline": _lambda_permission_headline(allowed, denied, unknown, explicit_denies),
    }


def _lambda_permission_headline(
    allowed: int,
    denied: int,
    unknown: int,
    explicit_denies: int,
) -> str:
    if explicit_denies:
        return f"{explicit_denies} permission check(s) hit an explicit deny."
    if denied:
        return f"{denied} permission check(s) are not allowed by IAM simulation."
    if unknown and not allowed:
        return "Permission checks could not be fully evaluated."
    if unknown:
        return f"{allowed} permission check(s) are allowed; {unknown} could not be evaluated."
    if allowed:
        return f"All {allowed} permission check(s) are allowed by IAM simulation."
    return "No permission checks were inferred."


def _event_source_actions(value: Any) -> list[str]:
    service = _arn_service(value)
    if service == "sqs":
        return ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
    if service == "dynamodb":
        return [
            "dynamodb:DescribeStream",
            "dynamodb:GetRecords",
            "dynamodb:GetShardIterator",
            "dynamodb:ListStreams",
        ]
    if service == "kinesis":
        return [
            "kinesis:DescribeStream",
            "kinesis:GetRecords",
            "kinesis:GetShardIterator",
        ]
    return []


def _simulatable_resource(value: Any) -> bool:
    if not value:
        return False
    resource = str(value)
    return resource == "*" or resource.startswith("arn:")


def _lambda_dependency_edges(
    summary: dict[str, Any],
    event_sources: dict[str, Any],
    log_group_name: str,
    iam_role: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build direct Lambda dependency edges from configuration metadata."""

    function_name = str(summary.get("function_name") or "")
    log_group_resource = _log_group_arn(summary, log_group_name) or log_group_name
    edges: list[dict[str, Any]] = [
        {
            "from": function_name,
            "to": log_group_resource,
            "relationship": "writes_logs_to",
            "target_type": "cloudwatch_log_group",
            "target_name": log_group_name,
        }
    ]
    role_arn = iam_role.get("role_arn")
    if role_arn:
        edges.append(
            {
                "from": function_name,
                "to": role_arn,
                "relationship": "uses_execution_role",
                "target_type": "iam_role",
            }
        )

    vpc = summary.get("vpc") or {}
    if isinstance(vpc, dict) and vpc.get("enabled"):
        edges.append(
            {
                "from": function_name,
                "to": vpc.get("vpc_id"),
                "relationship": "attached_to_vpc",
                "target_type": "vpc",
                "subnet_count": vpc.get("subnet_count"),
                "security_group_count": vpc.get("security_group_count"),
            }
        )

    dead_letter = summary.get("dead_letter") or {}
    if isinstance(dead_letter, dict) and dead_letter.get("configured"):
        edges.append(
            {
                "from": function_name,
                "to": dead_letter.get("target_arn"),
                "relationship": "sends_failed_async_events_to",
                "target_type": _arn_service(dead_letter.get("target_arn")),
            }
        )

    for hint in summary.get("environment_dependency_hints", []):
        service = hint.get("likely_service")
        key = hint.get("key")
        if not service or not key:
            continue
        edges.append(
            {
                "from": function_name,
                "to": f"inferred:{service}:{key}",
                "relationship": "may_depend_on",
                "target_type": service,
                "source": "environment_variable",
                "environment_key": key,
                "value_shape": hint.get("value_shape"),
                "confidence": hint.get("confidence"),
            }
        )

    for mapping in event_sources.get("event_sources", []):
        source_arn = mapping.get("event_source_arn")
        edges.append(
            {
                "from": source_arn,
                "to": function_name,
                "relationship": "triggers",
                "source_type": _arn_service(source_arn),
                "state": mapping.get("state"),
                "batch_size": mapping.get("batch_size"),
            }
        )
    return edges


def _arn_service(value: Any) -> str | None:
    if not value:
        return None
    parts = str(value).split(":")
    if len(parts) < 3 or parts[0] != "arn":
        return None
    return parts[2]


def _log_group_arn(summary: dict[str, Any], log_group_name: str) -> str | None:
    function_arn = str(summary.get("function_arn") or "")
    match = re.fullmatch(
        r"arn:(?P<partition>aws[a-zA-Z-]*):lambda:(?P<region>[^:]+):"
        r"(?P<account>\d{12}):function:.+",
        function_arn,
    )
    if not match:
        return None
    return (
        f"arn:{match.group('partition')}:logs:{match.group('region')}:"
        f"{match.group('account')}:log-group:{log_group_name}:*"
    )


def _lambda_permission_hints(
    edges: list[dict[str, Any]],
    iam_role: dict[str, Any],
) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    role_arn = iam_role.get("role_arn")
    for edge in edges:
        relationship = edge.get("relationship")
        target_type = edge.get("target_type") or edge.get("source_type")
        if relationship == "writes_logs_to":
            hints.append(
                {
                    "principal": role_arn,
                    "resource": edge.get("to"),
                    "actions_to_check": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "reason": (
                        "Lambda execution roles need CloudWatch Logs permissions to emit logs."
                    ),
                }
            )
        if relationship == "attached_to_vpc":
            hints.append(
                {
                    "principal": role_arn,
                    "resource": edge.get("to"),
                    "actions_to_check": [
                        "ec2:CreateNetworkInterface",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DeleteNetworkInterface",
                    ],
                    "reason": (
                        "VPC-enabled Lambdas need ENI permissions, commonly via "
                        "AWSLambdaVPCAccessExecutionRole."
                    ),
                }
            )
        if relationship == "sends_failed_async_events_to" and target_type:
            hints.append(
                {
                    "principal": role_arn,
                    "resource": edge.get("to"),
                    "actions_to_check": _dead_letter_actions(target_type),
                    "reason": (
                        "Dead-letter targets require publish/send permissions from the Lambda role."
                    ),
                }
            )
    return hints


def _dead_letter_actions(target_type: str) -> list[str]:
    if target_type == "sqs":
        return ["sqs:SendMessage"]
    if target_type == "sns":
        return ["sns:Publish"]
    return []


def _lambda_dependency_warnings(
    summary: dict[str, Any],
    aliases: dict[str, Any],
    event_sources: dict[str, Any],
    iam_role: dict[str, Any],
) -> list[str]:
    warnings = _lambda_summary_warnings(summary)
    for section in [aliases, event_sources, iam_role]:
        section_warnings = section.get("warnings", [])
        if isinstance(section_warnings, list):
            warnings.extend(str(warning) for warning in section_warnings)
    return warnings


def _empty_lambda_metrics(warning: str) -> dict[str, Any]:
    empty = _empty_metric_summary()
    return {
        "available": False,
        "warnings": [warning],
        "window_minutes": 60,
        "errors": empty,
        "throttles": empty,
        "invocations": empty,
        "max_duration_ms": empty,
    }


def _empty_metric_summary() -> dict[str, Any]:
    return {"datapoints": 0, "value": 0, "latest_timestamp": None}


def _lambda_metric_data_queries(function_name: str) -> list[dict[str, Any]]:
    return [
        _lambda_metric_data_query("errors", "Errors", "Sum", function_name),
        _lambda_metric_data_query("throttles", "Throttles", "Sum", function_name),
        _lambda_metric_data_query("invocations", "Invocations", "Sum", function_name),
        _lambda_metric_data_query("duration", "Duration", "Maximum", function_name),
    ]


def _lambda_metric_data_query(
    metric_id: str,
    metric_name: str,
    stat: str,
    function_name: str,
) -> dict[str, Any]:
    return {
        "Id": metric_id,
        "MetricStat": {
            "Metric": {
                "Namespace": "AWS/Lambda",
                "MetricName": metric_name,
                "Dimensions": [{"Name": "FunctionName", "Value": function_name}],
            },
            "Period": 300,
            "Stat": stat,
        },
        "ReturnData": True,
    }


def _summarize_metric_data_result(result: dict[str, Any]) -> dict[str, Any]:
    values = [float(value) for value in result.get("Values", [])]
    timestamps = result.get("Timestamps", [])
    if not values:
        return _empty_metric_summary()

    value = max(values) if result.get("Id") == "duration" else sum(values)
    latest = max(timestamps) if timestamps else None

    return {
        "datapoints": len(values),
        "value": value,
        "latest_timestamp": isoformat(latest),
    }


def _metric_data_warnings(results: list[dict[str, Any]]) -> list[str]:
    warnings = []
    for result in results:
        status = result.get("StatusCode")
        if status and status != "Complete":
            warnings.append(f"Metric {result.get('Id')} returned status {status}")
    return warnings


def _log_event_summary(event: dict[str, Any], max_string_length: int) -> dict[str, Any]:
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


def _lambda_failure_signals(
    summary: dict[str, Any],
    recent_errors: dict[str, Any],
) -> dict[str, Any]:
    metrics = summary.get("recent_metrics", {})
    error_groups = recent_errors.get("groups", [])
    messages = " ".join(str(group.get("sample_message", "")) for group in error_groups)

    errors = _metric_value(metrics, "errors")
    throttles = _metric_value(metrics, "throttles")
    invocations = _metric_value(metrics, "invocations")
    max_duration_ms = _metric_value(metrics, "max_duration_ms")
    timeout_seconds = float(summary.get("timeout_seconds") or 0)

    return {
        "errors_last_hour": errors,
        "throttles_last_hour": throttles,
        "invocations_last_hour": invocations,
        "max_duration_ms_last_hour": max_duration_ms,
        "recent_log_error_groups": len(error_groups),
        "timeout_configured_seconds": timeout_seconds,
        "timeout_indicators": _has_timeout_indicators(messages, max_duration_ms, timeout_seconds),
        "memory_indicators": _has_memory_indicators(messages),
        "permission_indicators": _has_permission_indicators(messages),
        "throttle_indicators": throttles > 0,
        "vpc_enabled": bool((summary.get("vpc") or {}).get("enabled")),
        "dead_letter_configured": bool((summary.get("dead_letter") or {}).get("configured")),
    }


def _lambda_summary_warnings(summary: dict[str, Any]) -> list[str]:
    metrics = summary.get("recent_metrics", {})
    if not isinstance(metrics, dict):
        return []
    warnings = metrics.get("warnings", [])
    if not isinstance(warnings, list):
        return []
    return [str(warning) for warning in warnings]


def _metric_value(metrics: dict[str, Any], name: str) -> float:
    metric = metrics.get(name, {})
    if not isinstance(metric, dict):
        return 0.0
    return float(metric.get("value") or 0)


def _has_timeout_indicators(messages: str, max_duration_ms: float, timeout_seconds: float) -> bool:
    lower = messages.lower()
    if "task timed out" in lower or "timeout" in lower or "timed out" in lower:
        return True
    if timeout_seconds <= 0 or max_duration_ms <= 0:
        return False
    return max_duration_ms >= timeout_seconds * 1000 * 0.9


def _has_memory_indicators(messages: str) -> bool:
    lower = messages.lower()
    return any(
        pattern in lower
        for pattern in [
            "outofmemory",
            "out of memory",
            "memoryerror",
            "runtime exited with error",
            "signal: killed",
        ]
    )


def _has_permission_indicators(messages: str) -> bool:
    lower = messages.lower()
    return any(
        pattern in lower
        for pattern in [
            "accessdenied",
            "access denied",
            "unauthorized",
            "not authorized",
            "permission",
            "explicit deny",
        ]
    )


def _lambda_diagnostic_summary(signals: dict[str, Any]) -> str:
    if signals["recent_log_error_groups"] == 0 and signals["errors_last_hour"] == 0:
        return (
            "No recent Lambda error logs or CloudWatch error metrics were found "
            "in the requested window."
        )

    findings: list[str] = []
    if signals["timeout_indicators"]:
        findings.append("timeout indicators")
    if signals["memory_indicators"]:
        findings.append("memory pressure indicators")
    if signals["permission_indicators"]:
        findings.append("permission or access-denied indicators")
    if signals["throttle_indicators"]:
        findings.append("throttling")

    if findings:
        return "Recent failures show " + ", ".join(findings) + "."
    return (
        "Recent failures were found, but no single dominant timeout, memory, "
        "permission, or throttle pattern was detected."
    )


def _lambda_suggested_next_checks(signals: dict[str, Any]) -> list[str]:
    checks: list[str] = []
    if signals["timeout_indicators"]:
        checks.append(
            "Compare max duration with configured timeout and inspect slow downstream calls."
        )
    if signals["memory_indicators"]:
        checks.append(
            "Check Lambda max memory usage and consider increasing memory or reducing payload size."
        )
    if signals["permission_indicators"]:
        checks.append("Review the Lambda execution role policy for the denied AWS action/resource.")
    if signals["throttle_indicators"]:
        checks.append(
            "Check reserved concurrency, account concurrency, and upstream retry behavior."
        )
    if signals["vpc_enabled"]:
        checks.append(
            "For VPC Lambdas, verify subnet routing, NAT access, security groups, "
            "and DNS resolution."
        )
    if not signals["dead_letter_configured"]:
        checks.append(
            "Consider configuring a DLQ or failure destination for asynchronous invocations."
        )
    if not checks:
        checks.append(
            "Inspect the grouped log samples and correlate timestamps with recent deployments or "
            "upstream events."
        )
    return checks
