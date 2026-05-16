from __future__ import annotations

import ipaddress
import re
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
