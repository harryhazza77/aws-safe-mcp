from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.config import RedactionConfig
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.redaction import REDACTED, is_secret_like_key, truncate_string
from aws_safe_mcp.tools.common import clamp_limit, clamp_since_minutes, isoformat, resolve_region
from aws_safe_mcp.tools.downstream import (
    event_driven_downstream_hints as _event_driven_downstream_hints,
)
from aws_safe_mcp.tools.graph import dependency_graph_summary, empty_permission_checks
from aws_safe_mcp.tools.lambda_tools import explain_lambda_dependencies
from aws_safe_mcp.tools.stepfunctions import explain_step_function_dependencies

EVENTBRIDGE_METRICS = [
    "Invocations",
    "FailedInvocations",
    "DeadLetterInvocations",
    "InvocationsSentToDLQ",
    "InvocationsFailedToBeSentToDLQ",
    "TriggeredRules",
    "MatchedEvents",
]


def list_eventbridge_rules(
    runtime: AwsRuntime,
    region: str | None = None,
    event_bus_name: str | None = None,
    name_prefix: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    """List EventBridge rules with target counts and target service summaries."""

    resolved_region = resolve_region(runtime, region)
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    client = runtime.client("events", region=resolved_region)
    warnings: list[str] = []
    buses = (
        [{"name": _require_event_bus_name(event_bus_name), "arn": None}]
        if event_bus_name
        else _list_event_buses(client, limit, warnings)
    )

    rules: list[dict[str, Any]] = []
    for bus in buses:
        bus_name = str(bus["name"])
        for rule in _list_rules_for_bus(
            client,
            bus_name,
            name_prefix,
            limit - len(rules),
            warnings,
        ):
            target_summary = _rule_target_summary(client, bus_name, str(rule.get("Name")), warnings)
            rules.append(_rule_list_item(rule, bus_name, target_summary))
            if len(rules) >= limit:
                break
        if len(rules) >= limit:
            break

    return {
        "region": resolved_region,
        "event_bus_name": event_bus_name,
        "name_prefix": name_prefix,
        "max_results": limit,
        "event_bus_count": len(buses),
        "count": len(rules),
        "event_buses": buses if not event_bus_name else [],
        "rules": rules,
        "warnings": warnings,
    }


def get_eventbridge_time_sources(
    runtime: AwsRuntime,
    region: str | None = None,
    event_bus_name: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    events = runtime.client("events", region=resolved_region)
    warnings: list[str] = []
    scheduled_rules = _scheduled_rules(events, event_bus_name, limit, warnings)
    archives = _eventbridge_archives(events, event_bus_name, limit, warnings)
    replays = _eventbridge_replays(events, limit, warnings)
    schedules = _scheduler_schedules(runtime, resolved_region, limit, warnings)
    return {
        "region": resolved_region,
        "event_bus_name": event_bus_name,
        "max_results": limit,
        "scheduled_rules": scheduled_rules,
        "scheduler_schedules": schedules,
        "archives": archives,
        "replays": replays,
        "summary": {
            "scheduled_rule_count": len(scheduled_rules),
            "scheduler_schedule_count": len(schedules),
            "archive_count": len(archives),
            "replay_count": len(replays),
        },
        "warnings": warnings,
    }


def explain_eventbridge_rule_dependencies(
    runtime: AwsRuntime,
    rule_name: str,
    event_bus_name: str | None = None,
    region: str | None = None,
    include_permission_checks: bool = True,
    max_permission_checks: int | None = None,
) -> dict[str, Any]:
    """Explain one EventBridge rule's targets, DLQs, roles, and permission paths."""

    resolved_region = resolve_region(runtime, region)
    required_rule = _require_rule_name(rule_name)
    required_bus = event_bus_name or "default"
    limit = clamp_limit(
        max_permission_checks,
        default=20,
        configured_max=runtime.config.max_results,
        label="max_permission_checks",
    )
    client = runtime.client("events", region=resolved_region)
    warnings: list[str] = []
    rule = _describe_rule(client, required_rule, required_bus)
    targets = _list_targets_for_rule(
        client,
        required_bus,
        required_rule,
        runtime.config.max_results,
    )
    target_nodes = [_target_summary(target) for target in targets]
    dlq_nodes = [
        _dlq_summary(runtime, resolved_region, target, warnings)
        for target in targets
        if _dlq_arn(target)
    ]
    role_nodes = _role_nodes(rule, targets)
    edges = _eventbridge_edges(rule, required_bus, target_nodes, dlq_nodes, role_nodes)
    permission_hints = _eventbridge_permission_hints(rule, required_bus, target_nodes)
    permission_checks = _eventbridge_permission_checks(
        runtime=runtime,
        region=resolved_region,
        rule=rule,
        event_bus_name=required_bus,
        targets=target_nodes,
        dead_letter_queues=dlq_nodes,
        include_permission_checks=include_permission_checks,
        limit=limit,
        warnings=warnings,
    )
    nodes = {
        "event_bus": {
            "name": required_bus,
            "arn": _event_bus_arn_from_rule(rule, required_bus),
        },
        "rule": _rule_node(rule, required_bus, runtime.config.redaction.max_string_length),
        "targets": target_nodes,
        "dead_letter_queues": dlq_nodes,
        "roles": role_nodes,
    }

    return {
        "name": required_rule,
        "arn": rule.get("Arn"),
        "rule_name": required_rule,
        "event_bus_name": required_bus,
        "region": resolved_region,
        "resource_type": "eventbridge_rule",
        "summary": {
            "state": rule.get("State"),
            "schedule_expression": rule.get("ScheduleExpression"),
            "has_event_pattern": bool(rule.get("EventPattern")),
            "managed_by": rule.get("ManagedBy"),
            "target_count": len(target_nodes),
            "target_types": sorted({str(target["target_type"]) for target in target_nodes}),
            "dlq_count": len(dlq_nodes),
        },
        "graph_summary": dependency_graph_summary(
            nodes=nodes,
            edges=edges,
            permission_checks=permission_checks,
            warnings=warnings,
        ),
        "nodes": nodes,
        "edges": edges,
        "permission_hints": permission_hints,
        "permission_checks": permission_checks,
        "warnings": warnings,
    }


def investigate_eventbridge_rule_delivery(
    runtime: AwsRuntime,
    rule_name: str,
    event_bus_name: str | None = None,
    region: str | None = None,
    since_minutes: int | None = 60,
) -> dict[str, Any]:
    """Diagnose EventBridge delivery using config, metrics, DLQs, and permissions."""

    resolved_region = resolve_region(runtime, region)
    window_minutes = clamp_since_minutes(
        since_minutes,
        default=60,
        configured_max=runtime.config.max_since_minutes,
    )
    dependencies = explain_eventbridge_rule_dependencies(
        runtime,
        rule_name=rule_name,
        event_bus_name=event_bus_name,
        region=resolved_region,
    )
    metrics = _eventbridge_metric_summary(
        runtime,
        rule_name=str(dependencies["rule_name"]),
        event_bus_name=str(dependencies["event_bus_name"]),
        region=resolved_region,
        since_minutes=window_minutes,
    )
    warnings = [*dependencies.get("warnings", []), *metrics.get("warnings", [])]
    signals = _delivery_signals(dependencies, metrics)

    return {
        "rule_name": dependencies["rule_name"],
        "event_bus_name": dependencies["event_bus_name"],
        "region": resolved_region,
        "window_minutes": window_minutes,
        "diagnostic_summary": _delivery_diagnostic_summary(dependencies, signals),
        "configuration": {
            "summary": dependencies["summary"],
            "targets": dependencies["nodes"]["targets"],
            "dead_letter_queues": dependencies["nodes"]["dead_letter_queues"],
        },
        "metrics": metrics,
        "permission_checks": dependencies["permission_checks"],
        "signals": signals,
        "suggested_next_checks": _delivery_suggested_next_checks(signals),
        "warnings": warnings,
    }


def explain_event_driven_flow(
    runtime: AwsRuntime,
    name_fragment: str | None = None,
    event_source: str | None = None,
    detail_type: str | None = None,
    detail_path: str | None = None,
    detail_value: str | None = None,
    region: str | None = None,
    max_rules: int | None = 10,
) -> dict[str, Any]:
    """Stitch EventBridge, Step Functions, and Lambda dependencies from intent fields."""

    criteria = _flow_criteria(
        name_fragment=name_fragment,
        event_source=event_source,
        detail_type=detail_type,
        detail_path=detail_path,
        detail_value=detail_value,
    )
    resolved_region = resolve_region(runtime, region)
    limit = clamp_limit(
        max_rules,
        default=10,
        configured_max=runtime.config.max_results,
        label="max_rules",
    )
    client = runtime.client("events", region=resolved_region)
    warnings: list[str] = []
    buses = _list_event_buses(client, limit, warnings)
    matched_rules: list[dict[str, Any]] = []
    scanned_rule_count = 0

    for bus in buses:
        bus_name = str(bus["name"])
        for rule in _list_rules_for_bus(
            client,
            bus_name,
            None,
            runtime.config.max_results,
            warnings,
        ):
            scanned_rule_count += 1
            if not _rule_matches_flow_criteria(rule, bus_name, criteria):
                continue
            matched_rules.append({"name": rule.get("Name"), "event_bus_name": bus_name})
            if len(matched_rules) >= limit:
                break
        if len(matched_rules) >= limit:
            break

    rule_flows: list[dict[str, Any]] = []
    nodes: dict[str, list[dict[str, Any]]] = {
        "eventbridge_rules": [],
        "step_functions": [],
        "lambdas": [],
    }
    edges: list[dict[str, Any]] = []
    permission_summaries: list[dict[str, Any]] = []

    for match in matched_rules:
        rule_flow = _expand_eventbridge_flow_rule(
            runtime=runtime,
            region=resolved_region,
            rule_name=str(match["name"]),
            event_bus_name=str(match["event_bus_name"]),
            warnings=warnings,
        )
        rule_flows.append(rule_flow)
        nodes["eventbridge_rules"].append(rule_flow["rule"])
        nodes["step_functions"].extend(rule_flow["step_functions"])
        nodes["lambdas"].extend(rule_flow["lambdas"])
        edges.extend(rule_flow["edges"])
        permission_summaries.extend(rule_flow["permission_summaries"])

    nodes = {key: _dedupe_named_nodes(value) for key, value in nodes.items()}
    permission_checks = {
        "enabled": True,
        "checked_count": sum(int(item.get("checked_count") or 0) for item in permission_summaries),
        "checks": [],
        "summary": _combined_permission_summary(permission_summaries),
    }
    flow_paths = _event_driven_flow_paths(rule_flows)
    downstream_hints = _event_driven_downstream_hints(runtime, rule_flows, warnings)
    key_findings = _event_driven_key_findings(
        rule_flows,
        permission_checks,
        warnings,
        downstream_hints,
    )

    return {
        "resource_type": "event_driven_flow",
        "region": resolved_region,
        "query": criteria,
        "matched_rule_count": len(matched_rules),
        "scanned_rule_count": scanned_rule_count,
        "summary": {
            "eventbridge_rule_count": len(nodes["eventbridge_rules"]),
            "step_function_count": len(nodes["step_functions"]),
            "lambda_count": len(nodes["lambdas"]),
            "path_count": len(rule_flows),
        },
        "diagnostic_summary": _event_driven_diagnostic_summary(
            matched_rule_count=len(matched_rules),
            flow_paths=flow_paths,
            permission_checks=permission_checks,
            warnings=warnings,
        ),
        "key_findings": key_findings,
        "flow_paths": flow_paths,
        "downstream_hints": downstream_hints,
        "graph_summary": dependency_graph_summary(
            nodes=nodes,
            edges=edges,
            permission_checks=permission_checks,
            warnings=warnings,
        ),
        "nodes": nodes,
        "edges": edges,
        "flows": rule_flows,
        "permission_checks": permission_checks,
        "warnings": warnings,
        "suggested_next_checks": _flow_suggested_next_checks(rule_flows, warnings),
    }


def _flow_criteria(
    *,
    name_fragment: str | None,
    event_source: str | None,
    detail_type: str | None,
    detail_path: str | None,
    detail_value: str | None,
) -> dict[str, str | None]:
    criteria = {
        "name_fragment": _normalized_optional(name_fragment),
        "event_source": _normalized_optional(event_source),
        "detail_type": _normalized_optional(detail_type),
        "detail_path": _normalized_optional(detail_path),
        "detail_value": _normalized_optional(detail_value),
    }
    if not any(criteria.values()):
        raise ToolInputError(
            "At least one of name_fragment, event_source, detail_type, or detail_path is required"
        )
    return criteria


def _rule_matches_flow_criteria(
    rule: dict[str, Any],
    event_bus_name: str,
    criteria: dict[str, str | None],
) -> bool:
    pattern = _parse_event_pattern(rule.get("EventPattern"))
    rendered = json.dumps(pattern, sort_keys=True).lower() if pattern is not None else ""
    checks: list[bool] = []
    if criteria["name_fragment"]:
        fragment = criteria["name_fragment"] or ""
        checks.append(
            any(
                (
                    fragment in str(rule.get("Name") or "").lower(),
                    fragment in event_bus_name.lower(),
                    fragment in str(rule.get("Arn") or "").lower(),
                    fragment in rendered,
                )
            )
        )
    if criteria["event_source"]:
        checks.append(_pattern_value_contains(pattern, ["source"], criteria["event_source"] or ""))
    if criteria["detail_type"]:
        checks.append(
            _pattern_value_contains(pattern, ["detail-type"], criteria["detail_type"] or "")
        )
    if criteria["detail_path"]:
        path = _event_pattern_path(criteria["detail_path"] or "")
        if criteria["detail_value"]:
            checks.append(_pattern_value_contains(pattern, path, criteria["detail_value"] or ""))
        else:
            checks.append(_pattern_path_exists(pattern, path))
    return all(checks)


def _expand_eventbridge_flow_rule(
    *,
    runtime: AwsRuntime,
    region: str,
    rule_name: str,
    event_bus_name: str,
    warnings: list[str],
) -> dict[str, Any]:
    dependencies = explain_eventbridge_rule_dependencies(
        runtime,
        rule_name=rule_name,
        event_bus_name=event_bus_name,
        region=region,
    )
    rule_node = dependencies["nodes"]["rule"]
    flow = {
        "rule": {
            "name": rule_node.get("name"),
            "arn": rule_node.get("arn"),
            "event_bus_name": event_bus_name,
            "state": rule_node.get("state"),
            "event_pattern": rule_node.get("event_pattern"),
        },
        "targets": dependencies["nodes"]["targets"],
        "step_functions": [],
        "lambdas": [],
        "edges": list(dependencies.get("edges", [])),
        "permission_summaries": [
            {
                "source": "eventbridge",
                "name": rule_name,
                **dependencies["permission_checks"]["summary"],
                "checked_count": dependencies["permission_checks"]["checked_count"],
            }
        ],
        "warnings": list(dependencies.get("warnings", [])),
    }
    for target in dependencies["nodes"]["targets"]:
        if target.get("target_type") == "stepfunctions":
            _follow_step_function_target(runtime, region, target, flow, warnings)
        elif target.get("target_type") == "lambda":
            _follow_lambda_target(runtime, region, target.get("arn"), flow, warnings)
    return flow


def _follow_step_function_target(
    runtime: AwsRuntime,
    region: str,
    target: dict[str, Any],
    flow: dict[str, Any],
    warnings: list[str],
) -> None:
    target_arn = str(target.get("arn") or "")
    try:
        dependencies = explain_step_function_dependencies(
            runtime,
            state_machine_arn=target_arn,
            region=region,
        )
    except Exception as exc:  # noqa: BLE001 - flow expansion should preserve partial graph
        warning = f"stepfunctions {target_arn}: {exc}"
        warnings.append(warning)
        flow["warnings"].append(warning)
        return

    flow["step_functions"].append(
        {
            "name": dependencies.get("name"),
            "arn": dependencies.get("arn"),
            "summary": dependencies.get("summary"),
            "flow_summary": dependencies.get("flow_summary"),
        }
    )
    flow["edges"].extend(dependencies.get("edges", []))
    flow["permission_summaries"].append(
        {
            "source": "stepfunctions",
            "name": dependencies.get("name"),
            **dependencies["permission_checks"]["summary"],
            "checked_count": dependencies["permission_checks"]["checked_count"],
        }
    )
    for edge in dependencies.get("edges", []):
        if edge.get("target_type") == "lambda":
            _follow_lambda_target(runtime, region, edge.get("to"), flow, warnings)


def _follow_lambda_target(
    runtime: AwsRuntime,
    region: str,
    target_arn: Any,
    flow: dict[str, Any],
    warnings: list[str],
) -> None:
    function_name = _lambda_name_from_arn(target_arn)
    if not function_name:
        return
    if any(item.get("name") == function_name for item in flow["lambdas"]):
        return
    try:
        dependencies = explain_lambda_dependencies(
            runtime,
            function_name=function_name,
            region=region,
        )
    except Exception as exc:  # noqa: BLE001 - flow expansion should preserve partial graph
        warning = f"lambda {function_name}: {exc}"
        warnings.append(warning)
        flow["warnings"].append(warning)
        return

    flow["lambdas"].append(
        {
            "name": dependencies.get("name"),
            "arn": dependencies.get("arn"),
            "summary": dependencies.get("summary"),
            "execution_role": (dependencies.get("nodes") or {}).get("execution_role") or {},
            "unresolved_resource_hints": dependencies.get("unresolved_resource_hints", []),
        }
    )
    flow["edges"].extend(dependencies.get("edges", []))
    flow["permission_summaries"].append(
        {
            "source": "lambda",
            "name": dependencies.get("name"),
            **dependencies["permission_checks"]["summary"],
            "checked_count": dependencies["permission_checks"]["checked_count"],
        }
    )


def _combined_permission_summary(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    allowed = sum(int(item.get("allowed") or 0) for item in summaries)
    denied = sum(int(item.get("denied") or 0) for item in summaries)
    unknown = sum(int(item.get("unknown") or 0) for item in summaries)
    explicit_denies = sum(int(item.get("explicit_denies") or 0) for item in summaries)
    return {
        "allowed": allowed,
        "denied": denied,
        "unknown": unknown,
        "explicit_denies": explicit_denies,
        "headline": (
            f"{allowed} allowed, {denied} denied/not found, {unknown} unknown permission check(s)."
        ),
    }


def _event_driven_flow_paths(rule_flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for flow in rule_flows:
        rule = flow["rule"]
        path_nodes: list[dict[str, str | None]] = [
            {
                "type": "eventbridge_rule",
                "name": _as_optional_str(rule.get("name")),
                "arn": _as_optional_str(rule.get("arn")),
            }
        ]
        for step_function in flow["step_functions"]:
            path_nodes.append(
                {
                    "type": "step_function",
                    "name": _as_optional_str(step_function.get("name")),
                    "arn": _as_optional_str(step_function.get("arn")),
                }
            )
        for lambda_node in flow["lambdas"]:
            path_nodes.append(
                {
                    "type": "lambda",
                    "name": _as_optional_str(lambda_node.get("name")),
                    "arn": _as_optional_str(lambda_node.get("arn")),
                }
            )
        paths.append(
            {
                "rule_name": rule.get("name"),
                "event_bus_name": rule.get("event_bus_name"),
                "status": "partial" if flow.get("warnings") else "complete",
                "path": " -> ".join(
                    str(node["name"] or node["arn"] or node["type"]) for node in path_nodes
                ),
                "nodes": path_nodes,
            }
        )
    return paths


def _event_driven_key_findings(
    rule_flows: list[dict[str, Any]],
    permission_checks: dict[str, Any],
    warnings: list[str],
    downstream_hints: list[dict[str, Any]],
) -> list[str]:
    if not rule_flows:
        return ["No EventBridge rules matched the supplied event flow criteria."]

    findings: list[str] = []
    rule_count = len(rule_flows)
    step_function_count = sum(len(flow["step_functions"]) for flow in rule_flows)
    lambda_count = sum(len(flow["lambdas"]) for flow in rule_flows)
    findings.append(
        f"Matched {rule_count} EventBridge rule(s), "
        f"{step_function_count} Step Function target(s), and "
        f"{lambda_count} Lambda dependency node(s)."
    )

    disabled_rules = [
        str(flow["rule"].get("name"))
        for flow in rule_flows
        if str(flow["rule"].get("state") or "").upper() == "DISABLED"
    ]
    if disabled_rules:
        findings.append(f"Disabled rule(s): {', '.join(disabled_rules)}.")

    dispatcher_lambdas = [
        str(step_function.get("name"))
        for flow in rule_flows
        for step_function in flow["step_functions"]
        if (step_function.get("flow_summary") or {}).get("dispatcher_pattern_detected")
    ]
    if dispatcher_lambdas:
        findings.append(
            "Dispatcher Step Function pattern detected: multiple states route through "
            f"the same Lambda in {', '.join(dispatcher_lambdas)}."
        )

    permission_summary = permission_checks["summary"]
    if int(permission_summary.get("denied") or 0):
        findings.append("One or more permission checks are denied or not found.")
    elif int(permission_summary.get("unknown") or 0):
        findings.append("One or more permission checks could not be confirmed.")
    elif int(permission_checks.get("checked_count") or 0):
        findings.append(
            f"All {permission_checks['checked_count']} permission check(s) were allowed."
        )

    unresolved_hint_count = sum(int(item.get("hint_count") or 0) for item in downstream_hints)
    if unresolved_hint_count:
        services = sorted(
            {
                str(service)
                for item in downstream_hints
                for service in item.get("likely_services", [])
            }
        )
        suffix = f" across {', '.join(services)}" if services else ""
        findings.append(
            f"Found {unresolved_hint_count} Lambda downstream hint(s){suffix}; "
            "these are inferred from safe metadata and may need resource-level verification."
        )

    if warnings:
        findings.append(f"Partial expansion produced {len(warnings)} warning(s).")
    return findings


def _event_driven_diagnostic_summary(
    *,
    matched_rule_count: int,
    flow_paths: list[dict[str, Any]],
    permission_checks: dict[str, Any],
    warnings: list[str],
) -> str:
    if matched_rule_count == 0:
        return "No EventBridge rules matched the supplied event flow criteria."

    permission_summary = permission_checks["summary"]
    denied = int(permission_summary.get("denied") or 0)
    unknown = int(permission_summary.get("unknown") or 0)
    checked = int(permission_checks.get("checked_count") or 0)
    path_count = len(flow_paths)
    if denied:
        permission_text = f"{denied} denied/not found permission check(s)"
    elif unknown:
        permission_text = f"{unknown} unknown permission check(s)"
    elif checked:
        permission_text = f"all {checked} permission check(s) allowed"
    else:
        permission_text = "no permission checks run"

    warning_text = f" with {len(warnings)} warning(s)" if warnings else ""
    return (
        f"Matched {matched_rule_count} EventBridge rule(s) and built {path_count} "
        f"event-driven flow path(s); {permission_text}{warning_text}."
    )


def _flow_suggested_next_checks(rule_flows: list[dict[str, Any]], warnings: list[str]) -> list[str]:
    if not rule_flows:
        return ["Broaden the query or check the EventBridge event source/detail-type values."]
    checks = [
        "Review the stitched flow paths and permission summaries for denied or unknown checks."
    ]
    if warnings:
        checks.append("Review warnings from partial graph expansion.")
    if any(not flow["lambdas"] for flow in rule_flows):
        checks.append(
            "If the flow continues outside Lambda, inspect the target service-specific logs."
        )
    return checks


def _dedupe_named_nodes(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for item in items:
        key = (str(item.get("arn") or ""), str(item.get("name") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _parse_event_pattern(value: Any) -> Any:
    if not value:
        return None
    try:
        return json.loads(str(value))
    except json.JSONDecodeError:
        return None


def _event_pattern_path(detail_path: str) -> list[str]:
    parts = [part for part in detail_path.split(".") if part]
    if parts and parts[0] == "detail":
        return parts
    return ["detail", *parts]


def _pattern_path_exists(pattern: Any, path: list[str]) -> bool:
    return _pattern_path_value(pattern, path) is not None


def _pattern_value_contains(pattern: Any, path: list[str], expected: str) -> bool:
    value = _pattern_path_value(pattern, path)
    if value is None:
        return False
    return expected.lower() in json.dumps(value, sort_keys=True).lower()


def _pattern_path_value(pattern: Any, path: list[str]) -> Any:
    current = pattern
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _lambda_name_from_arn(value: Any) -> str | None:
    text = str(value or "")
    match = re.fullmatch(r"arn:aws[a-zA-Z-]*:lambda:[^:]+:\d{12}:function:([^:]+).*", text)
    if match:
        return match.group(1)
    if text and not text.startswith("arn:"):
        return text
    return None


def _normalized_optional(value: str | None) -> str | None:
    normalized = value.strip().lower() if value else None
    return normalized or None


def _as_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _list_event_buses(
    client: Any,
    limit: int,
    warnings: list[str],
) -> list[dict[str, Any]]:
    buses: list[dict[str, Any]] = []
    next_token: str | None = None
    try:
        while len(buses) < limit:
            request: dict[str, Any] = {"Limit": min(100, limit - len(buses))}
            if next_token:
                request["NextToken"] = next_token
            response = client.list_event_buses(**request)
            for item in response.get("EventBuses", []):
                name = str(item.get("Name") or "")
                if not name:
                    continue
                buses.append({"name": name, "arn": item.get("Arn")})
                if len(buses) >= limit:
                    break
            next_token = response.get("NextToken")
            if not next_token:
                break
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "events.ListEventBuses")))
    return buses or [{"name": "default", "arn": None}]


def _list_rules_for_bus(
    client: Any,
    event_bus_name: str,
    name_prefix: str | None,
    limit: int,
    warnings: list[str],
) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    rules: list[dict[str, Any]] = []
    next_token: str | None = None
    try:
        while len(rules) < limit:
            request: dict[str, Any] = {
                "EventBusName": event_bus_name,
                "Limit": min(100, limit - len(rules)),
            }
            if name_prefix:
                request["NamePrefix"] = name_prefix
            if next_token:
                request["NextToken"] = next_token
            response = client.list_rules(**request)
            rules.extend(response.get("Rules", [])[: limit - len(rules)])
            next_token = response.get("NextToken")
            if not next_token:
                break
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "events.ListRules")))
    return rules


def _scheduled_rules(
    client: Any,
    event_bus_name: str | None,
    limit: int,
    warnings: list[str],
) -> list[dict[str, Any]]:
    buses = [event_bus_name] if event_bus_name else ["default"]
    rules = []
    for bus in buses:
        try:
            response = client.list_rules(EventBusName=bus, Limit=limit)
        except (BotoCoreError, ClientError) as exc:
            warnings.append(str(normalize_aws_error(exc, "events.ListRules")))
            continue
        for rule in response.get("Rules", []):
            if rule.get("ScheduleExpression"):
                rules.append(
                    {
                        "name": rule.get("Name"),
                        "arn": rule.get("Arn"),
                        "event_bus_name": bus,
                        "state": rule.get("State"),
                        "schedule_expression": rule.get("ScheduleExpression"),
                    }
                )
            if len(rules) >= limit:
                return rules
    return rules


def _eventbridge_archives(
    client: Any,
    event_bus_name: str | None,
    limit: int,
    warnings: list[str],
) -> list[dict[str, Any]]:
    request: dict[str, Any] = {"Limit": limit}
    if event_bus_name:
        request["EventSourceArn"] = event_bus_name
    try:
        response = client.list_archives(**request)
    except AttributeError:
        warnings.append("events.ListArchives is not supported by this client")
        return []
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "events.ListArchives")))
        return []
    return [
        {
            "name": item.get("ArchiveName"),
            "arn": item.get("ArchiveArn"),
            "state": item.get("State"),
            "event_count": item.get("EventCount"),
            "retention_days": item.get("RetentionDays"),
            "event_source_arn": item.get("EventSourceArn"),
        }
        for item in response.get("Archives", [])[:limit]
    ]


def _eventbridge_replays(client: Any, limit: int, warnings: list[str]) -> list[dict[str, Any]]:
    try:
        response = client.list_replays(Limit=limit)
    except AttributeError:
        warnings.append("events.ListReplays is not supported by this client")
        return []
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "events.ListReplays")))
        return []
    return [
        {
            "name": item.get("ReplayName"),
            "state": item.get("State"),
            "event_source_arn": item.get("EventSourceArn"),
            "event_start_time": isoformat(item.get("EventStartTime")),
            "event_end_time": isoformat(item.get("EventEndTime")),
        }
        for item in response.get("Replays", [])[:limit]
    ]


def _scheduler_schedules(
    runtime: AwsRuntime,
    region: str,
    limit: int,
    warnings: list[str],
) -> list[dict[str, Any]]:
    client = runtime.client("scheduler", region=region)
    try:
        response = client.list_schedules(MaxResults=limit)
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "scheduler.ListSchedules")))
        return []
    return [
        {
            "name": item.get("Name"),
            "group_name": item.get("GroupName"),
            "state": item.get("State"),
            "schedule_expression": item.get("ScheduleExpression"),
            "target_arn": (item.get("Target") or {}).get("Arn"),
        }
        for item in response.get("Schedules", [])[:limit]
    ]


def _rule_target_summary(
    client: Any,
    event_bus_name: str,
    rule_name: str,
    warnings: list[str],
) -> dict[str, Any]:
    try:
        targets = _list_targets_for_rule(client, event_bus_name, rule_name, 100)
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "events.ListTargetsByRule")))
        return {"count": 0, "target_types": [], "warning_count": 1}
    return {
        "count": len(targets),
        "target_types": sorted({_target_type(str(target.get("Arn") or "")) for target in targets}),
        "warning_count": 0,
    }


def _list_targets_for_rule(
    client: Any,
    event_bus_name: str,
    rule_name: str,
    limit: int,
) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    next_token: str | None = None
    while len(targets) < limit:
        request: dict[str, Any] = {
            "Rule": rule_name,
            "EventBusName": event_bus_name,
            "Limit": min(100, limit - len(targets)),
        }
        if next_token:
            request["NextToken"] = next_token
        response = client.list_targets_by_rule(**request)
        targets.extend(response.get("Targets", [])[: limit - len(targets)])
        next_token = response.get("NextToken")
        if not next_token:
            break
    return targets


def _describe_rule(client: Any, rule_name: str, event_bus_name: str) -> dict[str, Any]:
    try:
        response = client.describe_rule(Name=rule_name, EventBusName=event_bus_name)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "events.DescribeRule") from exc
    return dict(response)


def _rule_list_item(
    rule: dict[str, Any],
    event_bus_name: str,
    target_summary: dict[str, Any],
) -> dict[str, Any]:
    event_pattern = rule.get("EventPattern")
    return {
        "name": rule.get("Name"),
        "arn": rule.get("Arn"),
        "event_bus_name": rule.get("EventBusName") or event_bus_name,
        "state": rule.get("State"),
        "schedule_expression": rule.get("ScheduleExpression"),
        "has_event_pattern": bool(event_pattern),
        "event_pattern_keys": _event_pattern_keys(event_pattern),
        "managed_by": rule.get("ManagedBy"),
        "target_count": target_summary["count"],
        "target_types": target_summary["target_types"],
        "warning_count": target_summary["warning_count"],
    }


def _rule_node(rule: dict[str, Any], event_bus_name: str, max_length: int) -> dict[str, Any]:
    event_pattern = _event_pattern_summary(rule.get("EventPattern"), max_length)
    return {
        "name": rule.get("Name"),
        "arn": rule.get("Arn"),
        "event_bus_name": rule.get("EventBusName") or event_bus_name,
        "state": rule.get("State"),
        "description": truncate_string(str(rule.get("Description") or ""), max_length) or None,
        "schedule_expression": rule.get("ScheduleExpression"),
        "managed_by": rule.get("ManagedBy"),
        "role_arn": rule.get("RoleArn"),
        "event_pattern": event_pattern,
    }


def _target_summary(target: dict[str, Any]) -> dict[str, Any]:
    arn = str(target.get("Arn") or "")
    return {
        "id": target.get("Id"),
        "arn": arn,
        "target_type": _target_type(arn),
        "role_arn": target.get("RoleArn"),
        "dead_letter_arn": _dlq_arn(target),
        "retry_policy": target.get("RetryPolicy") or {},
        "input_transformer_configured": bool(target.get("InputTransformer")),
        "input_configured": any(
            target.get(key) is not None for key in ["Input", "InputPath", "InputTransformer"]
        ),
    }


def _dlq_summary(
    runtime: AwsRuntime,
    region: str,
    target: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    arn = str(_dlq_arn(target) or "")
    account = runtime.identity.account if runtime.identity else None
    summary: dict[str, Any] = {
        "arn": arn,
        "target_id": target.get("Id"),
        "queue_name": _sqs_queue_name_from_arn(arn),
        "same_region": _arn_region(arn) == region,
        "same_account": _arn_account(arn) == account,
        "available": False,
        "approximate_number_of_messages": None,
        "approximate_number_of_messages_not_visible": None,
        "policy_allows_eventbridge": None,
        "warnings": [],
    }
    queue_url = _queue_url_from_arn(arn)
    if not queue_url:
        summary["warnings"].append("DLQ ARN was not an SQS queue ARN")
        warnings.append(str(summary["warnings"][-1]))
        return summary

    sqs = runtime.client("sqs", region=_arn_region(arn) or region)
    try:
        response = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=[
                "ApproximateNumberOfMessages",
                "ApproximateNumberOfMessagesNotVisible",
                "Policy",
            ],
        )
    except (BotoCoreError, ClientError) as exc:
        warning = str(normalize_aws_error(exc, "sqs.GetQueueAttributes"))
        summary["warnings"].append(warning)
        warnings.append(warning)
        return summary

    attributes = response.get("Attributes", {})
    summary["available"] = True
    summary["approximate_number_of_messages"] = _int_or_none(
        attributes.get("ApproximateNumberOfMessages")
    )
    summary["approximate_number_of_messages_not_visible"] = _int_or_none(
        attributes.get("ApproximateNumberOfMessagesNotVisible")
    )
    summary["policy_allows_eventbridge"] = _policy_allows_service_action(
        attributes.get("Policy"),
        service="events.amazonaws.com",
        action="sqs:SendMessage",
    )
    return summary


def _role_nodes(rule: dict[str, Any], targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    role_arns = {
        str(value)
        for value in [rule.get("RoleArn"), *[target.get("RoleArn") for target in targets]]
        if value
    }
    return [{"arn": arn, "name": _role_name_from_arn(arn)} for arn in sorted(role_arns)]


def _eventbridge_edges(
    rule: dict[str, Any],
    event_bus_name: str,
    targets: list[dict[str, Any]],
    dlqs: list[dict[str, Any]],
    roles: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rule_arn = str(rule.get("Arn") or rule.get("Name") or "")
    bus_arn = _event_bus_arn_from_rule(rule, event_bus_name) or event_bus_name
    edges: list[dict[str, Any]] = [
        {
            "from": bus_arn,
            "to": rule_arn,
            "relationship": "matches_on_bus",
            "target_type": "eventbridge_rule",
        }
    ]
    for target in targets:
        edges.append(
            {
                "from": rule_arn,
                "to": target["arn"],
                "relationship": "routes_to",
                "target_id": target.get("id"),
                "target_type": target.get("target_type"),
            }
        )
        if target.get("role_arn"):
            edges.append(
                {
                    "from": rule_arn,
                    "to": target["role_arn"],
                    "relationship": "uses_role",
                    "target_id": target.get("id"),
                    "target_type": "iam_role",
                }
            )
        if target.get("dead_letter_arn"):
            edges.append(
                {
                    "from": target["arn"],
                    "to": target["dead_letter_arn"],
                    "relationship": "sends_failed_events_to",
                    "target_id": target.get("id"),
                    "target_type": "sqs",
                }
            )
    for role in roles:
        if role["arn"] == rule.get("RoleArn"):
            edges.append(
                {
                    "from": rule_arn,
                    "to": role["arn"],
                    "relationship": "uses_role",
                    "target_type": "iam_role",
                }
            )
    return [edge for edge in edges if edge.get("to") not in {None, ""}]


def _eventbridge_permission_hints(
    rule: dict[str, Any],
    event_bus_name: str,
    targets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rule_arn = str(rule.get("Arn") or "")
    hints: list[dict[str, Any]] = []
    for target in targets:
        action = _target_action(target.get("target_type"))
        if action:
            hints.append(
                {
                    "principal": target.get("role_arn") or "events.amazonaws.com",
                    "target_id": target.get("id"),
                    "resource": target.get("arn"),
                    "actions_to_check": [action],
                    "reason": (
                        f"EventBridge rule {rule.get('Name')} on bus {event_bus_name} "
                        f"routes to a {target.get('target_type')} target."
                    ),
                    "source_arn": rule_arn,
                }
            )
        else:
            hints.append(
                {
                    "principal": target.get("role_arn") or "events.amazonaws.com",
                    "target_id": target.get("id"),
                    "resource": target.get("arn"),
                    "actions_to_check": [],
                    "reason": "Target type is not supported for automatic permission checks.",
                    "source_arn": rule_arn,
                }
            )
        if target.get("dead_letter_arn"):
            hints.append(
                {
                    "principal": "events.amazonaws.com",
                    "target_id": target.get("id"),
                    "resource": target.get("dead_letter_arn"),
                    "actions_to_check": ["sqs:SendMessage"],
                    "reason": (
                        "EventBridge needs permission to send failed events to the target DLQ."
                    ),
                    "source_arn": rule_arn,
                }
            )
    return hints


def _eventbridge_permission_checks(
    *,
    runtime: AwsRuntime,
    region: str,
    rule: dict[str, Any],
    event_bus_name: str,
    targets: list[dict[str, Any]],
    dead_letter_queues: list[dict[str, Any]],
    include_permission_checks: bool,
    limit: int,
    warnings: list[str],
) -> dict[str, Any]:
    if not include_permission_checks:
        return empty_permission_checks()

    checks: list[dict[str, Any]] = []
    dlq_by_target_id = {dlq.get("target_id"): dlq for dlq in dead_letter_queues}
    for target in targets:
        if len(checks) >= limit:
            break
        check = _target_permission_check(
            runtime=runtime,
            region=region,
            rule=rule,
            event_bus_name=event_bus_name,
            target=target,
            warnings=warnings,
        )
        checks.append(check)
        if target.get("dead_letter_arn") and len(checks) < limit:
            checks.append(_dlq_permission_check(target, dlq_by_target_id.get(target.get("id"))))

    return {
        "enabled": True,
        "checked_count": len(checks),
        "checks": checks,
        "summary": _permission_summary(checks),
    }


def _target_permission_check(
    *,
    runtime: AwsRuntime,
    region: str,
    rule: dict[str, Any],
    event_bus_name: str,
    target: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    action = _target_action(target.get("target_type"))
    base: dict[str, Any] = {
        "rule_name": rule.get("Name"),
        "event_bus_name": event_bus_name,
        "target_id": target.get("id"),
        "principal": target.get("role_arn") or "events.amazonaws.com",
        "action": action,
        "resource_arn": target.get("arn"),
        "source_arn": rule.get("Arn"),
        "warnings": [],
    }
    if not action:
        return {
            **base,
            "decision": "unknown",
            "allowed": None,
            "explicit_deny": None,
            "matched_statements": [],
            "missing_context_values": [],
            "warnings": ["Unsupported target type for automatic permission checks."],
        }

    role_arn = target.get("role_arn")
    if role_arn:
        return _simulate_role_permission(
            runtime,
            str(role_arn),
            action,
            str(target.get("arn")),
            base,
        )

    if target.get("target_type") == "lambda":
        return _lambda_policy_check(runtime, region, rule, target, base)
    if target.get("target_type") == "sqs":
        return _sqs_policy_check(runtime, region, target, base, warnings)
    if target.get("target_type") == "sns":
        return _sns_policy_check(runtime, region, target, base, warnings)
    return {
        **base,
        "decision": "unknown",
        "allowed": None,
        "explicit_deny": None,
        "matched_statements": [],
        "missing_context_values": [],
        "warnings": ["Resource policy checks are not implemented for this target type."],
    }


def _simulate_role_permission(
    runtime: AwsRuntime,
    role_arn: str,
    action: str,
    resource_arn: str,
    base: dict[str, Any],
) -> dict[str, Any]:
    iam = runtime.client("iam", region=runtime.region)
    try:
        response = iam.simulate_principal_policy(
            PolicySourceArn=role_arn,
            ActionNames=[action],
            ResourceArns=[resource_arn],
        )
    except (BotoCoreError, ClientError) as exc:
        return _unknown_check(base, str(normalize_aws_error(exc, "iam.SimulatePrincipalPolicy")))
    evaluation = _simulation_evaluation(response)
    return {**base, **evaluation, "warnings": []}


def _lambda_policy_check(
    runtime: AwsRuntime,
    region: str,
    rule: dict[str, Any],
    target: dict[str, Any],
    base: dict[str, Any],
) -> dict[str, Any]:
    client = runtime.client("lambda", region=region)
    try:
        response = client.get_policy(FunctionName=str(target.get("arn")))
    except (BotoCoreError, ClientError) as exc:
        return _unknown_check(base, str(normalize_aws_error(exc, "lambda.GetPolicy")))
    allowed = _policy_allows_service_action(
        response.get("Policy"),
        service="events.amazonaws.com",
        action="lambda:InvokeFunction",
        source_arn=str(rule.get("Arn") or ""),
    )
    return _resource_policy_decision(base, allowed)


def _sqs_policy_check(
    runtime: AwsRuntime,
    region: str,
    target: dict[str, Any],
    base: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    attributes = _sqs_attributes(runtime, region, str(target.get("arn") or ""), warnings)
    if attributes is None:
        return _unknown_check(base, "Unable to read SQS queue policy")
    allowed = _policy_allows_service_action(
        attributes.get("Policy"),
        service="events.amazonaws.com",
        action="sqs:SendMessage",
    )
    return _resource_policy_decision(base, allowed)


def _sns_policy_check(
    runtime: AwsRuntime,
    region: str,
    target: dict[str, Any],
    base: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    sns = runtime.client("sns", region=_arn_region(str(target.get("arn") or "")) or region)
    try:
        response = sns.get_topic_attributes(TopicArn=str(target.get("arn")))
    except (BotoCoreError, ClientError) as exc:
        warning = str(normalize_aws_error(exc, "sns.GetTopicAttributes"))
        warnings.append(warning)
        return _unknown_check(base, warning)
    allowed = _policy_allows_service_action(
        response.get("Attributes", {}).get("Policy"),
        service="events.amazonaws.com",
        action="sns:Publish",
    )
    return _resource_policy_decision(base, allowed)


def _dlq_permission_check(target: dict[str, Any], dlq: dict[str, Any] | None) -> dict[str, Any]:
    allowed = dlq.get("policy_allows_eventbridge") if dlq else None
    return {
        "target_id": target.get("id"),
        "principal": "events.amazonaws.com",
        "action": "sqs:SendMessage",
        "resource_arn": target.get("dead_letter_arn"),
        "source": "dead_letter_config",
        "decision": _resource_policy_decision_text(allowed),
        "allowed": allowed,
        "explicit_deny": False if allowed is not None else None,
        "matched_statements": [],
        "missing_context_values": [],
        "warnings": [] if allowed is not None else ["DLQ policy could not be checked."],
    }


def _sqs_attributes(
    runtime: AwsRuntime,
    region: str,
    queue_arn: str,
    warnings: list[str],
) -> dict[str, Any] | None:
    queue_url = _queue_url_from_arn(queue_arn)
    if not queue_url:
        warnings.append("SQS target ARN could not be converted to a queue URL")
        return None
    sqs = runtime.client("sqs", region=_arn_region(queue_arn) or region)
    try:
        response = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])
    except (BotoCoreError, ClientError) as exc:
        warning = str(normalize_aws_error(exc, "sqs.GetQueueAttributes"))
        warnings.append(warning)
        return None
    attributes = response.get("Attributes", {})
    return dict(attributes) if isinstance(attributes, dict) else {}


def _unknown_check(base: dict[str, Any], warning: str) -> dict[str, Any]:
    return {
        **base,
        "decision": "unknown",
        "allowed": None,
        "explicit_deny": None,
        "matched_statements": [],
        "missing_context_values": [],
        "warnings": [warning],
    }


def _resource_policy_decision(base: dict[str, Any], allowed: bool | None) -> dict[str, Any]:
    if allowed is None:
        return _unknown_check(base, "Resource policy was unavailable or not valid JSON")
    return {
        **base,
        "decision": _resource_policy_decision_text(allowed),
        "allowed": allowed,
        "explicit_deny": False,
        "matched_statements": [],
        "missing_context_values": [],
        "warnings": [],
    }


def _resource_policy_decision_text(allowed: bool | None) -> str:
    if allowed is True:
        return "allowed"
    if allowed is False:
        return "not_found"
    return "unknown"


def _simulation_evaluation(response: dict[str, Any]) -> dict[str, Any]:
    result = (response.get("EvaluationResults") or [{}])[0]
    decision = str(result.get("EvalDecision") or "unknown")
    return {
        "decision": decision,
        "allowed": decision == "allowed",
        "explicit_deny": decision == "explicitDeny",
        "matched_statements": [
            {
                "source_policy_id": statement.get("SourcePolicyId"),
                "source_policy_type": statement.get("SourcePolicyType"),
            }
            for statement in result.get("MatchedStatements", [])
        ],
        "missing_context_values": [str(value) for value in result.get("MissingContextValues", [])],
    }


def _permission_summary(checks: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "allowed": sum(1 for check in checks if check.get("allowed") is True),
        "denied": sum(1 for check in checks if check.get("allowed") is False),
        "unknown": sum(1 for check in checks if check.get("allowed") is None),
        "explicit_denies": sum(1 for check in checks if check.get("explicit_deny") is True),
    }


def _eventbridge_metric_summary(
    runtime: AwsRuntime,
    rule_name: str,
    event_bus_name: str,
    region: str,
    since_minutes: int,
) -> dict[str, Any]:
    client = runtime.client("cloudwatch", region=region)
    end = datetime.now(UTC)
    start = end - timedelta(minutes=since_minutes)
    try:
        response = client.get_metric_data(
            MetricDataQueries=[
                _metric_query(metric, rule_name, event_bus_name) for metric in EVENTBRIDGE_METRICS
            ],
            StartTime=start,
            EndTime=end,
        )
    except (BotoCoreError, ClientError) as exc:
        return {
            "available": False,
            "window_minutes": since_minutes,
            "warnings": [str(normalize_aws_error(exc, "cloudwatch.GetMetricData"))],
            "metrics": {metric: _empty_metric() for metric in EVENTBRIDGE_METRICS},
        }

    metrics = {
        str(result.get("Label") or result.get("Id")): _summarize_metric_result(result)
        for result in response.get("MetricDataResults", [])
    }
    return {
        "available": True,
        "window_minutes": since_minutes,
        "warnings": [],
        "metrics": {metric: metrics.get(metric, _empty_metric()) for metric in EVENTBRIDGE_METRICS},
    }


def _metric_query(metric_name: str, rule_name: str, event_bus_name: str) -> dict[str, Any]:
    return {
        "Id": re.sub(r"[^a-z0-9_]", "_", metric_name.lower()),
        "Label": metric_name,
        "MetricStat": {
            "Metric": {
                "Namespace": "AWS/Events",
                "MetricName": metric_name,
                "Dimensions": [
                    {"Name": "RuleName", "Value": rule_name},
                    {"Name": "EventBusName", "Value": event_bus_name},
                ],
            },
            "Period": 60,
            "Stat": "Sum",
        },
        "ReturnData": True,
    }


def _summarize_metric_result(result: dict[str, Any]) -> dict[str, Any]:
    values = [float(value) for value in result.get("Values", [])]
    return {
        "sum": sum(values),
        "maximum": max(values) if values else 0.0,
        "datapoints": len(values),
        "latest_timestamp": isoformat(result.get("Timestamps", [None])[0])
        if result.get("Timestamps")
        else None,
        "status": result.get("StatusCode"),
    }


def _empty_metric() -> dict[str, Any]:
    return {
        "sum": 0.0,
        "maximum": 0.0,
        "datapoints": 0,
        "latest_timestamp": None,
        "status": None,
    }


def _delivery_signals(dependencies: dict[str, Any], metrics: dict[str, Any]) -> dict[str, Any]:
    metric_values = metrics.get("metrics", {})
    failed = _metric_sum(metric_values, "FailedInvocations")
    sent_to_dlq = _metric_sum(metric_values, "InvocationsSentToDLQ") + _metric_sum(
        metric_values, "DeadLetterInvocations"
    )
    matched = _metric_sum(metric_values, "MatchedEvents") + _metric_sum(
        metric_values, "TriggeredRules"
    )
    permission_summary = dependencies.get("permission_checks", {}).get("summary", {})
    dlqs = dependencies.get("nodes", {}).get("dead_letter_queues", [])
    return {
        "rule_disabled": dependencies.get("summary", {}).get("state") == "DISABLED",
        "has_targets": dependencies.get("summary", {}).get("target_count", 0) > 0,
        "has_failed_invocations": failed > 0,
        "has_dlq_activity": sent_to_dlq > 0,
        "has_matches": matched > 0,
        "permission_denied_count": int(permission_summary.get("denied") or 0),
        "permission_unknown_count": int(permission_summary.get("unknown") or 0),
        "dlq_visible_messages": sum(
            int(dlq.get("approximate_number_of_messages") or 0)
            for dlq in dlqs
            if isinstance(dlq, dict)
        ),
    }


def _delivery_diagnostic_summary(dependencies: dict[str, Any], signals: dict[str, Any]) -> str:
    rule_name = str(dependencies.get("rule_name"))
    if signals["rule_disabled"]:
        return f"EventBridge rule {rule_name} is disabled, so it will not deliver events."
    if not signals["has_targets"]:
        return f"EventBridge rule {rule_name} has no targets configured."
    if signals["permission_denied_count"]:
        return (
            f"EventBridge rule {rule_name} has target permission checks that did not find access."
        )
    if signals["has_failed_invocations"] or signals["has_dlq_activity"]:
        return f"EventBridge rule {rule_name} shows failed delivery or DLQ activity in the window."
    if signals["has_matches"]:
        return (
            f"EventBridge rule {rule_name} matched events and no delivery failures were detected."
        )
    return f"EventBridge rule {rule_name} has no obvious delivery failures in the selected window."


def _delivery_suggested_next_checks(signals: dict[str, Any]) -> list[str]:
    checks: list[str] = []
    if signals["rule_disabled"]:
        checks.append("Enable the rule if it is expected to process events.")
    if not signals["has_targets"]:
        checks.append("Add or repair rule targets; matched events have nowhere to go.")
    if signals["permission_denied_count"] or signals["permission_unknown_count"]:
        checks.append("Review target resource policies or target RoleArn permissions.")
    if signals["has_dlq_activity"] or signals["dlq_visible_messages"]:
        checks.append("Inspect the configured DLQ metadata and target retry policy.")
    if signals["has_failed_invocations"]:
        checks.append("Check target service logs and EventBridge failed invocation metrics.")
    if not checks:
        checks.append(
            "If events are expected but absent, verify the upstream event source and event pattern."
        )
    return checks


def _event_pattern_summary(value: Any, max_length: int) -> dict[str, Any] | None:
    if not value:
        return None
    raw = str(value)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "valid_json": False,
            "truncated": len(raw) > max_length,
            "value": truncate_string(raw, max_length),
        }
    redacted = _redact_event_pattern(parsed, RedactionConfig(max_string_length=max_length))
    rendered = json.dumps(redacted, sort_keys=True)
    return {
        "valid_json": True,
        "keys": sorted(str(key) for key in parsed) if isinstance(parsed, dict) else [],
        "source": parsed.get("source") if isinstance(parsed, dict) else None,
        "detail_type": parsed.get("detail-type") if isinstance(parsed, dict) else None,
        "truncated": len(rendered) > max_length,
        "value": truncate_string(rendered, max_length),
    }


def _event_pattern_keys(value: Any) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return []
    return sorted(str(key) for key in parsed) if isinstance(parsed, dict) else []


def _redact_event_pattern(
    value: Any,
    config: RedactionConfig,
    parent_key: str | None = None,
) -> Any:
    if isinstance(value, str):
        return truncate_string(value, config.max_string_length)
    if isinstance(value, list):
        return [_redact_event_pattern(item, config, parent_key) for item in value]
    if not isinstance(value, dict):
        return value

    redacted: dict[str, Any] = {}
    for key, nested in value.items():
        key_text = str(key)
        if _is_event_pattern_structural_key(key_text, parent_key):
            redacted[key_text] = _redact_event_pattern(nested, config, key_text)
        elif config.redact_secret_like_keys and is_secret_like_key(key_text):
            redacted[key_text] = REDACTED
        else:
            redacted[key_text] = _redact_event_pattern(nested, config, key_text)
    return redacted


def _is_event_pattern_structural_key(key: str, parent_key: str | None) -> bool:
    if key in {
        "account",
        "detail",
        "detail-type",
        "exists",
        "numeric",
        "prefix",
        "region",
        "resources",
        "source",
        "suffix",
    }:
        return True
    return parent_key in {"object", "requestParameters"} and key == "key"


def _policy_allows_service_action(
    policy_text: Any,
    *,
    service: str,
    action: str,
    source_arn: str | None = None,
) -> bool | None:
    if not policy_text:
        return False
    try:
        policy = json.loads(str(policy_text))
    except json.JSONDecodeError:
        return None
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return False
    return any(
        _statement_allows_service_action(statement, service, action, source_arn)
        for statement in statements
    )


def _statement_allows_service_action(
    statement: Any,
    service: str,
    action: str,
    source_arn: str | None,
) -> bool:
    if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
        return False
    if not _contains_value(statement.get("Principal"), service):
        return False
    if not _contains_value(statement.get("Action"), action):
        return False
    condition = statement.get("Condition")
    if source_arn and isinstance(condition, dict):
        rendered = json.dumps(condition, sort_keys=True)
        return source_arn in rendered
    return True


def _contains_value(value: Any, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected or value == "*"
    if isinstance(value, list):
        return any(_contains_value(item, expected) for item in value)
    if isinstance(value, dict):
        return any(_contains_value(item, expected) for item in value.values())
    return False


def _target_type(arn: str) -> str:
    service = _arn_service(arn)
    if service == "states":
        return "stepfunctions"
    if service == "firehose":
        return "firehose"
    return service or "unknown"


def _target_action(target_type: Any) -> str | None:
    return {
        "lambda": "lambda:InvokeFunction",
        "stepfunctions": "states:StartExecution",
        "sqs": "sqs:SendMessage",
        "sns": "sns:Publish",
        "kinesis": "kinesis:PutRecord",
        "firehose": "firehose:PutRecord",
        "ecs": "ecs:RunTask",
        "batch": "batch:SubmitJob",
    }.get(str(target_type))


def _dlq_arn(target: dict[str, Any]) -> str | None:
    dead_letter = target.get("DeadLetterConfig")
    if isinstance(dead_letter, dict) and dead_letter.get("Arn"):
        return str(dead_letter["Arn"])
    return None


def _event_bus_arn_from_rule(rule: dict[str, Any], event_bus_name: str) -> str | None:
    arn = str(rule.get("Arn") or "")
    if ":rule/" not in arn:
        return None
    prefix = arn.split(":rule/", maxsplit=1)[0]
    if event_bus_name == "default":
        return f"{prefix}:event-bus/default"
    return f"{prefix}:event-bus/{event_bus_name}"


def _queue_url_from_arn(arn: str) -> str | None:
    parts = arn.split(":", maxsplit=5)
    if len(parts) != 6 or parts[2] != "sqs":
        return None
    partition, region, account, queue_name = parts[1], parts[3], parts[4], parts[5]
    domain = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
    return f"https://sqs.{region}.{domain}/{account}/{queue_name}"


def _sqs_queue_name_from_arn(arn: str) -> str | None:
    parts = arn.split(":", maxsplit=5)
    return parts[5] if len(parts) == 6 and parts[2] == "sqs" else None


def _arn_service(arn: Any) -> str | None:
    parts = str(arn).split(":", maxsplit=5)
    return parts[2] if len(parts) >= 3 and parts[0] == "arn" else None


def _arn_region(arn: str) -> str | None:
    parts = arn.split(":", maxsplit=5)
    return parts[3] if len(parts) >= 4 and parts[0] == "arn" else None


def _arn_account(arn: str) -> str | None:
    parts = arn.split(":", maxsplit=5)
    return parts[4] if len(parts) >= 5 and parts[0] == "arn" else None


def _role_name_from_arn(role_arn: str) -> str | None:
    match = re.fullmatch(r"arn:aws[a-zA-Z-]*:iam::\d{12}:role/(.+)", role_arn)
    if not match:
        return None
    return match.group(1).rsplit("/", maxsplit=1)[-1]


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _metric_sum(metrics: dict[str, Any], name: str) -> float:
    item = metrics.get(name) or {}
    return float(item.get("sum") or 0.0)


def _require_rule_name(rule_name: str) -> str:
    if not rule_name.strip():
        raise ToolInputError("rule_name is required")
    return rule_name


def _require_event_bus_name(event_bus_name: str) -> str:
    if not event_bus_name.strip():
        raise ToolInputError("event_bus_name is required")
    return event_bus_name
