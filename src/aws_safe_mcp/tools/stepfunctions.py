from __future__ import annotations

import json
import re
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.config import ConfigError
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.redaction import redact_data, truncate_string
from aws_safe_mcp.tools.common import (
    clamp_limit,
    isoformat,
    page_size,
    require_step_functions_execution,
    resolve_region,
)
from aws_safe_mcp.tools.graph import dependency_graph_summary, empty_permission_checks


def list_step_functions(
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
    client = runtime.client("stepfunctions", region=resolved_region)
    state_machines: list[dict[str, Any]] = []

    try:
        paginator = client.get_paginator("list_state_machines")
        for page in paginator.paginate(
            PaginationConfig={"PageSize": page_size("stepfunctions.ListStateMachines", limit)}
        ):
            for item in page.get("stateMachines", []):
                name = str(item.get("name", ""))
                if name_prefix and not name.startswith(name_prefix):
                    continue
                state_machines.append(_state_machine_list_item(item))
                if len(state_machines) >= limit:
                    return {
                        "region": resolved_region,
                        "count": len(state_machines),
                        "state_machines": state_machines,
                    }
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "states.ListStateMachines") from exc

    return {
        "region": resolved_region,
        "count": len(state_machines),
        "state_machines": state_machines,
    }


def get_step_function_execution_summary(
    runtime: AwsRuntime,
    execution_arn: str,
    region: str | None = None,
) -> dict[str, Any]:
    parsed = require_step_functions_execution(runtime, execution_arn)
    resolved_region = resolve_region(runtime, region or parsed["region"])
    client = runtime.client("stepfunctions", region=resolved_region)

    try:
        execution = client.describe_execution(executionArn=execution_arn)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "states.DescribeExecution") from exc

    try:
        history = _collect_history_events(client, execution_arn)
        failed = _find_failed_state(history)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "states.GetExecutionHistory") from exc

    return {
        "execution_arn": execution_arn,
        "state_machine_name": parsed["state_machine_name"],
        "execution_name": parsed["execution_name"],
        "region": resolved_region,
        "status": execution.get("status"),
        "start_date": isoformat(execution.get("startDate")),
        "stop_date": isoformat(execution.get("stopDate")),
        "failed_state": failed,
        "input": _safe_json_field(execution.get("input"), runtime),
        "output": _safe_json_field(execution.get("output"), runtime),
    }


def investigate_step_function_failure(
    runtime: AwsRuntime,
    execution_arn: str,
    region: str | None = None,
) -> dict[str, Any]:
    summary = get_step_function_execution_summary(
        runtime,
        execution_arn=execution_arn,
        region=region,
    )
    failed_state = summary.get("failed_state")
    signals = _step_function_failure_signals(failed_state)
    definition_context, warnings = _step_function_failure_definition_context(
        runtime,
        execution_arn,
        summary,
    )

    return {
        "execution_arn": execution_arn,
        "state_machine_name": summary.get("state_machine_name"),
        "execution_name": summary.get("execution_name"),
        "region": summary.get("region"),
        "status": summary.get("status"),
        "diagnostic_summary": _step_function_diagnostic_summary(summary, signals),
        "warnings": warnings,
        "failed_state": failed_state,
        "failed_state_definition": definition_context.get("failed_state_definition"),
        "failed_state_path": definition_context.get("failed_state_path"),
        "previous_event_context": (
            failed_state.get("previous_event_context")
            if isinstance(failed_state, dict)
            else None
        ),
        "downstream_target": definition_context.get("downstream_target"),
        "retry_catch": definition_context.get("retry_catch"),
        "signals": signals,
        "suggested_next_checks": _step_function_suggested_next_checks(signals),
    }


def explain_step_function_dependencies(
    runtime: AwsRuntime,
    state_machine_arn: str,
    region: str | None = None,
    include_permission_checks: bool = True,
    max_permission_checks: int | None = None,
) -> dict[str, Any]:
    """Explain a state machine's task graph, execution role, and IAM checks."""

    parsed = _require_state_machine_arn(runtime, state_machine_arn)
    resolved_region = resolve_region(runtime, region or parsed["region"])
    limit = clamp_limit(
        max_permission_checks,
        default=20,
        configured_max=runtime.config.max_results,
        label="max_permission_checks",
    )
    client = runtime.client("stepfunctions", region=resolved_region)

    try:
        state_machine = client.describe_state_machine(stateMachineArn=state_machine_arn)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "states.DescribeStateMachine") from exc

    definition, definition_warnings = _parse_state_machine_definition(
        state_machine.get("definition"),
        runtime.config.redaction.max_string_length,
    )
    role_arn = str(state_machine.get("roleArn") or "")
    states = _asl_states(definition, state_machine_arn)
    edges = _step_function_dependency_edges(state_machine_arn, states)
    role = _step_function_iam_role_summary(runtime, role_arn)
    permission_hints = _step_function_permission_hints(edges, role_arn)
    permission_checks = _step_function_permission_checks(
        runtime=runtime,
        state_machine_name=parsed["state_machine_name"],
        region=resolved_region,
        role_arn=role_arn,
        permission_hints=permission_hints,
        include_permission_checks=include_permission_checks,
        limit=limit,
    )
    warnings = [*definition_warnings, *role.get("warnings", [])]
    nodes = {
        "state_machine": {
            "name": parsed["state_machine_name"],
            "arn": state_machine_arn,
        },
        "execution_role": role,
        "states": states,
    }

    return {
        "name": parsed["state_machine_name"],
        "arn": state_machine_arn,
        "state_machine_name": parsed["state_machine_name"],
        "state_machine_arn": state_machine_arn,
        "region": resolved_region,
        "type": state_machine.get("type"),
        "status": state_machine.get("status"),
        "resource_type": "step_function",
        "summary": {
            "state_count": len(states),
            "task_state_count": sum(1 for state in states if state.get("type") == "Task"),
            "start_at": definition.get("StartAt") if isinstance(definition, dict) else None,
        },
        "flow_summary": _step_function_flow_summary(definition, states, edges),
        "task_permission_proof": _step_function_task_permission_proof(
            states,
            permission_checks,
        ),
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


def audit_step_function_retry_catch_safety(
    runtime: AwsRuntime,
    state_machine_arn: str,
    region: str | None = None,
) -> dict[str, Any]:
    dependencies = explain_step_function_dependencies(
        runtime,
        state_machine_arn=state_machine_arn,
        region=region,
        include_permission_checks=False,
    )
    states = dependencies.get("nodes", {}).get("states", [])
    task_audits = [_step_function_task_retry_catch_audit(state) for state in states]
    terminal_failures = [
        {"name": state.get("name"), "type": state.get("type")}
        for state in states
        if state.get("type") == "Fail"
    ]
    signals = _step_function_retry_catch_signals(task_audits, terminal_failures)
    return {
        "state_machine_name": dependencies["state_machine_name"],
        "state_machine_arn": dependencies["state_machine_arn"],
        "region": dependencies["region"],
        "summary": _step_function_retry_catch_summary(signals),
        "task_audits": task_audits,
        "terminal_failure_states": terminal_failures,
        "signals": signals,
        "suggested_next_checks": _step_function_retry_catch_next_checks(signals),
        "warnings": dependencies.get("warnings", []),
    }


def _state_machine_list_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name"),
        "arn": item.get("stateMachineArn"),
        "type": item.get("type"),
        "creation_date": isoformat(item.get("creationDate")),
    }


def _require_state_machine_arn(runtime: AwsRuntime, state_machine_arn: str) -> dict[str, str]:
    match = re.fullmatch(
        r"arn:(?P<partition>aws[a-zA-Z-]*):states:(?P<region>[^:]+):"
        r"(?P<account>\d{12}):stateMachine:(?P<state_machine_name>.+)",
        state_machine_arn,
    )
    if not match:
        raise ToolInputError("state_machine_arn must be a valid Step Functions ARN")
    parsed = match.groupdict()
    try:
        runtime.config.require_account_allowed(parsed["account"])
    except ConfigError as exc:
        raise ToolInputError(str(exc)) from exc
    return parsed


def _parse_state_machine_definition(
    value: Any,
    max_string_length: int,
) -> tuple[dict[str, Any], list[str]]:
    if not value:
        return {}, ["State machine definition was empty or unavailable"]
    raw = str(value)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}, [
            "State machine definition was not valid JSON: "
            f"{truncate_string(raw, max_string_length)}"
        ]
    if not isinstance(parsed, dict):
        return {}, ["State machine definition root was not a JSON object"]
    return parsed, []


def _asl_states(
    definition: dict[str, Any],
    state_machine_arn: str | None = None,
) -> list[dict[str, Any]]:
    states = definition.get("States", {})
    if not isinstance(states, dict):
        return []
    return [_asl_state_summary(name, value, state_machine_arn) for name, value in states.items()]


def _asl_state_summary(
    name: str,
    value: Any,
    state_machine_arn: str | None = None,
) -> dict[str, Any]:
    state = value if isinstance(value, dict) else {}
    state_type = str(state.get("Type") or "")
    resource = state.get("Resource")
    raw_parameters = state.get("Parameters")
    parameters: dict[str, Any] = raw_parameters if isinstance(raw_parameters, dict) else {}
    raw_choices = state.get("Choices")
    choices: list[Any] = raw_choices if isinstance(raw_choices, list) else []
    return {
        "name": name,
        "type": state_type or None,
        "resource": resource if state_type == "Task" else None,
        "integration": _step_function_integration(resource),
        "target_arn": _step_function_task_target_arn(resource, parameters, state_machine_arn),
        "next": state.get("Next"),
        "default_next": state.get("Default"),
        "choice_next": [
            choice.get("Next")
            for choice in choices
            if isinstance(choice, dict) and choice.get("Next")
        ],
        "end": state.get("End") is True,
        "timeout_seconds": state.get("TimeoutSeconds"),
        "heartbeat_seconds": state.get("HeartbeatSeconds"),
        "retry": _retry_catch_summary(state.get("Retry")),
        "catch": _retry_catch_summary(state.get("Catch")),
    }


def _retry_catch_summary(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    summary = []
    for item in value:
        if not isinstance(item, dict):
            continue
        summary.append(
            {
                "error_equals": item.get("ErrorEquals", []),
                "next": item.get("Next"),
                "interval_seconds": item.get("IntervalSeconds"),
                "max_attempts": item.get("MaxAttempts"),
                "backoff_rate": item.get("BackoffRate"),
            }
        )
    return summary


def _step_function_task_retry_catch_audit(state: dict[str, Any]) -> dict[str, Any]:
    if state.get("type") != "Task":
        return {
            "name": state.get("name"),
            "type": state.get("type"),
            "included": False,
        }
    retry = state.get("retry") or []
    catch = state.get("catch") or []
    risks = []
    integration = state.get("integration")
    if not retry:
        risks.append("task_without_retry")
    if not catch:
        risks.append("task_without_catch")
    if integration and integration not in {"unknown"} and not catch:
        risks.append("external_integration_without_catch")
    if retry and not _retry_handles_transient_errors(retry):
        risks.append("retry_without_transient_errors")
    return {
        "name": state.get("name"),
        "type": state.get("type"),
        "integration": integration,
        "target_arn": state.get("target_arn"),
        "retry_count": len(retry),
        "catch_count": len(catch),
        "retry_error_sets": [item.get("error_equals", []) for item in retry],
        "catch_error_sets": [item.get("error_equals", []) for item in catch],
        "risks": risks,
        "included": True,
    }


def _retry_handles_transient_errors(retry: list[dict[str, Any]]) -> bool:
    transient = {
        "States.ALL",
        "States.TaskFailed",
        "Lambda.ServiceException",
        "Lambda.AWSLambdaException",
        "Lambda.SdkClientException",
        "ThrottlingException",
    }
    return any(
        transient.intersection({str(error) for error in item.get("error_equals", [])})
        for item in retry
    )


def _step_function_retry_catch_signals(
    task_audits: list[dict[str, Any]],
    terminal_failures: list[dict[str, Any]],
) -> dict[str, Any]:
    included = [item for item in task_audits if item.get("included")]
    risks = [risk for item in included for risk in item.get("risks", [])]
    return {
        "task_count": len(included),
        "terminal_failure_state_count": len(terminal_failures),
        "tasks_without_retry": [
            item["name"] for item in included if "task_without_retry" in item["risks"]
        ],
        "tasks_without_catch": [
            item["name"] for item in included if "task_without_catch" in item["risks"]
        ],
        "external_integrations_without_catch": [
            item["name"]
            for item in included
            if "external_integration_without_catch" in item["risks"]
        ],
        "risk_count": len(risks),
        "risks": sorted(set(risks)),
    }


def _step_function_retry_catch_summary(signals: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "retry_catch_gaps" if signals["risk_count"] else "retry_catch_covered",
        "task_count": signals["task_count"],
        "risk_count": signals["risk_count"],
        "risks": signals["risks"],
    }


def _step_function_retry_catch_next_checks(signals: dict[str, Any]) -> list[str]:
    checks = []
    if signals["tasks_without_retry"]:
        checks.append("Review retry coverage for high-risk task states.")
    if signals["tasks_without_catch"]:
        checks.append("Add Catch handlers where task failures should be controlled.")
    if signals["terminal_failure_state_count"]:
        checks.append("Confirm terminal Fail states are expected incident boundaries.")
    if not checks:
        checks.append("No Step Functions retry/catch coverage gap found.")
    return checks


def _step_function_flow_summary(
    definition: dict[str, Any],
    states: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize ASL flow shape for clients that need a quick mental model."""

    states_by_name = {str(state.get("name")): state for state in states}
    start_at = definition.get("StartAt") if isinstance(definition, dict) else None
    task_targets = [edge.get("to") for edge in edges if edge.get("to")]
    return {
        "start_at": start_at,
        "linear_paths": _linear_paths(states_by_name, start_at),
        "choice_states": _state_names_by_type(states, "Choice"),
        "wait_states": _state_names_by_type(states, "Wait"),
        "terminal_states": [
            str(state.get("name"))
            for state in states
            if state.get("end") is True or state.get("type") in {"Succeed", "Fail"}
        ],
        "dispatcher_pattern_detected": _dispatcher_pattern_detected(task_targets),
        "unique_task_target_count": len({str(target) for target in task_targets}),
    }


def _linear_paths(
    states_by_name: dict[str, dict[str, Any]],
    start_at: Any,
    max_paths: int = 5,
    max_depth: int = 50,
) -> list[list[str]]:
    """Walk representative ASL paths while bounding cycles and fan-out."""

    if not start_at:
        return []
    paths: list[list[str]] = []
    stack: list[tuple[str, list[str]]] = [(str(start_at), [])]
    while stack and len(paths) < max_paths:
        name, path = stack.pop()
        if name in path:
            paths.append([*path, name, "<cycle>"])
            continue
        state = states_by_name.get(name)
        if state is None:
            paths.append([*path, name, "<missing>"])
            continue
        next_path = [*path, name]
        if (
            len(next_path) >= max_depth
            or state.get("end") is True
            or state.get("type")
            in {
                "Succeed",
                "Fail",
            }
        ):
            paths.append(next_path)
            continue
        next_states = _next_state_names(state)
        if not next_states:
            paths.append(next_path)
            continue
        for next_name in reversed(next_states):
            stack.append((next_name, next_path))
    return paths


def _next_state_names(state: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ["next", "default_next"]:
        value = state.get(key)
        if value:
            names.append(str(value))
    for value in state.get("choice_next", []):
        if value:
            names.append(str(value))
    return list(dict.fromkeys(names))


def _state_names_by_type(states: list[dict[str, Any]], state_type: str) -> list[str]:
    return [str(state.get("name")) for state in states if state.get("type") == state_type]


def _dispatcher_pattern_detected(task_targets: list[Any]) -> bool:
    concrete_targets = [str(target) for target in task_targets if target]
    return bool(concrete_targets) and len(set(concrete_targets)) == 1 and len(concrete_targets) > 1


def _step_function_dependency_edges(
    state_machine_arn: str,
    states: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for state in states:
        if state.get("type") != "Task":
            continue
        target = state.get("target_arn") or state.get("resource")
        integration = state.get("integration") or "unknown"
        edges.append(
            {
                "from": state_machine_arn,
                "to": target,
                "relationship": "invokes_task",
                "state_name": state.get("name"),
                "target_type": integration,
                "resource": state.get("resource"),
            }
        )
    return edges


def _step_function_iam_role_summary(runtime: AwsRuntime, role_arn: str) -> dict[str, Any]:
    role_name = _role_name_from_arn(role_arn)
    if not role_name:
        return {
            "available": False,
            "role_arn": role_arn or None,
            "role_name": None,
            "warnings": ["State machine did not include a parseable execution role ARN"],
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


def _step_function_permission_hints(
    edges: list[dict[str, Any]],
    role_arn: str,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str | None, str, tuple[str, ...], str], dict[str, Any]] = {}
    for edge in edges:
        target = edge.get("to")
        integration = edge.get("target_type")
        actions = _step_function_actions_for_integration(integration, target)
        if not actions:
            continue
        action_key = tuple(actions)
        key = (role_arn or None, str(target), action_key, str(integration))
        hint = grouped.setdefault(
            key,
            {
                "principal": role_arn or None,
                "resource": target,
                "actions_to_check": actions,
                "integration": integration,
                "state_names": [],
                "state_count": 0,
                "reason": "",
            },
        )
        state_name = edge.get("state_name")
        if state_name and state_name not in hint["state_names"]:
            hint["state_names"].append(state_name)
            hint["state_count"] = len(hint["state_names"])

    for hint in grouped.values():
        state_count = hint["state_count"]
        integration = hint["integration"]
        suffix = "state uses" if state_count == 1 else "states use"
        hint["reason"] = f"{state_count} Task {suffix} {integration} integration for this target."
    return list(grouped.values())


def _step_function_permission_checks(
    *,
    runtime: AwsRuntime,
    state_machine_name: str,
    region: str,
    role_arn: str,
    permission_hints: list[dict[str, Any]],
    include_permission_checks: bool,
    limit: int,
) -> dict[str, Any]:
    """Run bounded IAM simulations for task targets inferred from ASL."""

    if not include_permission_checks:
        return empty_permission_checks()
    candidates = _dedupe_permission_candidates(_permission_candidates(permission_hints))[:limit]
    checks = [
        _simulate_role_permission(
            runtime=runtime,
            subject_name=state_machine_name,
            region=region,
            role_arn=role_arn,
            action=str(candidate["action"]),
            resource=str(candidate["resource"]),
            source=str(candidate.get("source") or "dependency_hint"),
            reason=candidate.get("reason"),
        )
        for candidate in candidates
    ]
    return {
        "enabled": True,
        "checked_count": len(checks),
        "checks": checks,
        "summary": _permission_summary(checks),
    }


def _step_function_task_permission_proof(
    states: list[dict[str, Any]],
    permission_checks: dict[str, Any],
) -> dict[str, Any]:
    checks = permission_checks.get("checks", [])
    checks_by_resource: dict[str, list[dict[str, Any]]] = {}
    for check in checks:
        checks_by_resource.setdefault(str(check.get("resource_arn")), []).append(check)
    task_proofs = []
    for state in states:
        if state.get("type") != "Task":
            continue
        target = str(state.get("target_arn") or "")
        state_checks = checks_by_resource.get(target, [])
        task_proofs.append(
            {
                "state_name": state.get("name"),
                "integration": state.get("integration"),
                "target_arn": target or None,
                "retry_count": len(state.get("retry") or []),
                "catch_count": len(state.get("catch") or []),
                "permission_status": _task_permission_status(state_checks),
                "checked_actions": sorted(
                    str(check.get("action")) for check in state_checks if check.get("action")
                ),
            }
        )
    blockers = [
        proof["state_name"]
        for proof in task_proofs
        if proof["permission_status"] in {"denied", "unknown"}
    ]
    return {
        "status": "blocked" if blockers else "ready",
        "task_count": len(task_proofs),
        "blocked_state_names": blockers,
        "tasks": task_proofs,
    }


def _task_permission_status(checks: list[dict[str, Any]]) -> str:
    if not checks:
        return "not_checked"
    if any(check.get("allowed") is False for check in checks):
        return "denied"
    if any(check.get("allowed") is None for check in checks):
        return "unknown"
    return "allowed"


def _permission_candidates(permission_hints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for hint in permission_hints:
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


def _simulate_role_permission(
    *,
    runtime: AwsRuntime,
    subject_name: str,
    region: str,
    role_arn: str,
    action: str,
    resource: str,
    source: str,
    reason: Any,
) -> dict[str, Any]:
    role_name = _role_name_from_arn(role_arn)
    base = {
        "state_machine_name": subject_name,
        "region": region,
        "principal": {
            "type": "step_function_execution_role",
            "role_name": role_name,
            "role_arn": role_arn or None,
        },
        "action": action,
        "resource_arn": resource,
        "source": source,
        "reason": reason,
    }
    if not role_name:
        return {
            **base,
            "decision": "unknown",
            "allowed": None,
            "explicit_deny": None,
            "matched_statements": [],
            "missing_context_values": [],
            "warnings": ["State machine did not include a parseable execution role ARN"],
        }

    iam = runtime.client("iam", region=runtime.region)
    try:
        response = iam.simulate_principal_policy(
            PolicySourceArn=role_arn,
            ActionNames=[action],
            ResourceArns=[resource],
        )
    except (BotoCoreError, ClientError) as exc:
        return {
            **base,
            "decision": "unknown",
            "allowed": None,
            "explicit_deny": None,
            "matched_statements": [],
            "missing_context_values": [],
            "warnings": [str(normalize_aws_error(exc, "iam.SimulatePrincipalPolicy"))],
        }

    evaluation = _simulation_evaluation(response)
    return {
        **base,
        "decision": evaluation["decision"],
        "allowed": evaluation["allowed"],
        "explicit_deny": evaluation["explicit_deny"],
        "matched_statements": evaluation["matched_statements"],
        "missing_context_values": evaluation["missing_context_values"],
        "warnings": [],
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
            }
            for statement in result.get("MatchedStatements", [])
        ],
        "missing_context_values": [str(value) for value in result.get("MissingContextValues", [])],
    }


def _permission_summary(checks: list[dict[str, Any]]) -> dict[str, Any]:
    allowed = sum(1 for check in checks if check.get("allowed") is True)
    denied = sum(1 for check in checks if check.get("allowed") is False)
    unknown = sum(1 for check in checks if check.get("allowed") is None)
    explicit_denies = sum(1 for check in checks if check.get("explicit_deny") is True)
    return {
        "allowed": allowed,
        "denied": denied,
        "unknown": unknown,
        "explicit_denies": explicit_denies,
    }


def _step_function_integration(resource: Any) -> str | None:
    value = str(resource or "")
    if not value:
        return None
    if value.startswith("arn:aws:lambda:"):
        return "lambda"
    if value.startswith("arn:aws:states:::"):
        service = value.removeprefix("arn:aws:states:::").split(":", maxsplit=1)[0]
        return service or "aws-sdk"
    return _arn_service(value)


def _step_function_task_target_arn(
    resource: Any,
    parameters: dict[str, Any],
    state_machine_arn: str | None = None,
) -> str | None:
    value = str(resource or "")
    if value.startswith("arn:aws:lambda:"):
        return value
    parsed_state_machine = _state_machine_parts(state_machine_arn)
    for key in [
        "FunctionName",
        "FunctionName.$",
        "QueueUrl",
        "QueueUrl.$",
        "TopicArn",
        "TopicArn.$",
        "StateMachineArn",
        "StateMachineArn.$",
        "TableName",
        "TableName.$",
        "JobQueue",
        "JobQueue.$",
        "EventBusName",
        "EventBusName.$",
    ]:
        candidate = parameters.get(key)
        if isinstance(candidate, str) and candidate.startswith("arn:"):
            return candidate
        if key.startswith("QueueUrl") and isinstance(candidate, str):
            queue_arn = _sqs_queue_arn_from_url(candidate)
            if queue_arn:
                return queue_arn
        if key.startswith("TableName") and isinstance(candidate, str) and parsed_state_machine:
            return (
                f"arn:{parsed_state_machine['partition']}:dynamodb:"
                f"{parsed_state_machine['region']}:{parsed_state_machine['account']}:"
                f"table/{candidate}"
            )
    return None


def _state_machine_parts(state_machine_arn: str | None) -> dict[str, str] | None:
    if not state_machine_arn:
        return None
    match = re.fullmatch(
        r"arn:(?P<partition>aws[a-zA-Z-]*):states:(?P<region>[^:]+):"
        r"(?P<account>\d{12}):stateMachine:.+",
        state_machine_arn,
    )
    return match.groupdict() if match else None


def _sqs_queue_arn_from_url(queue_url: str) -> str | None:
    match = re.search(
        r"https?://sqs[.-](?P<region>[^./]+)\.amazonaws\.com/(?P<account>\d{12})/(?P<name>[^/?]+)",
        queue_url,
    )
    if not match:
        return None
    parts = match.groupdict()
    return f"arn:aws:sqs:{parts['region']}:{parts['account']}:{parts['name']}"


def _step_function_actions_for_integration(integration: Any, target: Any) -> list[str]:
    if not _simulatable_resource(target):
        return []
    if integration == "lambda":
        return ["lambda:InvokeFunction"]
    if integration == "batch":
        return ["batch:SubmitJob"]
    if integration == "ecs":
        return ["ecs:RunTask"]
    if integration == "sns":
        return ["sns:Publish"]
    if integration == "sqs":
        return ["sqs:SendMessage"]
    if integration == "events":
        return ["events:PutEvents"]
    if integration == "states":
        return ["states:StartExecution"]
    if integration == "dynamodb":
        return ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
    return []


def _arn_service(value: Any) -> str | None:
    if not value:
        return None
    parts = str(value).split(":")
    if len(parts) < 3 or parts[0] != "arn":
        return None
    return parts[2]


def _simulatable_resource(value: Any) -> bool:
    if not value:
        return False
    resource = str(value)
    return resource == "*" or resource.startswith("arn:")


def _collect_history_events(client: Any, execution_arn: str) -> list[dict[str, Any]]:
    """Collect recent execution history events newest-first with a hard cap."""

    events: list[dict[str, Any]] = []
    next_token: str | None = None
    while len(events) < 500:
        request: dict[str, Any] = {
            "executionArn": execution_arn,
            "reverseOrder": True,
            "maxResults": min(100, 500 - len(events)),
        }
        if next_token:
            request["nextToken"] = next_token
        response = client.get_execution_history(**request)
        events.extend(response.get("events", []))
        next_token = response.get("nextToken")
        if not next_token:
            break
    return events[:500]


def _find_failed_state(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Find the most recent failed/timed-out event and attach state context."""

    events_by_id = {int(event["id"]): event for event in events if isinstance(event.get("id"), int)}
    for event in events:
        event_type = str(event.get("type", ""))
        if event_type.endswith("Failed") or event_type in {"ExecutionFailed", "ExecutionTimedOut"}:
            return _failed_event_summary(event, events_by_id)
    return None


def _failed_event_summary(
    event: dict[str, Any],
    events_by_id: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    details = _failure_details(event)
    state_entered = _find_previous_state_entered(event, events_by_id)
    return {
        "event_id": event.get("id"),
        "previous_event_id": event.get("previousEventId"),
        "timestamp": isoformat(event.get("timestamp")),
        "type": event.get("type"),
        "state_name": _state_entered_name(state_entered) or details.get("name"),
        "error": details.get("error"),
        "cause": details.get("cause"),
        "previous_event_context": _previous_event_context(state_entered),
    }


def _previous_event_context(event: dict[str, Any] | None) -> dict[str, Any] | None:
    if event is None:
        return None
    return {
        "event_id": event.get("id"),
        "previous_event_id": event.get("previousEventId"),
        "timestamp": isoformat(event.get("timestamp")),
        "type": event.get("type"),
        "state_name": _state_entered_name(event),
    }


def _step_function_failure_definition_context(
    runtime: AwsRuntime,
    execution_arn: str,
    summary: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    failed_state = summary.get("failed_state")
    if not isinstance(failed_state, dict) or not failed_state.get("state_name"):
        return {}, []
    state_machine_arn = _state_machine_arn_from_execution_arn(execution_arn)
    if state_machine_arn is None:
        return {}, ["Unable to derive state machine ARN from execution ARN"]
    region = str(summary.get("region") or runtime.region)
    client = runtime.client("stepfunctions", region=region)
    try:
        state_machine = client.describe_state_machine(stateMachineArn=state_machine_arn)
    except (BotoCoreError, ClientError) as exc:
        return {}, [str(normalize_aws_error(exc, "states.DescribeStateMachine"))]

    definition, warnings = _parse_state_machine_definition(
        state_machine.get("definition"),
        runtime.config.redaction.max_string_length,
    )
    states = _asl_states(definition, state_machine_arn)
    state = next(
        (item for item in states if item.get("name") == failed_state.get("state_name")),
        None,
    )
    if state is None:
        return {}, [*warnings, "Failed state was not found in the state machine definition"]
    edges = _step_function_dependency_edges(state_machine_arn, states)
    downstream_edge = next(
        (edge for edge in edges if edge.get("state_name") == state.get("name")),
        None,
    )
    path = _path_to_state(definition, states, str(state["name"]))
    return {
        "failed_state_definition": {
            "name": state.get("name"),
            "type": state.get("type"),
            "resource": state.get("resource"),
            "integration": state.get("integration"),
            "target_arn": state.get("target_arn"),
            "next": state.get("next"),
            "end": state.get("end"),
            "timeout_seconds": state.get("timeout_seconds"),
            "heartbeat_seconds": state.get("heartbeat_seconds"),
        },
        "failed_state_path": path,
        "downstream_target": _downstream_target_context(downstream_edge),
        "retry_catch": {
            "retry": state.get("retry", []),
            "catch": state.get("catch", []),
            "has_retry": bool(state.get("retry")),
            "has_catch": bool(state.get("catch")),
        },
    }, warnings


def _state_machine_arn_from_execution_arn(execution_arn: str) -> str | None:
    match = re.fullmatch(
        r"arn:(?P<partition>aws[a-zA-Z-]*):states:(?P<region>[^:]+):"
        r"(?P<account>\d{12}):execution:(?P<state_machine_name>[^:]+):.+",
        execution_arn,
    )
    if not match:
        return None
    parts = match.groupdict()
    return (
        f"arn:{parts['partition']}:states:{parts['region']}:{parts['account']}:"
        f"stateMachine:{parts['state_machine_name']}"
    )


def _path_to_state(
    definition: dict[str, Any],
    states: list[dict[str, Any]],
    target_state_name: str,
) -> list[str]:
    states_by_name = {str(state.get("name")): state for state in states}
    start_at = definition.get("StartAt") if isinstance(definition, dict) else None
    for path in _linear_paths(states_by_name, start_at):
        if target_state_name in path:
            return path[: path.index(target_state_name) + 1]
    return [target_state_name]


def _downstream_target_context(edge: dict[str, Any] | None) -> dict[str, Any] | None:
    if edge is None:
        return None
    return {
        "target": edge.get("to"),
        "target_type": edge.get("target_type"),
        "relationship": edge.get("relationship"),
        "resource": edge.get("resource"),
    }


def _failure_details(event: dict[str, Any]) -> dict[str, Any]:
    for key, value in event.items():
        if (
            key.endswith("FailedEventDetails") or key.endswith("TimedOutEventDetails")
        ) and isinstance(value, dict):
            return value
    return {}


def _find_previous_state_entered(
    event: dict[str, Any],
    events_by_id: dict[int, dict[str, Any]],
) -> dict[str, Any] | None:
    """Walk previousEventId links to recover the state name for failures.

    Step Functions task failure details often omit the state name, so the
    reliable path is to follow event history back to the nearest StateEntered
    event.
    """

    previous_id = event.get("previousEventId")
    seen: set[int] = set()
    while isinstance(previous_id, int) and previous_id not in seen:
        seen.add(previous_id)
        previous = events_by_id.get(previous_id)
        if previous is None:
            return None
        if str(previous.get("type", "")).endswith("StateEntered"):
            return previous
        previous_id = previous.get("previousEventId")
    return None


def _state_entered_name(event: dict[str, Any] | None) -> str | None:
    if event is None:
        return None
    for key, value in event.items():
        if key.endswith("StateEnteredEventDetails") and isinstance(value, dict):
            name = value.get("name")
            return str(name) if name else None
    return None


def _safe_json_field(value: Any, runtime: AwsRuntime) -> dict[str, Any] | None:
    if value is None:
        return None
    max_length = runtime.config.redaction.max_string_length
    raw = str(value)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "truncated": len(raw) > max_length,
            "value": truncate_string(raw, max_length),
        }

    redacted = redact_data(parsed, runtime.config.redaction)
    rendered = json.dumps(redacted, sort_keys=True)
    return {
        "truncated": len(rendered) > max_length,
        "value": truncate_string(rendered, max_length),
    }


def _step_function_failure_signals(failed_state: Any) -> dict[str, Any]:
    if not isinstance(failed_state, dict):
        return {
            "has_failure": False,
            "lambda_or_task_failure": False,
            "timeout": False,
            "permission": False,
            "service_exception": False,
        }

    text = " ".join(
        str(failed_state.get(key) or "") for key in ["type", "state_name", "error", "cause"]
    ).lower()
    return {
        "has_failure": True,
        "lambda_or_task_failure": "lambda" in text or "task" in text,
        "timeout": "timeout" in text or "timedout" in text or "timed out" in text,
        "permission": any(
            pattern in text
            for pattern in [
                "accessdenied",
                "access denied",
                "not authorized",
                "unauthorized",
                "permission",
            ]
        ),
        "service_exception": "serviceexception" in text or "service exception" in text,
    }


def _step_function_diagnostic_summary(
    summary: dict[str, Any],
    signals: dict[str, Any],
) -> str:
    status = summary.get("status")
    if not signals["has_failure"]:
        return f"Execution status is {status}; no failed state was found in recent history."

    findings: list[str] = []
    if signals["lambda_or_task_failure"]:
        findings.append("Lambda/task failure")
    if signals["timeout"]:
        findings.append("timeout")
    if signals["permission"]:
        findings.append("permission issue")
    if signals["service_exception"]:
        findings.append("AWS service exception")

    if findings:
        return "Execution failed with " + ", ".join(findings) + " indicators."
    return "Execution failed; inspect failed state error and cause for domain-specific details."


def _step_function_suggested_next_checks(signals: dict[str, Any]) -> list[str]:
    if not signals["has_failure"]:
        return [
            "Check execution input, output, and downstream systems if behavior still looks wrong."
        ]

    checks: list[str] = []
    if signals["lambda_or_task_failure"]:
        checks.append("Inspect the failed task target, especially related Lambda logs and metrics.")
    if signals["timeout"]:
        checks.append("Compare state timeout/heartbeat settings with downstream task duration.")
    if signals["permission"]:
        checks.append("Review the state machine role and target resource permissions.")
    if signals["service_exception"]:
        checks.append(
            "Check AWS service availability, retries, throttling, and integration error handling."
        )
    if not checks:
        checks.append("Inspect the failed state cause and correlate with target service logs.")
    return checks
