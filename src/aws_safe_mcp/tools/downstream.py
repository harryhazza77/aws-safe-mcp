from __future__ import annotations

import re
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import normalize_aws_error


def event_driven_downstream_hints(
    runtime: AwsRuntime,
    rule_flows: list[dict[str, Any]],
    warnings: list[str],
) -> list[dict[str, Any]]:
    needed_services = _needed_downstream_services(rule_flows)
    visible_buckets = _visible_s3_bucket_names(runtime, warnings) if "s3" in needed_services else []
    visible_queues = _visible_sqs_queues(runtime, warnings) if "sqs" in needed_services else []
    visible_tables = (
        _visible_dynamodb_tables(runtime, warnings) if "dynamodb" in needed_services else []
    )
    visible_topics = _visible_sns_topics(runtime, warnings) if "sns" in needed_services else []
    visible_event_buses = (
        _visible_eventbridge_buses(runtime, warnings) if "eventbridge" in needed_services else []
    )
    visible_secrets = (
        _visible_secretsmanager_secrets(runtime, warnings)
        if "secretsmanager" in needed_services
        else []
    )
    visible_parameters = (
        _visible_ssm_parameters(runtime, warnings) if "ssm" in needed_services else []
    )
    visible_kms_keys = _visible_kms_aliases(runtime, warnings) if "kms" in needed_services else []
    buckets_by_flow = {
        str(flow["rule"].get("name") or ""): _referenced_s3_buckets_from_flow(
            flow,
            visible_buckets,
        )
        for flow in rule_flows
    }
    grouped: dict[str, dict[str, Any]] = {}
    for flow in rule_flows:
        rule_name = str(flow["rule"].get("name") or "")
        referenced_buckets = buckets_by_flow.get(rule_name, [])
        for lambda_node in flow["lambdas"]:
            lambda_name = str(lambda_node.get("name") or "")
            if not lambda_name:
                continue
            entry = grouped.setdefault(
                lambda_name,
                {
                    "lambda_name": lambda_name,
                    "lambda_arn": lambda_node.get("arn"),
                    "hint_count": 0,
                    "likely_services": [],
                    "hints": [],
                    "summary": "",
                },
            )
            for raw_hint in lambda_node.get("unresolved_resource_hints") or []:
                if not isinstance(raw_hint, dict):
                    continue
                hint = _event_driven_downstream_hint(
                    runtime,
                    lambda_name,
                    lambda_node,
                    raw_hint,
                    visible_buckets,
                    visible_queues,
                    visible_tables,
                    visible_topics,
                    visible_event_buses,
                    visible_secrets,
                    visible_parameters,
                    visible_kms_keys,
                    referenced_buckets,
                    warnings,
                )
                entry["hints"].append(hint)

    results: list[dict[str, Any]] = []
    for entry in grouped.values():
        hints = _dedupe_downstream_hints(entry["hints"])
        if not hints:
            continue
        services = sorted(
            {
                str(hint["likely_service"])
                for hint in hints
                if hint.get("likely_service") != "unknown"
            }
        )
        entry["hints"] = hints
        entry["hint_count"] = len(hints)
        entry["likely_services"] = services
        entry["summary"] = _event_driven_downstream_summary(
            str(entry["lambda_name"]),
            services,
            hints,
        )
        results.append(entry)
    return results


def _needed_downstream_services(rule_flows: list[dict[str, Any]]) -> set[str]:
    services: set[str] = set()
    for flow in rule_flows:
        for lambda_node in flow["lambdas"]:
            for raw_hint in lambda_node.get("unresolved_resource_hints") or []:
                if isinstance(raw_hint, dict):
                    services.add(str(raw_hint.get("likely_service") or "unknown"))
    return services


def _event_driven_downstream_hint(
    runtime: AwsRuntime,
    lambda_name: str,
    lambda_node: dict[str, Any],
    raw_hint: dict[str, Any],
    visible_buckets: list[str],
    visible_queues: list[dict[str, str]],
    visible_tables: list[dict[str, str]],
    visible_topics: list[dict[str, str]],
    visible_event_buses: list[dict[str, str]],
    visible_secrets: list[dict[str, str]],
    visible_parameters: list[dict[str, str]],
    visible_kms_keys: list[dict[str, str]],
    referenced_buckets: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    source = str(raw_hint.get("source") or "unknown")
    identifier = str(raw_hint.get("key") or raw_hint.get("name") or "")
    likely_service = str(raw_hint.get("likely_service") or "unknown")
    s3_candidates = (
        _s3_candidate_buckets(source, identifier, visible_buckets, referenced_buckets)
        if likely_service == "s3"
        else []
    )
    sqs_candidates = (
        _sqs_candidate_queues(source, identifier, visible_queues) if likely_service == "sqs" else []
    )
    dynamodb_candidates = (
        _dynamodb_candidate_tables(source, identifier, visible_tables)
        if likely_service == "dynamodb"
        else []
    )
    sns_candidates = (
        _sns_candidate_topics(source, identifier, visible_topics) if likely_service == "sns" else []
    )
    eventbridge_candidates = (
        _eventbridge_candidate_buses(source, identifier, visible_event_buses)
        if likely_service == "eventbridge"
        else []
    )
    secretsmanager_candidates = (
        _secretsmanager_candidate_secrets(source, identifier, visible_secrets)
        if likely_service == "secretsmanager"
        else []
    )
    ssm_candidates = (
        _ssm_candidate_parameters(source, identifier, visible_parameters)
        if likely_service == "ssm"
        else []
    )
    kms_candidates = (
        _kms_candidate_keys(source, identifier, visible_kms_keys) if likely_service == "kms" else []
    )
    role_arn = _lambda_execution_role_arn(lambda_node)
    if s3_candidates:
        s3_candidates = [
            _s3_candidate_with_permission_checks(
                runtime=runtime,
                lambda_name=lambda_name,
                role_arn=role_arn,
                candidate=candidate,
                warnings=warnings,
            )
            for candidate in s3_candidates
        ]
    if sqs_candidates:
        sqs_candidates = [
            _sqs_candidate_with_permission_checks(
                runtime=runtime,
                lambda_name=lambda_name,
                role_arn=role_arn,
                candidate=candidate,
                warnings=warnings,
            )
            for candidate in sqs_candidates
        ]
    if dynamodb_candidates:
        dynamodb_candidates = [
            _dynamodb_candidate_with_permission_checks(
                runtime=runtime,
                lambda_name=lambda_name,
                role_arn=role_arn,
                candidate=candidate,
                warnings=warnings,
            )
            for candidate in dynamodb_candidates
        ]
    if sns_candidates:
        sns_candidates = [
            _sns_candidate_with_permission_checks(
                runtime=runtime,
                lambda_name=lambda_name,
                role_arn=role_arn,
                candidate=candidate,
                warnings=warnings,
            )
            for candidate in sns_candidates
        ]
    if eventbridge_candidates:
        eventbridge_candidates = [
            _eventbridge_candidate_with_permission_checks(
                runtime=runtime,
                lambda_name=lambda_name,
                role_arn=role_arn,
                candidate=candidate,
                warnings=warnings,
            )
            for candidate in eventbridge_candidates
        ]
    if secretsmanager_candidates:
        secretsmanager_candidates = [
            _secretsmanager_candidate_with_permission_checks(
                runtime=runtime,
                lambda_name=lambda_name,
                role_arn=role_arn,
                candidate=candidate,
                warnings=warnings,
            )
            for candidate in secretsmanager_candidates
        ]
    if ssm_candidates:
        ssm_candidates = [
            _ssm_candidate_with_permission_checks(
                runtime=runtime,
                lambda_name=lambda_name,
                role_arn=role_arn,
                candidate=candidate,
                warnings=warnings,
            )
            for candidate in ssm_candidates
        ]
    if kms_candidates:
        kms_candidates = [
            _kms_candidate_with_permission_checks(
                runtime=runtime,
                lambda_name=lambda_name,
                role_arn=role_arn,
                candidate=candidate,
                warnings=warnings,
            )
            for candidate in kms_candidates
        ]
    has_candidates = bool(
        s3_candidates
        or sqs_candidates
        or dynamodb_candidates
        or sns_candidates
        or eventbridge_candidates
        or secretsmanager_candidates
        or ssm_candidates
        or kms_candidates
    )
    note = _sensitive_resolution_note(likely_service) if not has_candidates else None
    hint = {
        "lambda_name": lambda_name,
        "source": source,
        "identifier": identifier,
        "likely_service": likely_service,
        "inference": _hint_inference(source),
        "status": "candidate_match" if has_candidates else "unresolved",
        "verification": "candidate_name_match" if has_candidates else "not_checked",
        "s3_candidate_buckets": s3_candidates,
        "sqs_candidate_queues": sqs_candidates,
        "dynamodb_candidate_tables": dynamodb_candidates,
        "sns_candidate_topics": sns_candidates,
        "eventbridge_candidate_buses": eventbridge_candidates,
        "secretsmanager_candidate_secrets": secretsmanager_candidates,
        "ssm_candidate_parameters": ssm_candidates,
        "kms_candidate_keys": kms_candidates,
        "reason": raw_hint.get("reason"),
    }
    if note:
        hint["sensitive_resolution_note"] = note
    return hint


def _lambda_execution_role_arn(lambda_node: dict[str, Any]) -> str | None:
    execution_role = lambda_node.get("execution_role") or {}
    role_arn = execution_role.get("role_arn")
    return str(role_arn) if role_arn else None


def _s3_candidate_with_permission_checks(
    *,
    runtime: AwsRuntime,
    lambda_name: str,
    role_arn: str | None,
    candidate: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    bucket = str(candidate["bucket"])
    if not role_arn:
        return {
            **candidate,
            "permission_checks": _disabled_role_permission_checks(),
        }

    checks = [
        _simulate_named_resource_permission(
            runtime=runtime,
            role_arn=role_arn,
            lambda_name=lambda_name,
            resource_name_key="bucket",
            resource_name=bucket,
            action="s3:ListBucket",
            resource_arn=f"arn:aws:s3:::{bucket}",
            warnings=warnings,
        ),
        _simulate_named_resource_permission(
            runtime=runtime,
            role_arn=role_arn,
            lambda_name=lambda_name,
            resource_name_key="bucket",
            resource_name=bucket,
            action="s3:GetObject",
            resource_arn=f"arn:aws:s3:::{bucket}/*",
            warnings=warnings,
        ),
        _simulate_named_resource_permission(
            runtime=runtime,
            role_arn=role_arn,
            lambda_name=lambda_name,
            resource_name_key="bucket",
            resource_name=bucket,
            action="s3:PutObject",
            resource_arn=f"arn:aws:s3:::{bucket}/*",
            warnings=warnings,
        ),
    ]
    return {
        **candidate,
        "permission_checks": {
            "enabled": True,
            "checked_count": len(checks),
            "checks": checks,
            "summary": _permission_summary(checks),
        },
    }


def _sqs_candidate_with_permission_checks(
    *,
    runtime: AwsRuntime,
    lambda_name: str,
    role_arn: str | None,
    candidate: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    if not role_arn:
        return {
            **candidate,
            "permission_checks": _disabled_role_permission_checks(),
        }

    check = _simulate_named_resource_permission(
        runtime=runtime,
        role_arn=role_arn,
        lambda_name=lambda_name,
        resource_name_key="queue_name",
        resource_name=str(candidate["queue_name"]),
        action="sqs:SendMessage",
        resource_arn=str(candidate["queue_arn"]),
        warnings=warnings,
    )
    return _single_check_candidate(candidate, check)


def _dynamodb_candidate_with_permission_checks(
    *,
    runtime: AwsRuntime,
    lambda_name: str,
    role_arn: str | None,
    candidate: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    table_arn = str(candidate["table_arn"])
    if not role_arn:
        return {
            **candidate,
            "permission_checks": _disabled_role_permission_checks(),
        }

    checks = [
        _simulate_named_resource_permission(
            runtime=runtime,
            role_arn=role_arn,
            lambda_name=lambda_name,
            resource_name_key="table_name",
            resource_name=str(candidate["table_name"]),
            action=action,
            resource_arn=table_arn,
            warnings=warnings,
        )
        for action in [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:Query",
        ]
    ]
    return {
        **candidate,
        "permission_checks": {
            "enabled": True,
            "checked_count": len(checks),
            "checks": checks,
            "summary": _permission_summary(checks),
        },
    }


def _sns_candidate_with_permission_checks(
    *,
    runtime: AwsRuntime,
    lambda_name: str,
    role_arn: str | None,
    candidate: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    if not role_arn:
        return {
            **candidate,
            "permission_checks": _disabled_role_permission_checks(),
        }

    check = _simulate_named_resource_permission(
        runtime=runtime,
        role_arn=role_arn,
        lambda_name=lambda_name,
        resource_name_key="topic_name",
        resource_name=str(candidate["topic_name"]),
        action="sns:Publish",
        resource_arn=str(candidate["topic_arn"]),
        warnings=warnings,
    )
    return _single_check_candidate(candidate, check)


def _eventbridge_candidate_with_permission_checks(
    *,
    runtime: AwsRuntime,
    lambda_name: str,
    role_arn: str | None,
    candidate: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    if not role_arn:
        return {
            **candidate,
            "permission_checks": _disabled_role_permission_checks(),
        }

    check = _simulate_named_resource_permission(
        runtime=runtime,
        role_arn=role_arn,
        lambda_name=lambda_name,
        resource_name_key="event_bus_name",
        resource_name=str(candidate["event_bus_name"]),
        action="events:PutEvents",
        resource_arn=str(candidate["event_bus_arn"]),
        warnings=warnings,
    )
    return _single_check_candidate(candidate, check)


def _secretsmanager_candidate_with_permission_checks(
    *,
    runtime: AwsRuntime,
    lambda_name: str,
    role_arn: str | None,
    candidate: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    if not role_arn:
        return {
            **candidate,
            "permission_checks": _disabled_role_permission_checks(),
        }

    checks = [
        _simulate_named_resource_permission(
            runtime=runtime,
            role_arn=role_arn,
            lambda_name=lambda_name,
            resource_name_key="secret_name",
            resource_name=str(candidate["secret_name"]),
            action=action,
            resource_arn=str(candidate["secret_arn"]),
            warnings=warnings,
        )
        for action in ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
    ]
    return _multi_check_candidate(candidate, checks)


def _ssm_candidate_with_permission_checks(
    *,
    runtime: AwsRuntime,
    lambda_name: str,
    role_arn: str | None,
    candidate: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    if not role_arn:
        return {
            **candidate,
            "permission_checks": _disabled_role_permission_checks(),
        }

    check = _simulate_named_resource_permission(
        runtime=runtime,
        role_arn=role_arn,
        lambda_name=lambda_name,
        resource_name_key="parameter_name",
        resource_name=str(candidate["parameter_name"]),
        action="ssm:GetParameter",
        resource_arn=str(candidate["parameter_arn"]),
        warnings=warnings,
    )
    return _single_check_candidate(candidate, check)


def _kms_candidate_with_permission_checks(
    *,
    runtime: AwsRuntime,
    lambda_name: str,
    role_arn: str | None,
    candidate: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    if not role_arn:
        return {
            **candidate,
            "permission_checks": _disabled_role_permission_checks(),
        }

    checks = [
        _simulate_named_resource_permission(
            runtime=runtime,
            role_arn=role_arn,
            lambda_name=lambda_name,
            resource_name_key="alias_name",
            resource_name=str(candidate["alias_name"]),
            action=action,
            resource_arn=str(candidate["key_arn"]),
            warnings=warnings,
        )
        for action in ["kms:Decrypt", "kms:GenerateDataKey"]
    ]
    return _multi_check_candidate(candidate, checks)


def _multi_check_candidate(
    candidate: dict[str, Any], checks: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        **candidate,
        "permission_checks": {
            "enabled": True,
            "checked_count": len(checks),
            "checks": checks,
            "summary": _permission_summary(checks),
        },
    }


def _single_check_candidate(candidate: dict[str, Any], check: dict[str, Any]) -> dict[str, Any]:
    return {
        **candidate,
        "permission_checks": {
            "enabled": True,
            "checked_count": 1,
            "checks": [check],
            "summary": _permission_summary([check]),
        },
    }


def _simulate_named_resource_permission(
    *,
    runtime: AwsRuntime,
    role_arn: str,
    lambda_name: str,
    resource_name_key: str,
    resource_name: str,
    action: str,
    resource_arn: str,
    warnings: list[str],
) -> dict[str, Any]:
    base = {
        "source": "event_driven_downstream_hint",
        "lambda_name": lambda_name,
        "principal": {
            "type": "lambda_execution_role",
            "role_name": role_arn.rsplit("/", 1)[-1],
            "role_arn": role_arn,
        },
        resource_name_key: resource_name,
        "action": action,
        "resource_arn": resource_arn,
    }
    check = _simulate_role_permission(runtime, role_arn, action, resource_arn, base)
    if check.get("allowed") is None:
        warnings.extend(str(warning) for warning in check.get("warnings", []))
    return check


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


def _simulation_evaluation(response: dict[str, Any]) -> dict[str, Any]:
    results = response.get("EvaluationResults") or []
    if not results:
        return {
            "decision": "unknown",
            "allowed": None,
            "explicit_deny": None,
            "matched_statements": [],
            "missing_context_values": [],
        }
    result = results[0]
    decision = str(result.get("EvalDecision") or "unknown")
    return {
        "decision": decision,
        "allowed": decision.lower() == "allowed",
        "explicit_deny": decision.lower() == "explicitdeny",
        "matched_statements": result.get("MatchedStatements", []),
        "missing_context_values": result.get("MissingContextValues", []),
    }


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


def _permission_summary(checks: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "allowed": sum(1 for check in checks if check.get("allowed") is True),
        "denied": sum(1 for check in checks if check.get("allowed") is False),
        "unknown": sum(1 for check in checks if check.get("allowed") is None),
        "explicit_denies": sum(1 for check in checks if check.get("explicit_deny") is True),
    }


def _disabled_role_permission_checks() -> dict[str, Any]:
    return {
        "enabled": False,
        "checked_count": 0,
        "checks": [],
        "summary": {
            "allowed": 0,
            "denied": 0,
            "unknown": 0,
            "explicit_denies": 0,
        },
        "warnings": ["Lambda execution role ARN was unavailable."],
    }


def _hint_inference(source: str) -> str:
    if source == "environment_variable_key":
        return "inferred_from_env_key"
    if source in {"inline_policy_name", "attached_policy_name"}:
        return "inferred_from_iam_policy_name"
    return "inferred_from_metadata"


def _sensitive_resolution_note(likely_service: str) -> str | None:
    if likely_service == "secretsmanager":
        return (
            "No strong Secrets Manager name match found. This may be a raw environment "
            "value, an external secret reference, or a secret whose name does not match "
            "the metadata hint."
        )
    if likely_service == "ssm":
        return (
            "No strong SSM parameter name match found. This may be a raw environment "
            "value, an external configuration reference, or a parameter whose name does "
            "not match the metadata hint."
        )
    if likely_service == "kms":
        return (
            "No strong KMS alias match found. This may be a raw key/config value, a key "
            "ID or ARN without a matching alias, or an external key reference."
        )
    return None


def _visible_s3_bucket_names(runtime: AwsRuntime, warnings: list[str]) -> list[str]:
    try:
        response = runtime.client("s3", region=runtime.region).list_buckets()
    except (BotoCoreError, ClientError) as exc:
        warnings.append(f"s3.ListBuckets unavailable for downstream hint matching: {exc}")
        return []
    return sorted(str(item.get("Name")) for item in response.get("Buckets", []) if item.get("Name"))


def _visible_sqs_queues(runtime: AwsRuntime, warnings: list[str]) -> list[dict[str, str]]:
    client = runtime.client("sqs", region=runtime.region)
    queues: list[dict[str, str]] = []
    token: str | None = None
    try:
        while len(queues) < runtime.config.max_results:
            kwargs: dict[str, Any] = {"MaxResults": min(1000, runtime.config.max_results)}
            if token:
                kwargs["NextToken"] = token
            response = client.list_queues(**kwargs)
            for queue_url in response.get("QueueUrls", []):
                queue = _sqs_queue_summary(client, str(queue_url), warnings)
                if queue:
                    queues.append(queue)
                if len(queues) >= runtime.config.max_results:
                    break
            token = response.get("NextToken")
            if not token:
                break
    except (BotoCoreError, ClientError) as exc:
        warnings.append(f"sqs.ListQueues unavailable for downstream hint matching: {exc}")
        return []
    return sorted(queues, key=lambda item: item["queue_name"])


def _sqs_queue_summary(
    client: Any,
    queue_url: str,
    warnings: list[str],
) -> dict[str, str] | None:
    try:
        response = client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["QueueArn"],
        )
    except (BotoCoreError, ClientError) as exc:
        warnings.append(f"sqs.GetQueueAttributes unavailable for {queue_url}: {exc}")
        return None
    queue_arn = response.get("Attributes", {}).get("QueueArn")
    if not queue_arn:
        return None
    return {
        "queue_name": queue_url.rsplit("/", 1)[-1],
        "queue_url": queue_url,
        "queue_arn": str(queue_arn),
    }


def _visible_dynamodb_tables(runtime: AwsRuntime, warnings: list[str]) -> list[dict[str, str]]:
    identity = runtime.require_identity()
    client = runtime.client("dynamodb", region=runtime.region)
    tables: list[dict[str, str]] = []
    request: dict[str, Any] = {"Limit": min(100, runtime.config.max_results)}
    try:
        while len(tables) < runtime.config.max_results:
            response = client.list_tables(**request)
            for table_name in response.get("TableNames", []):
                tables.append(
                    {
                        "table_name": str(table_name),
                        "table_arn": (
                            f"arn:aws:dynamodb:{runtime.region}:{identity.account}:"
                            f"table/{table_name}"
                        ),
                    }
                )
                if len(tables) >= runtime.config.max_results:
                    break
            last_name = response.get("LastEvaluatedTableName")
            if not last_name:
                break
            request["ExclusiveStartTableName"] = last_name
    except (BotoCoreError, ClientError) as exc:
        warnings.append(f"dynamodb.ListTables unavailable for downstream hint matching: {exc}")
        return []
    return sorted(tables, key=lambda item: item["table_name"])


def _visible_sns_topics(runtime: AwsRuntime, warnings: list[str]) -> list[dict[str, str]]:
    client = runtime.client("sns", region=runtime.region)
    topics: list[dict[str, str]] = []
    token: str | None = None
    try:
        while len(topics) < runtime.config.max_results:
            kwargs: dict[str, Any] = {}
            if token:
                kwargs["NextToken"] = token
            response = client.list_topics(**kwargs)
            for item in response.get("Topics", []):
                topic_arn = str(item.get("TopicArn") or "")
                if not topic_arn:
                    continue
                topics.append(
                    {
                        "topic_name": topic_arn.rsplit(":", 1)[-1],
                        "topic_arn": topic_arn,
                    }
                )
                if len(topics) >= runtime.config.max_results:
                    break
            token = response.get("NextToken")
            if not token:
                break
    except (BotoCoreError, ClientError) as exc:
        warnings.append(f"sns.ListTopics unavailable for downstream hint matching: {exc}")
        return []
    return sorted(topics, key=lambda item: item["topic_name"])


def _visible_secretsmanager_secrets(
    runtime: AwsRuntime,
    warnings: list[str],
) -> list[dict[str, str]]:
    client = runtime.client("secretsmanager", region=runtime.region)
    secrets: list[dict[str, str]] = []
    token: str | None = None
    try:
        while len(secrets) < runtime.config.max_results:
            kwargs: dict[str, Any] = {"MaxResults": min(100, runtime.config.max_results)}
            if token:
                kwargs["NextToken"] = token
            response = client.list_secrets(**kwargs)
            for item in response.get("SecretList", []):
                name = str(item.get("Name") or "")
                arn = str(item.get("ARN") or "")
                if not name or not arn:
                    continue
                secrets.append({"secret_name": name, "secret_arn": arn})
                if len(secrets) >= runtime.config.max_results:
                    break
            token = response.get("NextToken")
            if not token:
                break
    except (BotoCoreError, ClientError) as exc:
        warnings.append(
            f"secretsmanager.ListSecrets unavailable for downstream hint matching: {exc}"
        )
        return []
    return sorted(secrets, key=lambda item: item["secret_name"])


def _visible_ssm_parameters(runtime: AwsRuntime, warnings: list[str]) -> list[dict[str, str]]:
    identity = runtime.require_identity()
    client = runtime.client("ssm", region=runtime.region)
    parameters: list[dict[str, str]] = []
    token: str | None = None
    try:
        while len(parameters) < runtime.config.max_results:
            kwargs: dict[str, Any] = {"MaxResults": min(50, runtime.config.max_results)}
            if token:
                kwargs["NextToken"] = token
            response = client.describe_parameters(**kwargs)
            for item in response.get("Parameters", []):
                name = str(item.get("Name") or "")
                if not name:
                    continue
                arn_name = name[1:] if name.startswith("/") else name
                parameters.append(
                    {
                        "parameter_name": name,
                        "parameter_arn": (
                            f"arn:aws:ssm:{runtime.region}:{identity.account}:parameter/{arn_name}"
                        ),
                    }
                )
                if len(parameters) >= runtime.config.max_results:
                    break
            token = response.get("NextToken")
            if not token:
                break
    except (BotoCoreError, ClientError) as exc:
        warnings.append(f"ssm.DescribeParameters unavailable for downstream hint matching: {exc}")
        return []
    return sorted(parameters, key=lambda item: item["parameter_name"])


def _visible_kms_aliases(runtime: AwsRuntime, warnings: list[str]) -> list[dict[str, str]]:
    identity = runtime.require_identity()
    client = runtime.client("kms", region=runtime.region)
    aliases: list[dict[str, str]] = []
    marker: str | None = None
    try:
        while len(aliases) < runtime.config.max_results:
            kwargs: dict[str, Any] = {"Limit": min(100, runtime.config.max_results)}
            if marker:
                kwargs["Marker"] = marker
            response = client.list_aliases(**kwargs)
            for item in response.get("Aliases", []):
                alias_name = str(item.get("AliasName") or "")
                target_key_id = str(item.get("TargetKeyId") or "")
                if not alias_name or not target_key_id:
                    continue
                aliases.append(
                    {
                        "alias_name": alias_name,
                        "key_id": target_key_id,
                        "key_arn": (
                            f"arn:aws:kms:{runtime.region}:{identity.account}:key/{target_key_id}"
                        ),
                    }
                )
                if len(aliases) >= runtime.config.max_results:
                    break
            marker = response.get("NextMarker")
            if not response.get("Truncated") or not marker:
                break
    except (BotoCoreError, ClientError) as exc:
        warnings.append(f"kms.ListAliases unavailable for downstream hint matching: {exc}")
        return []
    return sorted(aliases, key=lambda item: item["alias_name"])


def _visible_eventbridge_buses(runtime: AwsRuntime, warnings: list[str]) -> list[dict[str, str]]:
    client = runtime.client("events", region=runtime.region)
    buses = _list_event_buses(client, runtime.config.max_results, warnings)
    account = runtime.require_identity().account
    return sorted(
        [
            {
                "event_bus_name": str(bus["name"]),
                "event_bus_arn": str(
                    bus.get("arn")
                    or f"arn:aws:events:{runtime.region}:{account}:event-bus/{bus['name']}"
                ),
            }
            for bus in buses
            if bus.get("name")
        ],
        key=lambda item: item["event_bus_name"],
    )


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


def _referenced_s3_buckets_from_flow(
    flow: dict[str, Any],
    visible_buckets: list[str],
) -> list[str]:
    pattern = ((flow.get("rule") or {}).get("event_pattern") or {}).get("value")
    if not pattern:
        return []
    rendered = str(pattern)
    return [bucket for bucket in visible_buckets if bucket in rendered]


def _s3_candidate_buckets(
    source: str,
    identifier: str,
    visible_buckets: list[str],
    referenced_buckets: list[str],
) -> list[dict[str, Any]]:
    tokens = _resource_identifier_tokens(identifier)
    token_counts = {
        token: sum(1 for bucket in visible_buckets if token in _normalized_resource_name(bucket))
        for token in tokens
    }
    discriminating_tokens = [
        token for token in tokens if token_counts[token] <= max(1, len(visible_buckets) // 3)
    ]
    candidates: list[dict[str, Any]] = []
    for bucket in visible_buckets:
        reasons: list[str] = []
        score = 0
        matching_tokens = [
            token for token in discriminating_tokens if token in _normalized_resource_name(bucket)
        ]
        if bucket in referenced_buckets and matching_tokens:
            score += 60
            reasons.append("EventBridge event pattern references this bucket.")
        if matching_tokens:
            score += 30
            reasons.append(f"Identifier token(s) match bucket name: {', '.join(matching_tokens)}.")
        if source != "environment_variable_key" and len(matching_tokens) < 2:
            continue
        if not score:
            continue
        candidates.append(
            {
                "bucket": bucket,
                "confidence": _candidate_confidence(score),
                "match_type": "event_pattern_and_name"
                if bucket in referenced_buckets and matching_tokens
                else "event_pattern_reference"
                if bucket in referenced_buckets
                else "name_token_match",
                "reasons": reasons,
            }
        )
    return sorted(
        candidates,
        key=lambda item: (
            {"high": 2, "medium": 1, "low": 0}.get(str(item["confidence"]), 0),
            str(item["bucket"]),
        ),
        reverse=True,
    )[:5]


def _sqs_candidate_queues(
    source: str,
    identifier: str,
    visible_queues: list[dict[str, str]],
) -> list[dict[str, Any]]:
    return _named_resource_candidates(
        source=source,
        identifier=identifier,
        resources=visible_queues,
        name_key="queue_name",
        reason_label="queue",
    )


def _dynamodb_candidate_tables(
    source: str,
    identifier: str,
    visible_tables: list[dict[str, str]],
) -> list[dict[str, Any]]:
    return _named_resource_candidates(
        source=source,
        identifier=identifier,
        resources=visible_tables,
        name_key="table_name",
        reason_label="table",
    )


def _sns_candidate_topics(
    source: str,
    identifier: str,
    visible_topics: list[dict[str, str]],
) -> list[dict[str, Any]]:
    return _named_resource_candidates(
        source=source,
        identifier=identifier,
        resources=visible_topics,
        name_key="topic_name",
        reason_label="topic",
    )


def _eventbridge_candidate_buses(
    source: str,
    identifier: str,
    visible_buses: list[dict[str, str]],
) -> list[dict[str, Any]]:
    return _named_resource_candidates(
        source=source,
        identifier=identifier,
        resources=visible_buses,
        name_key="event_bus_name",
        reason_label="event bus",
    )


def _secretsmanager_candidate_secrets(
    source: str,
    identifier: str,
    visible_secrets: list[dict[str, str]],
) -> list[dict[str, Any]]:
    return _sensitive_named_resource_candidates(
        source=source,
        identifier=identifier,
        resources=visible_secrets,
        name_key="secret_name",
        reason_label="secret",
    )


def _ssm_candidate_parameters(
    source: str,
    identifier: str,
    visible_parameters: list[dict[str, str]],
) -> list[dict[str, Any]]:
    return _sensitive_named_resource_candidates(
        source=source,
        identifier=identifier,
        resources=visible_parameters,
        name_key="parameter_name",
        reason_label="parameter",
    )


def _kms_candidate_keys(
    source: str,
    identifier: str,
    visible_kms_keys: list[dict[str, str]],
) -> list[dict[str, Any]]:
    return _sensitive_named_resource_candidates(
        source=source,
        identifier=identifier,
        resources=visible_kms_keys,
        name_key="alias_name",
        reason_label="KMS alias",
    )


def _sensitive_named_resource_candidates(
    *,
    source: str,
    identifier: str,
    resources: list[dict[str, str]],
    name_key: str,
    reason_label: str,
) -> list[dict[str, Any]]:
    tokens = _resource_identifier_tokens(identifier)
    if not tokens:
        return []
    names = [resource[name_key] for resource in resources]
    token_counts = {
        token: sum(1 for name in names if token in _normalized_resource_name(name))
        for token in tokens
    }
    discriminating_tokens = [
        token for token in tokens if token_counts[token] <= max(1, len(names) // 4)
    ]
    candidates: list[dict[str, Any]] = []
    for resource in resources:
        matching_tokens = [
            token
            for token in discriminating_tokens
            if token in _normalized_resource_name(resource[name_key])
        ]
        if len(matching_tokens) < 1:
            continue
        if source != "environment_variable_key" and len(matching_tokens) < 2:
            continue
        candidates.append(
            {
                **resource,
                "confidence": _candidate_confidence(30 * len(matching_tokens)),
                "match_type": "sensitive_name_token_match",
                "reasons": [
                    f"Identifier token(s) match {reason_label} name: {', '.join(matching_tokens)}."
                ],
            }
        )
    return sorted(
        candidates,
        key=lambda item: (
            {"high": 2, "medium": 1, "low": 0}.get(str(item["confidence"]), 0),
            str(item[name_key]),
        ),
        reverse=True,
    )[:3]


def _named_resource_candidates(
    *,
    source: str,
    identifier: str,
    resources: list[dict[str, str]],
    name_key: str,
    reason_label: str,
) -> list[dict[str, Any]]:
    tokens = _resource_identifier_tokens(identifier)
    names = [resource[name_key] for resource in resources]
    token_counts = {
        token: sum(1 for name in names if token in _normalized_resource_name(name))
        for token in tokens
    }
    discriminating_tokens = [
        token for token in tokens if token_counts[token] <= max(1, len(names) // 3)
    ]
    candidates: list[dict[str, Any]] = []
    for resource in resources:
        matching_tokens = [
            token
            for token in discriminating_tokens
            if token in _normalized_resource_name(resource[name_key])
        ]
        if source != "environment_variable_key" and len(matching_tokens) < 2:
            continue
        if not matching_tokens:
            continue
        candidates.append(
            {
                **resource,
                "confidence": _candidate_confidence(30),
                "match_type": "name_token_match",
                "reasons": [
                    f"Identifier token(s) match {reason_label} name: {', '.join(matching_tokens)}."
                ],
            }
        )
    return sorted(
        candidates,
        key=lambda item: (
            {"high": 2, "medium": 1, "low": 0}.get(str(item["confidence"]), 0),
            str(item[name_key]),
        ),
        reverse=True,
    )[:5]


def _resource_identifier_tokens(value: str) -> list[str]:
    ignored = {
        "aws",
        "arn",
        "bucket",
        "buckets",
        "bus",
        "buses",
        "dev",
        "development",
        "encryption",
        "event",
        "events",
        "eventbridge",
        "id",
        "key",
        "keys",
        "name",
        "parameter",
        "parameters",
        "param",
        "params",
        "prod",
        "production",
        "poc",
        "queue",
        "queues",
        "s3",
        "sqs",
        "stage",
        "staging",
        "secret",
        "secrets",
        "secretsmanager",
        "table",
        "tables",
        "test",
        "topic",
        "topics",
        "url",
    }
    return [
        token
        for token in re.split(r"[^a-z0-9]+", value.lower())
        if len(token) >= 3 and token not in ignored
    ]


def _normalized_resource_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower())


def _candidate_confidence(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _dedupe_downstream_hints(hints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for hint in hints:
        key = (
            str(hint.get("source") or ""),
            str(hint.get("identifier") or ""),
            str(hint.get("likely_service") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hint)
    return deduped


def _event_driven_downstream_summary(
    lambda_name: str,
    services: list[str],
    hints: list[dict[str, Any]],
) -> str:
    if not hints:
        return f"Lambda {lambda_name} has no inferred downstream hints."
    service_text = ", ".join(services) if services else "unknown services"
    identifiers = [str(hint["identifier"]) for hint in hints if hint.get("identifier")][:5]
    identifier_text = f" from {', '.join(identifiers)}" if identifiers else ""
    candidate_texts = [
        _s3_candidate_summary_text(hints),
        _sqs_candidate_summary_text(hints),
        _dynamodb_candidate_summary_text(hints),
        _sns_candidate_summary_text(hints),
        _eventbridge_candidate_summary_text(hints),
        _secretsmanager_candidate_summary_text(hints),
        _ssm_candidate_summary_text(hints),
        _kms_candidate_summary_text(hints),
    ]
    candidate_text = " ".join(text for text in candidate_texts if text)
    candidate_text = f" {candidate_text}" if candidate_text else ""
    return (
        f"Lambda {lambda_name} likely depends on {service_text}{identifier_text}; "
        "hints are inferred from metadata and resource targets are not fully verified."
        f"{candidate_text}"
    )


def _s3_candidate_summary_text(hints: list[dict[str, Any]]) -> str:
    return _multi_action_candidate_summary_text(
        hints,
        candidate_key="s3_candidate_buckets",
        identifier_label="S3 candidates",
        name_key="bucket",
    )


def _sqs_candidate_summary_text(hints: list[dict[str, Any]]) -> str:
    return _single_action_candidate_summary_text(
        hints,
        candidate_key="sqs_candidate_queues",
        identifier_label="SQS candidates",
        name_key="queue_name",
        action_label="SendMessage",
    )


def _dynamodb_candidate_summary_text(hints: list[dict[str, Any]]) -> str:
    return _multi_action_candidate_summary_text(
        hints,
        candidate_key="dynamodb_candidate_tables",
        identifier_label="DynamoDB candidates",
        name_key="table_name",
    )


def _sns_candidate_summary_text(hints: list[dict[str, Any]]) -> str:
    return _single_action_candidate_summary_text(
        hints,
        candidate_key="sns_candidate_topics",
        identifier_label="SNS candidates",
        name_key="topic_name",
        action_label="Publish",
    )


def _eventbridge_candidate_summary_text(hints: list[dict[str, Any]]) -> str:
    return _single_action_candidate_summary_text(
        hints,
        candidate_key="eventbridge_candidate_buses",
        identifier_label="EventBridge candidates",
        name_key="event_bus_name",
        action_label="PutEvents",
    )


def _secretsmanager_candidate_summary_text(hints: list[dict[str, Any]]) -> str:
    return _multi_action_candidate_summary_text(
        hints,
        candidate_key="secretsmanager_candidate_secrets",
        identifier_label="Secrets Manager candidates",
        name_key="secret_name",
    )


def _ssm_candidate_summary_text(hints: list[dict[str, Any]]) -> str:
    return _single_action_candidate_summary_text(
        hints,
        candidate_key="ssm_candidate_parameters",
        identifier_label="SSM Parameter candidates",
        name_key="parameter_name",
        action_label="GetParameter",
    )


def _kms_candidate_summary_text(hints: list[dict[str, Any]]) -> str:
    return _multi_action_candidate_summary_text(
        hints,
        candidate_key="kms_candidate_keys",
        identifier_label="KMS alias candidates",
        name_key="alias_name",
    )


def _multi_action_candidate_summary_text(
    hints: list[dict[str, Any]],
    *,
    candidate_key: str,
    identifier_label: str,
    name_key: str,
) -> str:
    mappings: list[str] = []
    for hint in hints:
        candidates = hint.get(candidate_key) or []
        if not candidates:
            continue
        names = [
            _multi_action_candidate_summary(candidate, name_key) for candidate in candidates[:3]
        ]
        mappings.append(f"{hint.get('identifier')} -> {', '.join(names)}")
    if not mappings:
        return ""
    return f"{identifier_label}: {'; '.join(mappings)}."


def _multi_action_candidate_summary(candidate: dict[str, Any], name_key: str) -> str:
    name = str(candidate.get(name_key) or "")
    permission_checks = candidate.get("permission_checks") or {}
    if not permission_checks.get("enabled"):
        return name
    summary = permission_checks.get("summary") or {}
    allowed = int(summary.get("allowed") or 0)
    denied = int(summary.get("denied") or 0)
    unknown = int(summary.get("unknown") or 0)
    checked = int(permission_checks.get("checked_count") or 0)
    if checked == 0:
        return name
    if denied:
        status = f"{denied}/{checked} denied"
    elif unknown:
        status = f"{unknown}/{checked} unknown"
    else:
        status = f"{allowed}/{checked} allowed"
    return f"{name} ({status})"


def _single_action_candidate_summary_text(
    hints: list[dict[str, Any]],
    *,
    candidate_key: str,
    identifier_label: str,
    name_key: str,
    action_label: str,
) -> str:
    mappings: list[str] = []
    for hint in hints:
        candidates = hint.get(candidate_key) or []
        if not candidates:
            continue
        names = [
            _single_action_candidate_summary(candidate, name_key, action_label)
            for candidate in candidates[:3]
        ]
        mappings.append(f"{hint.get('identifier')} -> {', '.join(names)}")
    if not mappings:
        return ""
    return f"{identifier_label}: {'; '.join(mappings)}."


def _single_action_candidate_summary(
    candidate: dict[str, Any],
    name_key: str,
    action_label: str,
) -> str:
    name = str(candidate.get(name_key) or "")
    permission_checks = candidate.get("permission_checks") or {}
    if not permission_checks.get("enabled"):
        return name
    summary = permission_checks.get("summary") or {}
    allowed = int(summary.get("allowed") or 0)
    denied = int(summary.get("denied") or 0)
    unknown = int(summary.get("unknown") or 0)
    if denied:
        status = f"{action_label} denied"
    elif unknown:
        status = f"{action_label} unknown"
    elif allowed:
        status = f"{action_label} allowed"
    else:
        return name
    return f"{name} ({status})"
