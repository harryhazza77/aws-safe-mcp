from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.apigateway import list_api_gateways
from aws_safe_mcp.tools.cloudwatch import list_cloudwatch_alarms, list_cloudwatch_log_groups
from aws_safe_mcp.tools.common import clamp_limit, resolve_region
from aws_safe_mcp.tools.dynamodb import list_dynamodb_tables
from aws_safe_mcp.tools.eventbridge import list_eventbridge_rules
from aws_safe_mcp.tools.lambda_tools import (
    explain_lambda_dependencies,
    get_lambda_recent_errors,
    list_lambda_functions,
)
from aws_safe_mcp.tools.s3 import list_s3_buckets
from aws_safe_mcp.tools.stepfunctions import list_step_functions

SUPPORTED_SERVICES = {
    "lambda",
    "stepfunctions",
    "s3",
    "dynamodb",
    "cloudwatch",
    "apigateway",
    "eventbridge",
}


def search_aws_resources(
    runtime: AwsRuntime,
    query: str,
    services: list[str] | None = None,
    region: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    normalized_query = query.strip().lower()
    if not normalized_query:
        raise ToolInputError("query is required")
    selected = _selected_services(services)
    limit = max_results or 50
    results: list[dict[str, Any]] = []
    warnings: list[str] = []

    for service in selected:
        try:
            results.extend(_search_service(runtime, service, normalized_query, region, limit))
        except Exception as exc:  # noqa: BLE001 - search should be best-effort across services
            warnings.append(f"{service}: {exc}")

    return {
        "query": query,
        "services": selected,
        "region": region or runtime.region,
        "count": len(results[:limit]),
        "results": results[:limit],
        "warnings": warnings,
    }


def search_aws_resources_by_tag(
    runtime: AwsRuntime,
    tag_key: str,
    tag_value: str | None = None,
    region: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    required_key = _require_tag_key(tag_key)
    resolved_region = resolve_region(runtime, region)
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    client = runtime.client("resourcegroupstaggingapi", region=resolved_region)
    request: dict[str, Any] = {
        "ResourcesPerPage": min(limit, 100),
        "TagFilters": [{"Key": required_key}],
    }
    if tag_value is not None:
        request["TagFilters"][0]["Values"] = [tag_value]

    resources: list[dict[str, Any]] = []
    pagination_token = ""
    warnings: list[str] = []
    try:
        while len(resources) < limit:
            page_request = dict(request)
            if pagination_token:
                page_request["PaginationToken"] = pagination_token
            response = client.get_resources(**page_request)
            for item in response.get("ResourceTagMappingList", []):
                resources.append(_tagged_resource_summary(item))
                if len(resources) >= limit:
                    break
            pagination_token = str(response.get("PaginationToken") or "")
            if not pagination_token:
                break
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "tagging.GetResources")))

    return {
        "tag_key": required_key,
        "tag_value": tag_value,
        "region": resolved_region,
        "count": len(resources),
        "is_truncated": bool(pagination_token),
        "summary": _tagged_resource_group_summary(resources),
        "resources": resources,
        "warnings": warnings,
    }


def get_cross_service_incident_brief(
    runtime: AwsRuntime,
    query: str,
    region: str | None = None,
    max_matches: int | None = None,
) -> dict[str, Any]:
    normalized_query = query.strip()
    if not normalized_query:
        raise ToolInputError("query is required")
    limit = clamp_limit(
        max_matches,
        default=10,
        configured_max=runtime.config.max_results,
        label="max_matches",
    )
    warnings: list[str] = []
    resources = search_aws_resources(
        runtime,
        query=normalized_query,
        region=region,
        max_results=limit,
    )
    alarms = _incident_alarm_matches(runtime, normalized_query, region, limit, warnings)
    lambda_context = [
        _incident_lambda_context(runtime, str(item.get("name")), region, warnings)
        for item in resources.get("results", [])
        if item.get("service") == "lambda"
    ][:3]
    return {
        "query": normalized_query,
        "region": region or runtime.region,
        "matching_resources": resources,
        "alarm_matches": alarms,
        "lambda_context": lambda_context,
        "suggested_next_checks": _incident_next_checks(resources, alarms, lambda_context),
        "warnings": [*resources.get("warnings", []), *warnings],
    }


def plan_end_to_end_transaction_trace(
    runtime: AwsRuntime,
    seed_resource: str,
    region: str | None = None,
    max_matches: int | None = None,
) -> dict[str, Any]:
    seed = seed_resource.strip()
    if not seed:
        raise ToolInputError("seed_resource is required")
    brief = get_cross_service_incident_brief(
        runtime,
        seed,
        region=region,
        max_matches=max_matches,
    )
    resources = brief.get("matching_resources", {}).get("results", [])
    ordered = _transaction_trace_steps(resources)
    return {
        "seed_resource": seed,
        "region": region or runtime.region,
        "probable_resources": resources,
        "trace_plan": ordered,
        "probable_breakpoints": _transaction_breakpoints(ordered, brief),
        "source_brief": brief,
    }


def get_risk_scored_dependency_health_summary(
    runtime: AwsRuntime,
    application_prefix: str,
    region: str | None = None,
    max_matches: int | None = None,
) -> dict[str, Any]:
    prefix = application_prefix.strip()
    if not prefix:
        raise ToolInputError("application_prefix is required")
    resources = search_aws_resources(runtime, prefix, region=region, max_results=max_matches)
    scores = [_resource_health_score(item) for item in resources.get("results", [])]
    total = sum(item["score"] for item in scores)
    average = round(total / len(scores), 2) if scores else 0
    return {
        "application_prefix": prefix,
        "region": region or runtime.region,
        "resource_count": len(scores),
        "average_risk_score": average,
        "resources": scores,
        "summary": {
            "status": "risks_detected"
            if any(item["score"] > 0 for item in scores)
            else "no_resources",
            "highest_risk_score": max((item["score"] for item in scores), default=0),
        },
        "warnings": resources.get("warnings", []),
    }


def diagnose_region_partition_mismatches(
    runtime: AwsRuntime,
    resource_refs: list[str],
    expected_region: str | None = None,
    expected_partition: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region or expected_region)
    resolved_partition = expected_partition or "aws"
    refs = [_require_resource_ref(value) for value in resource_refs]
    findings = [
        _region_partition_finding(ref, resolved_region, resolved_partition) for ref in refs
    ]
    endpoint_findings = _endpoint_override_findings(
        runtime,
        expected_region=resolved_region,
        expected_partition=resolved_partition,
    )
    all_findings = [*findings, *endpoint_findings]
    mismatches = [finding for finding in all_findings if finding["status"] == "mismatch"]
    unknown = [finding for finding in all_findings if finding["status"] == "unknown"]
    return {
        "expected_region": resolved_region,
        "expected_partition": resolved_partition,
        "checked_count": len(all_findings),
        "mismatch_count": len(mismatches),
        "unknown_count": len(unknown),
        "summary": _region_partition_summary(mismatches, unknown),
        "findings": all_findings,
        "warnings": [],
    }


def _require_tag_key(tag_key: str) -> str:
    normalized = tag_key.strip()
    if not normalized:
        raise ToolInputError("tag_key is required")
    return normalized


def _require_resource_ref(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ToolInputError("resource_refs must not contain blank values")
    return normalized


def _incident_alarm_matches(
    runtime: AwsRuntime,
    query: str,
    region: str | None,
    limit: int,
    warnings: list[str],
) -> list[dict[str, Any]]:
    try:
        response = list_cloudwatch_alarms(runtime, region=region, max_results=limit)
    except Exception as exc:  # noqa: BLE001 - incident brief is best-effort
        warnings.append(f"cloudwatch_alarms: {exc}")
        return []
    normalized = query.lower()
    matches = []
    for alarm in response.get("alarms", []):
        resource_names = " ".join(
            str(resource.get("name") or "") for resource in alarm.get("inferred_resources", [])
        )
        haystack = " ".join(
            [
                str(alarm.get("alarm_name") or ""),
                str(alarm.get("namespace") or ""),
                str(alarm.get("metric_name") or ""),
                resource_names,
            ]
        ).lower()
        if normalized in haystack:
            matches.append(alarm)
    return matches[:limit]


def _incident_lambda_context(
    runtime: AwsRuntime,
    function_name: str,
    region: str | None,
    warnings: list[str],
) -> dict[str, Any]:
    context: dict[str, Any] = {"function_name": function_name}
    try:
        errors = get_lambda_recent_errors(
            runtime,
            function_name,
            region=region,
            max_events=5,
            since_minutes=60,
        )
        context["recent_error_count"] = errors.get("count")
        context["recent_error_groups"] = errors.get("groups", [])[:3]
    except Exception as exc:  # noqa: BLE001 - incident brief is best-effort
        warnings.append(f"lambda_recent_errors:{function_name}: {exc}")
    try:
        dependencies = explain_lambda_dependencies(
            runtime,
            function_name,
            region=region,
            include_permission_checks=False,
        )
        context["dependency_summary"] = dependencies.get("graph_summary")
        context["dependency_edges"] = dependencies.get("edges", [])[:10]
    except Exception as exc:  # noqa: BLE001 - incident brief is best-effort
        warnings.append(f"lambda_dependencies:{function_name}: {exc}")
    return context


def _incident_next_checks(
    resources: dict[str, Any],
    alarms: list[dict[str, Any]],
    lambda_context: list[dict[str, Any]],
) -> list[str]:
    checks = []
    if alarms:
        checks.append("Review matching CloudWatch alarms first; they encode expected symptoms.")
    if any(context.get("recent_error_count") for context in lambda_context):
        checks.append(
            "Inspect grouped Lambda errors and dependency edges for the failing function."
        )
    if resources.get("count", 0) == 0:
        checks.append("Broaden the resource name fragment or search by tag.")
    if not checks:
        checks.append(
            "Open the matching resource summaries and follow dependency tools for the service."
        )
    return checks


def _transaction_trace_steps(resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order = ["apigateway", "eventbridge", "stepfunctions", "lambda", "sqs", "dynamodb", "s3"]
    by_service: dict[str, list[dict[str, Any]]] = {service: [] for service in order}
    for item in resources:
        service = str(item.get("service") or "")
        if service in by_service:
            by_service[service].append(item)
    steps = []
    for service in order:
        for item in by_service[service]:
            steps.append(
                {
                    "service": service,
                    "resource": item.get("name") or item.get("arn"),
                    "check": _transaction_check_for_service(service),
                }
            )
    return steps


def _transaction_check_for_service(service: str) -> str:
    return {
        "apigateway": "investigate API Gateway route integration and Lambda permission",
        "eventbridge": "investigate rule delivery and target policy",
        "stepfunctions": "explain task dependencies and execution failures",
        "lambda": "inspect Lambda errors, dependencies, network, and invocation proof",
        "sqs": "check queue delivery, visibility timeout, DLQ, and Lambda mapping",
        "dynamodb": "inspect table state, streams, and encryption",
        "s3": "inspect bucket policy, notifications, and encryption",
    }.get(service, "inspect resource summary")


def _transaction_breakpoints(
    steps: list[dict[str, Any]],
    brief: dict[str, Any],
) -> list[dict[str, str]]:
    breakpoints = [
        {"stage": str(step["service"]), "reason": str(step["check"])} for step in steps[:5]
    ]
    if brief.get("alarm_matches", {}).get("count", 0):
        breakpoints.insert(0, {"stage": "cloudwatch", "reason": "matching alarms exist"})
    return breakpoints


def _resource_health_score(item: dict[str, Any]) -> dict[str, Any]:
    service = str(item.get("service") or "unknown")
    risks = []
    if service in {"lambda", "sqs", "eventbridge", "apigateway"}:
        risks.append("callability_not_proven")
    if service in {"lambda", "apigateway"}:
        risks.append("observability_should_be_checked")
    score = min(100, len(risks) * 25)
    return {
        "service": service,
        "name": item.get("name"),
        "arn": item.get("arn"),
        "score": score,
        "risks": risks,
    }


def _selected_services(services: list[str] | None) -> list[str]:
    if not services:
        return sorted(SUPPORTED_SERVICES)
    selected = [service.lower() for service in services]
    unsupported = sorted(set(selected) - SUPPORTED_SERVICES)
    if unsupported:
        raise ToolInputError(f"unsupported services: {', '.join(unsupported)}")
    return selected


def _search_service(
    runtime: AwsRuntime,
    service: str,
    query: str,
    region: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    if service == "lambda":
        response = list_lambda_functions(runtime, region=region, max_results=limit)
        return [
            _result("lambda", item.get("function_name"), item)
            for item in response.get("functions", [])
            if _matches(query, item.get("function_name"))
        ]
    if service == "stepfunctions":
        response = list_step_functions(runtime, region=region, max_results=limit)
        return [
            _result("stepfunctions", item.get("name"), item)
            for item in response.get("state_machines", [])
            if _matches(query, item.get("name"))
        ]
    if service == "s3":
        response = list_s3_buckets(runtime, max_results=limit)
        return [
            _result("s3", item.get("name"), item)
            for item in response.get("buckets", [])
            if _matches(query, item.get("name"))
        ]
    if service == "dynamodb":
        response = list_dynamodb_tables(runtime, region=region, max_results=limit)
        return [
            _result("dynamodb", item, {"table_name": item})
            for item in response.get("tables", [])
            if _matches(query, item)
        ]
    if service == "cloudwatch":
        response = list_cloudwatch_log_groups(runtime, region=region, max_results=limit)
        return [
            _result("cloudwatch", item.get("log_group_name"), item)
            for item in response.get("log_groups", [])
            if _matches(query, item.get("log_group_name"))
        ]
    if service == "apigateway":
        response = list_api_gateways(runtime, region=region, max_results=limit)
        return [
            _result("apigateway", item.get("name"), item)
            for item in response.get("apis", [])
            if _matches(query, item.get("name")) or _matches(query, item.get("api_id"))
        ]
    if service == "eventbridge":
        response = list_eventbridge_rules(runtime, region=region, max_results=limit)
        return [
            _result("eventbridge", item.get("name"), item)
            for item in response.get("rules", [])
            if _matches(query, item.get("name")) or _matches(query, item.get("event_bus_name"))
        ]
    return []


def _matches(query: str, value: Any) -> bool:
    return query in str(value or "").lower()


def _result(service: str, name: Any, item: dict[str, Any]) -> dict[str, Any]:
    return {
        "service": service,
        "name": name,
        "summary": item,
    }


def _tagged_resource_summary(item: dict[str, Any]) -> dict[str, Any]:
    arn = str(item.get("ResourceARN") or "")
    arn_parts = _arn_parts(arn)
    return {
        "arn": arn,
        "service": arn_parts["service"],
        "resource_type": arn_parts["resource_type"],
        "name": arn_parts["name"],
        "tags": _tag_summary(item.get("Tags")),
    }


def _arn_parts(arn: str) -> dict[str, str | None]:
    parts = arn.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return {"service": None, "resource_type": None, "name": arn or None}
    resource = parts[5]
    if "/" in resource:
        resource_type, name = resource.split("/", 1)
    elif ":" in resource:
        resource_type, name = resource.split(":", 1)
    else:
        resource_type, name = None, resource
    return {"service": parts[2], "resource_type": resource_type, "name": name}


def _tag_summary(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    tags = []
    for item in value:
        if not isinstance(item, dict):
            continue
        tags.append({"key": str(item.get("Key") or ""), "value": str(item.get("Value") or "")})
    return tags


def _tagged_resource_group_summary(resources: list[dict[str, Any]]) -> dict[str, Any]:
    by_service: dict[str, int] = {}
    by_resource_type: dict[str, int] = {}
    for resource in resources:
        service = str(resource.get("service") or "unknown")
        resource_type = str(resource.get("resource_type") or "unknown")
        by_service[service] = by_service.get(service, 0) + 1
        by_resource_type[resource_type] = by_resource_type.get(resource_type, 0) + 1
    return {
        "resource_count": len(resources),
        "by_service": by_service,
        "by_resource_type": by_resource_type,
    }


def _region_partition_finding(
    value: str,
    expected_region: str,
    expected_partition: str,
) -> dict[str, Any]:
    parsed = _parse_region_partition_ref(value)
    observed_region = parsed.get("region")
    observed_partition = parsed.get("partition")
    mismatches: list[dict[str, str | None]] = []
    if observed_region and observed_region != expected_region:
        mismatches.append(
            {
                "field": "region",
                "expected": expected_region,
                "observed": observed_region,
            }
        )
    if observed_partition and observed_partition != expected_partition:
        mismatches.append(
            {
                "field": "partition",
                "expected": expected_partition,
                "observed": observed_partition,
            }
        )
    status = "mismatch" if mismatches else "ok"
    if not observed_region and not observed_partition:
        status = "unknown"
    return {
        "source": "input",
        "value": value,
        "kind": parsed["kind"],
        "service": parsed.get("service"),
        "region": observed_region,
        "partition": observed_partition,
        "status": status,
        "mismatches": mismatches,
    }


def _endpoint_override_findings(
    runtime: AwsRuntime,
    expected_region: str,
    expected_partition: str,
) -> list[dict[str, Any]]:
    configured: list[tuple[str, str]] = []
    if runtime.config.endpoint_url:
        configured.append(("global", runtime.config.endpoint_url))
    configured.extend(sorted(runtime.config.service_endpoint_urls.items()))
    findings = []
    for service, endpoint_url in configured:
        finding = _region_partition_finding(endpoint_url, expected_region, expected_partition)
        finding["source"] = "config_endpoint"
        finding["service"] = service if service != "global" else finding.get("service")
        findings.append(finding)
    return findings


def _parse_region_partition_ref(value: str) -> dict[str, str | None]:
    arn = _parse_arn_region_partition(value)
    if arn:
        return arn
    url = _parse_url_region_partition(value)
    if url:
        return url
    return {
        "kind": "name_or_unknown",
        "service": None,
        "region": None,
        "partition": None,
    }


def _parse_arn_region_partition(value: str) -> dict[str, str | None] | None:
    parts = value.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return None
    return {
        "kind": "arn",
        "service": parts[2] or None,
        "region": parts[3] or None,
        "partition": parts[1] or None,
    }


def _parse_url_region_partition(value: str) -> dict[str, str | None] | None:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return None
    host = parsed.hostname or ""
    host_parts = host.split(".")
    partition = _partition_from_host(host)
    region = _region_from_host_parts(host_parts)
    return {
        "kind": "url",
        "service": host_parts[0] if host_parts else None,
        "region": region,
        "partition": partition,
    }


def _region_from_host_parts(parts: list[str]) -> str | None:
    for part in parts:
        if re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", part):
            return part
    return None


def _partition_from_host(host: str) -> str | None:
    if host.endswith(".amazonaws.com.cn"):
        return "aws-cn"
    if host.endswith(".amazonaws.com"):
        return "aws"
    return None


def _region_partition_summary(
    mismatches: list[dict[str, Any]],
    unknown: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "status": "mismatch" if mismatches else "ok",
        "mismatch_count": len(mismatches),
        "unknown_count": len(unknown),
        "first_mismatch": mismatches[0] if mismatches else None,
    }
