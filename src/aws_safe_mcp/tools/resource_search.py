from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.apigateway import list_api_gateways
from aws_safe_mcp.tools.cloudwatch import list_cloudwatch_log_groups
from aws_safe_mcp.tools.common import clamp_limit, resolve_region
from aws_safe_mcp.tools.dynamodb import list_dynamodb_tables
from aws_safe_mcp.tools.eventbridge import list_eventbridge_rules
from aws_safe_mcp.tools.lambda_tools import list_lambda_functions
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


def _require_tag_key(tag_key: str) -> str:
    normalized = tag_key.strip()
    if not normalized:
        raise ToolInputError("tag_key is required")
    return normalized


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
