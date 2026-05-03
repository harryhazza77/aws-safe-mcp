from __future__ import annotations

from typing import Any

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError
from aws_safe_mcp.tools.apigateway import list_api_gateways
from aws_safe_mcp.tools.cloudwatch import list_cloudwatch_log_groups
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
