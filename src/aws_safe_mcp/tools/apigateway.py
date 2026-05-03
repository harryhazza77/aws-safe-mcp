from __future__ import annotations

import json
import re
from fnmatch import fnmatchcase
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.common import clamp_limit, isoformat, resolve_region
from aws_safe_mcp.tools.graph import dependency_graph_summary


def list_api_gateways(
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
    warnings: list[str] = []
    rest_apis = _list_rest_apis(runtime, resolved_region, name_prefix, limit, warnings)
    http_apis = _list_v2_apis(runtime, resolved_region, name_prefix, limit, warnings)
    apis = (rest_apis + http_apis)[:limit]

    return {
        "region": resolved_region,
        "name_prefix": name_prefix,
        "max_results": limit,
        "count": len(apis),
        "apis": apis,
        "warnings": warnings,
    }


def get_api_gateway_summary(
    runtime: AwsRuntime,
    api_id: str,
    api_type: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    if not api_id.strip():
        raise ToolInputError("api_id is required")
    normalized_type = (api_type or "auto").lower()
    if normalized_type in {"auto", "rest"}:
        summary = _rest_api_summary(runtime, resolved_region, api_id)
        if summary is not None:
            return summary
        if normalized_type == "rest":
            error = {"Error": {"Code": "NotFound", "Message": "REST API not found"}}
            raise normalize_aws_error(ClientError(error, "GetRestApi"), "apigateway.GetRestApi")
    if normalized_type in {"auto", "http", "websocket"}:
        summary = _v2_api_summary(runtime, resolved_region, api_id)
        if summary is not None:
            return summary
    raise normalize_aws_error(
        ClientError({"Error": {"Code": "NotFound", "Message": "API Gateway not found"}}, "GetApi"),
        "apigatewayv2.GetApi",
    )


def explain_api_gateway_dependencies(
    runtime: AwsRuntime,
    api_id: str,
    api_type: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    """Explain API Gateway routes, integrations, and Lambda invoke permissions."""

    resolved_region = resolve_region(runtime, region)
    if not api_id.strip():
        raise ToolInputError("api_id is required")
    normalized_type = (api_type or "auto").lower()
    warnings: list[str] = []

    if normalized_type in {"auto", "rest"}:
        result = _rest_api_dependencies(runtime, resolved_region, api_id, warnings)
        if result is not None:
            return result
        if normalized_type == "rest":
            error = {"Error": {"Code": "NotFound", "Message": "REST API not found"}}
            raise normalize_aws_error(ClientError(error, "GetRestApi"), "apigateway.GetRestApi")
    if normalized_type in {"auto", "http", "websocket"}:
        result = _v2_api_dependencies(runtime, resolved_region, api_id, warnings)
        if result is not None:
            return result
    raise normalize_aws_error(
        ClientError({"Error": {"Code": "NotFound", "Message": "API Gateway not found"}}, "GetApi"),
        "apigatewayv2.GetApi",
    )


def _list_rest_apis(
    runtime: AwsRuntime,
    region: str,
    name_prefix: str | None,
    limit: int,
    warnings: list[str],
) -> list[dict[str, Any]]:
    client = runtime.client("apigateway", region=region)
    apis: list[dict[str, Any]] = []
    position: str | None = None
    try:
        while len(apis) < limit:
            request: dict[str, Any] = {"limit": min(limit - len(apis), 500)}
            if position:
                request["position"] = position
            response = client.get_rest_apis(**request)
            for item in response.get("items", []):
                name = str(item.get("name", ""))
                if name_prefix and not name.startswith(name_prefix):
                    continue
                apis.append(_rest_api_list_item(item))
                if len(apis) >= limit:
                    break
            position = response.get("position")
            if not position:
                break
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "apigateway.GetRestApis")))
    return apis


def _list_v2_apis(
    runtime: AwsRuntime,
    region: str,
    name_prefix: str | None,
    limit: int,
    warnings: list[str],
) -> list[dict[str, Any]]:
    client = runtime.client("apigatewayv2", region=region)
    apis: list[dict[str, Any]] = []
    next_token: str | None = None
    try:
        while len(apis) < limit:
            request: dict[str, Any] = {"MaxResults": str(min(limit - len(apis), 100))}
            if next_token:
                request["NextToken"] = next_token
            response = client.get_apis(**request)
            for item in response.get("Items", []):
                name = str(item.get("Name", ""))
                if name_prefix and not name.startswith(name_prefix):
                    continue
                apis.append(_v2_api_list_item(item))
                if len(apis) >= limit:
                    break
            next_token = response.get("NextToken")
            if not next_token:
                break
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "apigatewayv2.GetApis")))
    return apis


def _rest_api_list_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "api_id": item.get("id"),
        "name": item.get("name"),
        "api_type": "REST",
        "created_date": isoformat(item.get("createdDate")),
        "description": item.get("description"),
        "endpoint_types": item.get("endpointConfiguration", {}).get("types", []),
    }


def _v2_api_list_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "api_id": item.get("ApiId"),
        "name": item.get("Name"),
        "api_type": item.get("ProtocolType"),
        "created_date": isoformat(item.get("CreatedDate")),
        "description": item.get("Description"),
        "endpoint": item.get("ApiEndpoint"),
    }


def _collect_rest_resources(
    client: Any,
    api_id: str,
    limit: int,
) -> tuple[dict[str, Any], bool]:
    items: list[dict[str, Any]] = []
    position: str | None = None
    next_position: str | None = None
    while len(items) < limit:
        request: dict[str, Any] = {"restApiId": api_id, "limit": min(500, limit - len(items))}
        if position:
            request["position"] = position
        response = client.get_resources(**request)
        items.extend(response.get("items", [])[: limit - len(items)])
        next_position = response.get("position")
        if not next_position:
            break
        position = str(next_position)
    return {"items": items}, bool(next_position and len(items) >= limit)


def _collect_v2_routes(
    client: Any,
    api_id: str,
    limit: int,
) -> tuple[dict[str, Any], bool]:
    items: list[dict[str, Any]] = []
    next_token: str | None = None
    while len(items) < limit:
        request: dict[str, Any] = {"ApiId": api_id, "MaxResults": str(min(100, limit - len(items)))}
        if next_token:
            request["NextToken"] = next_token
        response = client.get_routes(**request)
        items.extend(response.get("Items", [])[: limit - len(items)])
        next_token = response.get("NextToken")
        if not next_token:
            break
    return {"Items": items}, bool(next_token and len(items) >= limit)


def _rest_api_summary(runtime: AwsRuntime, region: str, api_id: str) -> dict[str, Any] | None:
    client = runtime.client("apigateway", region=region)
    try:
        api = client.get_rest_api(restApiId=api_id)
        resources, truncated = _collect_rest_resources(
            client,
            api_id,
            limit=runtime.config.max_results,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in {"NotFoundException", "NotFound"}:
            return None
        raise normalize_aws_error(exc, "apigateway.GetRestApi") from exc
    except BotoCoreError as exc:
        raise normalize_aws_error(exc, "apigateway.GetRestApi") from exc

    methods = sum(len(item.get("resourceMethods", {})) for item in resources.get("items", []))
    return {
        "api_id": api_id,
        "region": region,
        "name": api.get("name"),
        "api_type": "REST",
        "created_date": isoformat(api.get("createdDate")),
        "description": api.get("description"),
        "endpoint_types": api.get("endpointConfiguration", {}).get("types", []),
        "resource_count": len(resources.get("items", [])),
        "method_count": methods,
        "is_truncated": truncated,
    }


def _rest_api_dependencies(
    runtime: AwsRuntime,
    region: str,
    api_id: str,
    warnings: list[str],
) -> dict[str, Any] | None:
    client = runtime.client("apigateway", region=region)
    try:
        api = client.get_rest_api(restApiId=api_id)
        resources, truncated = _collect_rest_resources(
            client,
            api_id,
            limit=runtime.config.max_results,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in {"NotFoundException", "NotFound"}:
            return None
        raise normalize_aws_error(exc, "apigateway.GetRestApi") from exc
    except BotoCoreError as exc:
        raise normalize_aws_error(exc, "apigateway.GetRestApi") from exc

    routes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    if truncated:
        warnings.append("REST API resources were truncated at the configured max_results limit")
    for resource in resources.get("items", []):
        path = str(resource.get("path") or "/")
        for method in resource.get("resourceMethods", {}):
            integration = _safe_rest_integration(
                client,
                api_id,
                resource.get("id"),
                method,
                warnings,
            )
            route = _api_route_summary(
                route_key=f"{method} {path}",
                method=str(method),
                path=path,
                integration=integration,
            )
            routes.append(route)
            edge = _api_route_edge(api_id, route)
            if edge:
                edges.append(edge)

    return _api_dependency_result(
        runtime=runtime,
        api_id=api_id,
        region=region,
        api_name=api.get("name"),
        api_type="REST",
        endpoint=api.get("endpointConfiguration", {}).get("types", []),
        routes=routes,
        edges=edges,
        warnings=warnings,
    )


def _v2_api_summary(runtime: AwsRuntime, region: str, api_id: str) -> dict[str, Any] | None:
    client = runtime.client("apigatewayv2", region=region)
    try:
        api = client.get_api(ApiId=api_id)
        routes, truncated = _collect_v2_routes(client, api_id, limit=runtime.config.max_results)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in {"NotFoundException", "NotFound"}:
            return None
        raise normalize_aws_error(exc, "apigatewayv2.GetApi") from exc
    except BotoCoreError as exc:
        raise normalize_aws_error(exc, "apigatewayv2.GetApi") from exc

    return {
        "api_id": api_id,
        "region": region,
        "name": api.get("Name"),
        "api_type": api.get("ProtocolType"),
        "created_date": isoformat(api.get("CreatedDate")),
        "description": api.get("Description"),
        "endpoint": api.get("ApiEndpoint"),
        "route_count": len(routes.get("Items", [])),
        "is_truncated": truncated,
    }


def _v2_api_dependencies(
    runtime: AwsRuntime,
    region: str,
    api_id: str,
    warnings: list[str],
) -> dict[str, Any] | None:
    client = runtime.client("apigatewayv2", region=region)
    try:
        api = client.get_api(ApiId=api_id)
        routes_response, truncated = _collect_v2_routes(
            client,
            api_id,
            limit=runtime.config.max_results,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in {"NotFoundException", "NotFound"}:
            return None
        raise normalize_aws_error(exc, "apigatewayv2.GetApi") from exc
    except BotoCoreError as exc:
        raise normalize_aws_error(exc, "apigatewayv2.GetApi") from exc

    routes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    if truncated:
        warnings.append("API Gateway v2 routes were truncated at the configured max_results limit")
    for item in routes_response.get("Items", []):
        route_key = str(item.get("RouteKey") or "")
        integration = _safe_v2_integration(client, api_id, item.get("Target"), warnings)
        method, path = _route_key_parts(route_key)
        route = _api_route_summary(
            route_key=route_key,
            method=method,
            path=path,
            integration=integration,
        )
        routes.append(route)
        edge = _api_route_edge(api_id, route)
        if edge:
            edges.append(edge)

    return _api_dependency_result(
        runtime=runtime,
        api_id=api_id,
        region=region,
        api_name=api.get("Name"),
        api_type=api.get("ProtocolType"),
        endpoint=api.get("ApiEndpoint"),
        routes=routes,
        edges=edges,
        warnings=warnings,
    )


def _safe_rest_integration(
    client: Any,
    api_id: str,
    resource_id: Any,
    method: str,
    warnings: list[str],
) -> dict[str, Any]:
    if not resource_id:
        return {"available": False, "warnings": ["API Gateway resource had no resource id"]}
    try:
        integration = client.get_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod=method,
        )
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "apigateway.GetIntegration")))
        return {"available": False, "warnings": [warnings[-1]]}
    return {
        "available": True,
        "type": integration.get("type"),
        "integration_http_method": integration.get("httpMethod"),
        "uri": integration.get("uri"),
        "lambda_function_arn": _lambda_arn_from_integration_uri(integration.get("uri")),
    }


def _safe_v2_integration(
    client: Any,
    api_id: str,
    target: Any,
    warnings: list[str],
) -> dict[str, Any]:
    integration_id = _v2_integration_id(target)
    if not integration_id:
        return {"available": False, "warnings": ["Route did not reference an integration id"]}
    try:
        integration = client.get_integration(ApiId=api_id, IntegrationId=integration_id)
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "apigatewayv2.GetIntegration")))
        return {"available": False, "warnings": [warnings[-1]]}
    uri = integration.get("IntegrationUri")
    return {
        "available": True,
        "integration_id": integration_id,
        "type": integration.get("IntegrationType"),
        "integration_method": integration.get("IntegrationMethod"),
        "uri": uri,
        "lambda_function_arn": _lambda_arn_from_integration_uri(uri),
    }


def _api_route_summary(
    *,
    route_key: str,
    method: str | None,
    path: str | None,
    integration: dict[str, Any],
) -> dict[str, Any]:
    return {
        "route_key": route_key,
        "method": method,
        "path": path,
        "integration_type": integration.get("type"),
        "integration_uri": integration.get("uri"),
        "lambda_function_arn": integration.get("lambda_function_arn"),
        "integration_available": integration.get("available"),
        "warnings": integration.get("warnings", []),
    }


def _api_route_edge(api_id: str, route: dict[str, Any]) -> dict[str, Any] | None:
    target = route.get("lambda_function_arn") or route.get("integration_uri")
    if not target:
        return None
    target_type = "lambda" if route.get("lambda_function_arn") else "http"
    return {
        "from": f"api:{api_id}:{route.get('route_key')}",
        "to": target,
        "relationship": "routes_to",
        "route_key": route.get("route_key"),
        "method": route.get("method"),
        "path": route.get("path"),
        "target_type": target_type,
    }


def _api_dependency_result(
    *,
    runtime: AwsRuntime,
    api_id: str,
    region: str,
    api_name: Any,
    api_type: Any,
    endpoint: Any,
    routes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any]:
    """Assemble the shared dependency graph result for REST and v2 APIs."""

    lambda_targets = sorted(
        {str(route["lambda_function_arn"]) for route in routes if route.get("lambda_function_arn")}
    )
    lambda_permissions = [
        _lambda_resource_policy_summary(runtime, region, api_id, arn) for arn in lambda_targets
    ]
    permission_hints = [
        {
            "principal": "apigateway.amazonaws.com",
            "target": arn,
            "action": "lambda:InvokeFunction",
            "reason": (
                "API Gateway Lambda integrations require Lambda resource-policy invoke permission."
            ),
        }
        for arn in lambda_targets
    ]
    permission_checks = _api_permission_checks(lambda_permissions)
    all_warnings = [
        *warnings,
        *[warning for item in lambda_permissions for warning in item["warnings"]],
    ]
    nodes = {
        "api": {
            "api_id": api_id,
            "name": api_name,
            "type": api_type,
        },
        "routes": routes,
        "lambda_targets": lambda_targets,
    }
    return {
        "api_id": api_id,
        "id": api_id,
        "region": region,
        "name": api_name,
        "api_type": api_type,
        "endpoint": endpoint,
        "resource_type": "api_gateway",
        "routes": routes,
        "summary": {
            "route_count": len(routes),
            "lambda_target_count": len(lambda_targets),
            "non_lambda_route_count": sum(
                1 for edge in edges if edge.get("target_type") != "lambda"
            ),
        },
        "graph_summary": dependency_graph_summary(
            nodes=nodes,
            edges=edges,
            permission_checks=permission_checks,
            warnings=all_warnings,
        ),
        "nodes": nodes,
        "edges": edges,
        "permission_hints": permission_hints,
        "permission_checks": permission_checks,
        "lambda_resource_policies": lambda_permissions,
        "warnings": all_warnings,
    }


def _lambda_resource_policy_summary(
    runtime: AwsRuntime,
    region: str,
    api_id: str,
    function_arn: str,
) -> dict[str, Any]:
    """Summarize whether a Lambda resource policy allows API Gateway invoke.

    The raw policy document is parsed only to produce bounded decision metadata;
    it is not returned to the MCP client.
    """

    client = runtime.client("lambda", region=region)
    try:
        response = client.get_policy(FunctionName=function_arn)
    except (BotoCoreError, ClientError) as exc:
        warning = str(normalize_aws_error(exc, "lambda.GetPolicy"))
        return {
            "function_arn": function_arn,
            "available": False,
            "allows_apigateway_invoke": None,
            "statement_count": 0,
            "warnings": [warning],
        }

    policy_text = str(response.get("Policy") or "{}")
    try:
        policy = json.loads(policy_text)
    except json.JSONDecodeError:
        return {
            "function_arn": function_arn,
            "available": False,
            "allows_apigateway_invoke": None,
            "statement_count": 0,
            "warnings": ["Lambda resource policy was not valid JSON"],
        }
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        statements = []
    source = _api_gateway_source_context(region, api_id, function_arn)
    allowed = any(_statement_allows_apigateway(statement, source) for statement in statements)
    explicit_deny = any(_statement_denies_apigateway(statement, source) for statement in statements)
    return {
        "function_arn": function_arn,
        "available": True,
        "allows_apigateway_invoke": allowed and not explicit_deny,
        "explicit_deny": explicit_deny,
        "statement_count": len(statements),
        "warnings": [],
    }


def _api_permission_checks(lambda_permissions: list[dict[str, Any]]) -> dict[str, Any]:
    checks = [
        {
            "principal": "apigateway.amazonaws.com",
            "action": "lambda:InvokeFunction",
            "resource_arn": item.get("function_arn"),
            "allowed": item.get("allows_apigateway_invoke"),
            "explicit_deny": item.get("explicit_deny"),
            "decision": _api_permission_decision(item),
            "warnings": item.get("warnings", []),
        }
        for item in lambda_permissions
    ]
    return {
        "enabled": True,
        "checked_count": len(checks),
        "checks": checks,
        "summary": _api_permission_summary(checks),
    }


def _api_permission_decision(item: dict[str, Any]) -> str:
    if item.get("explicit_deny") is True:
        return "explicitDeny"
    if item.get("allows_apigateway_invoke") is True:
        return "allowed"
    if item.get("allows_apigateway_invoke") is False:
        return "not_found"
    return "unknown"


def _api_permission_summary(checks: list[dict[str, Any]]) -> dict[str, Any]:
    allowed = sum(1 for check in checks if check.get("allowed") is True)
    denied = sum(1 for check in checks if check.get("allowed") is False)
    unknown = sum(1 for check in checks if check.get("allowed") is None)
    explicit_denies = sum(1 for check in checks if check.get("explicit_deny") is True)
    headline = (
        "No Lambda target permissions to check."
        if not checks
        else f"{allowed} allowed, {denied} not found, {unknown} unknown Lambda permission check(s)."
    )
    return {
        "allowed": allowed,
        "denied": denied,
        "unknown": unknown,
        "explicit_denies": explicit_denies,
        "headline": headline,
    }


def _statement_allows_apigateway(statement: Any, source: dict[str, str | None]) -> bool:
    if not isinstance(statement, dict):
        return False
    principal = statement.get("Principal")
    action = statement.get("Action")
    effect = statement.get("Effect")
    return (
        effect == "Allow"
        and _contains_value(principal, "apigateway.amazonaws.com")
        and _contains_value(action, "lambda:InvokeFunction")
        and _statement_conditions_match(statement.get("Condition"), source)
    )


def _statement_denies_apigateway(statement: Any, source: dict[str, str | None]) -> bool:
    if not isinstance(statement, dict):
        return False
    principal = statement.get("Principal")
    action = statement.get("Action")
    effect = statement.get("Effect")
    return (
        effect == "Deny"
        and _contains_value(principal, "apigateway.amazonaws.com")
        and _contains_value(action, "lambda:InvokeFunction")
        and _statement_conditions_match(statement.get("Condition"), source)
    )


def _contains_value(value: Any, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected
    if isinstance(value, list):
        return expected in value
    if isinstance(value, dict):
        return any(_contains_value(item, expected) for item in value.values())
    return False


def _statement_conditions_match(condition: Any, source: dict[str, str | None]) -> bool:
    if not condition:
        return True
    if not isinstance(condition, dict):
        return False

    source_arn = source.get("source_arn")
    source_account = source.get("source_account")
    saw_supported_condition = False

    for operator, values in condition.items():
        if not isinstance(values, dict):
            continue
        for key, expected in values.items():
            normalized_key = str(key).lower()
            if normalized_key.endswith("sourcearn"):
                saw_supported_condition = True
                if not source_arn or not _condition_value_matches_arn(expected, source_arn):
                    return False
            elif normalized_key.endswith("sourceaccount"):
                saw_supported_condition = True
                if not source_account or not _condition_value_contains(expected, source_account):
                    return False
            elif str(operator).lower().endswith("ifexists"):
                continue
            else:
                return False

    return saw_supported_condition


def _condition_value_matches_arn(expected: Any, source_arn: str) -> bool:
    if isinstance(expected, str):
        source_prefix = source_arn.split("*", maxsplit=1)[0]
        return expected.startswith(source_prefix) or fnmatchcase(source_arn, expected)
    if isinstance(expected, list):
        return any(_condition_value_matches_arn(item, source_arn) for item in expected)
    return False


def _condition_value_contains(expected: Any, value: str) -> bool:
    if isinstance(expected, str):
        return expected == value
    if isinstance(expected, list):
        return value in expected
    return False


def _api_gateway_source_context(
    region: str,
    api_id: str,
    function_arn: str,
) -> dict[str, str | None]:
    parts = function_arn.split(":")
    partition = parts[1] if len(parts) > 1 else "aws"
    account = parts[4] if len(parts) > 4 else None
    return {
        "source_arn": f"arn:{partition}:execute-api:{region}:{account or '*'}:{api_id}/*/*/*",
        "source_account": account,
    }


def _lambda_arn_from_integration_uri(uri: Any) -> str | None:
    if not uri:
        return None
    match = re.search(
        r"arn:aws[a-zA-Z-]*:lambda:[^:/]+:\d{12}:function:[A-Za-z0-9-_.$:/]+",
        str(uri),
    )
    if not match:
        return None
    value = match.group(0)
    suffix = "/invocations"
    return value.removesuffix(suffix)


def _v2_integration_id(target: Any) -> str | None:
    if not target:
        return None
    value = str(target)
    if value.startswith("integrations/"):
        return value.split("/", maxsplit=1)[1]
    return value


def _route_key_parts(route_key: str) -> tuple[str | None, str | None]:
    if " " not in route_key:
        return None, route_key or None
    method, path = route_key.split(" ", maxsplit=1)
    return method, path
