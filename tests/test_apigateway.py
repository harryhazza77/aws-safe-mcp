from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.tools.apigateway import (
    analyze_api_gateway_authorizer_failures,
    explain_api_gateway_dependencies,
    get_api_gateway_authorizer_summary,
    get_api_gateway_summary,
    investigate_api_gateway_route,
    list_api_gateways,
)


class FakeRestApiClient:
    def get_rest_apis(self, **_: Any) -> dict[str, Any]:
        return {
            "items": [
                {
                    "id": "rest1",
                    "name": "dev-rest",
                    "createdDate": datetime(2026, 1, 1, tzinfo=UTC),
                    "endpointConfiguration": {"types": ["REGIONAL"]},
                }
            ]
        }

    def get_rest_api(self, **_: Any) -> dict[str, Any]:
        return {
            "id": "rest1",
            "name": "dev-rest",
            "createdDate": datetime(2026, 1, 1, tzinfo=UTC),
            "endpointConfiguration": {"types": ["REGIONAL"]},
        }

    def get_resources(self, **_: Any) -> dict[str, Any]:
        return {
            "items": [
                {
                    "id": "resource1",
                    "path": "/orders",
                    "resourceMethods": {
                        "GET": {
                            "authorizationType": "CUSTOM",
                            "authorizerId": "auth1",
                        },
                        "POST": {"authorizationType": "NONE"},
                    },
                }
            ]
        }

    def get_authorizers(self, **_: Any) -> dict[str, Any]:
        return {
            "items": [
                {
                    "id": "auth1",
                    "name": "orders-auth",
                    "type": "REQUEST",
                    "identitySource": "method.request.header.Authorization",
                    "authorizerUri": (
                        "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/"
                        "arn:aws:lambda:eu-west-2:123456789012:function:auth/invocations"
                    ),
                    "authorizerResultTtlInSeconds": 300,
                }
            ]
        }

    def get_integration(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "type": "AWS_PROXY",
            "httpMethod": "POST",
            "uri": (
                "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/"
                "arn:aws:lambda:eu-west-2:123456789012:function:dev-api/invocations"
            ),
        }


class FakeHttpApiClient:
    def get_apis(self, **_: Any) -> dict[str, Any]:
        return {
            "Items": [
                {
                    "ApiId": "http1",
                    "Name": "dev-http",
                    "ProtocolType": "HTTP",
                    "CreatedDate": datetime(2026, 1, 2, tzinfo=UTC),
                    "ApiEndpoint": "https://example.execute-api.eu-west-2.amazonaws.com",
                }
            ]
        }

    def get_api(self, **_: Any) -> dict[str, Any]:
        return {
            "ApiId": "http1",
            "Name": "dev-http",
            "ProtocolType": "HTTP",
            "CreatedDate": datetime(2026, 1, 2, tzinfo=UTC),
            "ApiEndpoint": "https://example.execute-api.eu-west-2.amazonaws.com",
        }

    def get_routes(self, **_: Any) -> dict[str, Any]:
        return {
            "Items": [
                {
                    "RouteKey": "GET /orders",
                    "Target": "integrations/int1",
                    "AuthorizationType": "CUSTOM",
                    "AuthorizerId": "auth1",
                },
                {"RouteKey": "POST /orders", "Target": "integrations/int1"},
            ]
        }

    def get_authorizers(self, **_: Any) -> dict[str, Any]:
        return {
            "Items": [
                {
                    "AuthorizerId": "auth1",
                    "Name": "orders-auth",
                    "AuthorizerType": "REQUEST",
                    "IdentitySource": ["$request.header.Authorization"],
                    "AuthorizerUri": (
                        "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/"
                        "arn:aws:lambda:eu-west-2:123456789012:function:auth/invocations"
                    ),
                    "AuthorizerResultTtlInSeconds": 300,
                }
            ]
        }

    def get_integration(self, **_: Any) -> dict[str, Any]:
        return {
            "IntegrationId": "int1",
            "IntegrationType": "AWS_PROXY",
            "IntegrationMethod": "POST",
            "IntegrationUri": "arn:aws:lambda:eu-west-2:123456789012:function:dev-http",
        }


class FakeLambdaClient:
    def get_policy(self, FunctionName: str) -> dict[str, Any]:
        return {
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "apigateway.amazonaws.com"},
                            "Action": "lambda:InvokeFunction",
                            "Resource": FunctionName,
                        }
                    ]
                }
            )
        }

    def get_function_configuration(self, FunctionName: str) -> dict[str, Any]:
        return {
            "FunctionName": FunctionName.rsplit(":", 1)[-1],
            "FunctionArn": FunctionName,
            "Runtime": "python3.11",
            "Handler": "index.handler",
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "Role": "arn:aws:iam::123456789012:role/dev-api-role",
            "Timeout": 10,
            "MemorySize": 128,
        }


class FakeLogsClient:
    def filter_log_events(self, **_: Any) -> dict[str, Any]:
        return {
            "events": [
                {
                    "timestamp": 1778918870000,
                    "message": "ERROR failed request 123",
                }
            ]
        }


class FakeRuntime:
    def __init__(self) -> None:
        self.config = AwsSafeConfig(allowed_account_ids=["123456789012"])
        self.region = "eu-west-2"
        self.rest = FakeRestApiClient()
        self.http = FakeHttpApiClient()
        self.lambda_client = FakeLambdaClient()
        self.logs = FakeLogsClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert region == "eu-west-2"
        if service_name == "apigateway":
            return self.rest
        if service_name == "apigatewayv2":
            return self.http
        if service_name == "lambda":
            return self.lambda_client
        if service_name == "logs":
            return self.logs
        raise AssertionError(service_name)


class RuntimeWithClients:
    def __init__(self, rest: Any, http: Any, lambda_client: Any | None = None) -> None:
        self.config = AwsSafeConfig(allowed_account_ids=["123456789012"])
        self.region = "eu-west-2"
        self.rest = rest
        self.http = http
        self.lambda_client = lambda_client or FakeLambdaClient()
        self.logs = FakeLogsClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert region == "eu-west-2"
        if service_name == "apigateway":
            return self.rest
        if service_name == "apigatewayv2":
            return self.http
        if service_name == "lambda":
            return self.lambda_client
        if service_name == "logs":
            return self.logs
        raise AssertionError(service_name)


class EmptyRestApiClient:
    def get_rest_apis(self, **_: Any) -> dict[str, Any]:
        return {"items": []}

    def get_rest_api(self, **_: Any) -> dict[str, Any]:
        error = {"Error": {"Code": "NotFoundException", "Message": "not found"}}
        raise ClientError(error, "GetRestApi")


class EmptyHttpApiClient:
    def get_apis(self, **_: Any) -> dict[str, Any]:
        return {"Items": []}

    def get_api(self, **_: Any) -> dict[str, Any]:
        error = {"Error": {"Code": "NotFoundException", "Message": "not found"}}
        raise ClientError(error, "GetApi")


def test_list_api_gateways_returns_rest_and_v2() -> None:
    result = list_api_gateways(FakeRuntime(), name_prefix="dev")

    assert result["count"] == 2
    assert [item["api_id"] for item in result["apis"]] == ["rest1", "http1"]
    assert result["warnings"] == []


def test_get_api_gateway_summary_returns_rest_summary() -> None:
    result = get_api_gateway_summary(FakeRuntime(), "rest1", api_type="rest")

    assert result["api_type"] == "REST"
    assert result["resource_count"] == 1
    assert result["method_count"] == 2


def test_get_api_gateway_summary_returns_http_summary() -> None:
    result = get_api_gateway_summary(FakeRuntime(), "http1", api_type="http")

    assert result["api_type"] == "HTTP"
    assert result["route_count"] == 2


def test_get_api_gateway_authorizer_summary_returns_http_routes() -> None:
    result = get_api_gateway_authorizer_summary(FakeRuntime(), "http1", api_type="http")

    assert result["summary"] == {
        "authorizer_count": 1,
        "attached_route_count": 1,
        "unauthenticated_route_count": 1,
        "lambda_authorizer_count": 1,
    }
    assert result["authorizers"][0]["identity_sources"] == ["$request.header.Authorization"]
    assert result["authorizers"][0]["lambda_function_arn"].endswith(":function:auth")
    assert result["routes"][0]["authorizer_name"] == "orders-auth"


def test_get_api_gateway_authorizer_summary_returns_rest_routes() -> None:
    result = get_api_gateway_authorizer_summary(FakeRuntime(), "rest1", api_type="rest")

    assert result["summary"]["authorizer_count"] == 1
    assert result["summary"]["attached_route_count"] == 1
    assert result["routes"][0]["route_key"] == "GET /orders"
    assert result["routes"][0]["authorizer_name"] == "orders-auth"


def test_analyze_api_gateway_authorizer_failures_reports_lambda_error_risks() -> None:
    result = analyze_api_gateway_authorizer_failures(
        FakeRuntime(),
        "http1",
        route_key="GET /orders",
        api_type="http",
        max_events=5,
    )

    assert result["summary"] == {
        "status": "auth_failure_risks",
        "route_count": 1,
        "protected_route_count": 1,
        "risk_count": 1,
        "risks": ["recent_authorizer_lambda_errors"],
    }
    route = result["routes"][0]
    assert route["authorizer"]["identity_sources"] == ["$request.header.Authorization"]
    assert route["lambda_permission"]["allows_apigateway_invoke"] is True
    assert route["lambda"]["recent_error_count"] == 1
    assert any("authorizer Lambda errors" in check for check in result["suggested_next_checks"])


def test_explain_api_gateway_dependencies_returns_rest_routes_and_policy() -> None:
    result = explain_api_gateway_dependencies(FakeRuntime(), "rest1", api_type="rest")

    assert result["id"] == "rest1"
    assert result["name"] == "dev-rest"
    assert result["api_type"] == "REST"
    assert result["summary"]["route_count"] == 2
    assert result["summary"]["lambda_target_count"] == 1
    assert result["routes"][0]["route_key"] == "GET /orders"
    assert result["edges"][0]["target_type"] == "lambda"
    assert result["permission_checks"]["checked_count"] == 1
    assert result["permission_checks"]["summary"]["allowed"] == 1
    assert result["graph_summary"]["edge_count"] == len(result["edges"])
    assert result["lambda_resource_policies"][0]["allows_apigateway_invoke"] is True
    assert result["warnings"] == []


def test_explain_api_gateway_dependencies_returns_http_routes_and_policy() -> None:
    result = explain_api_gateway_dependencies(FakeRuntime(), "http1", api_type="http")

    assert result["api_type"] == "HTTP"
    assert result["summary"]["route_count"] == 2
    assert result["routes"][0]["route_key"] == "GET /orders"
    assert result["routes"][0]["lambda_function_arn"].endswith(":function:dev-http")
    assert result["permission_hints"][0]["principal"] == "apigateway.amazonaws.com"


def test_investigate_api_gateway_route_reports_lambda_permission_and_errors() -> None:
    result = investigate_api_gateway_route(
        FakeRuntime(),
        "http1",
        route_key="GET /orders",
        api_type="http",
        max_events=5,
    )

    assert result["route"]["route_key"] == "GET /orders"
    assert result["integration"]["lambda_function_arn"].endswith(":function:dev-http")
    assert result["lambda_permission"]["allows_apigateway_invoke"] is True
    assert result["lambda"]["summary"]["runtime"] == "python3.11"
    assert result["lambda"]["recent_error_count"] == 1
    assert result["diagnostic_summary"] == (
        "Route targets Lambda and recent Lambda error signals were found."
    )
    assert result["callability_summary"] == {
        "status": "likely_callable",
        "blockers": [],
        "recent_lambda_error_count": 1,
    }
    assert result["callability_signals"]["lambda_permission_allows_invoke"] is True
    assert result["callability_signals"]["lambda_active"] is True
    assert any("Lambda errors" in check for check in result["suggested_next_checks"])


def test_investigate_api_gateway_route_reports_missing_invoke_permission() -> None:
    class DenyingPolicyLambdaClient(FakeLambdaClient):
        def get_policy(self, FunctionName: str) -> dict[str, Any]:
            return {
                "Policy": json.dumps(
                    {
                        "Statement": {
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": ["lambda:InvokeFunction"],
                            "Resource": FunctionName,
                        }
                    }
                )
            }

    result = investigate_api_gateway_route(
        RuntimeWithClients(
            rest=EmptyRestApiClient(),
            http=FakeHttpApiClient(),
            lambda_client=DenyingPolicyLambdaClient(),
        ),
        "http1",
        route_key="GET /orders",
        api_type="http",
    )

    assert result["diagnostic_summary"] == (
        "Route targets Lambda but API Gateway invoke permission was not found."
    )


def test_get_api_gateway_summary_follows_v2_route_pagination() -> None:
    class PaginatedRoutesHttpClient(FakeHttpApiClient):
        def get_routes(self, **kwargs: Any) -> dict[str, Any]:
            if "NextToken" not in kwargs:
                return {
                    "NextToken": "page-2",
                    "Items": [{"RouteKey": "GET /orders", "Target": "integrations/int1"}],
                }
            return {"Items": [{"RouteKey": "POST /orders", "Target": "integrations/int1"}]}

    result = get_api_gateway_summary(
        RuntimeWithClients(rest=EmptyRestApiClient(), http=PaginatedRoutesHttpClient()),
        "http1",
        api_type="http",
    )

    assert result["route_count"] == 2
    assert result["is_truncated"] is False


def test_explain_api_gateway_dependencies_follows_rest_resource_pagination() -> None:
    class PaginatedResourcesRestClient(FakeRestApiClient):
        def get_resources(self, **kwargs: Any) -> dict[str, Any]:
            if "position" not in kwargs:
                return {
                    "position": "page-2",
                    "items": [
                        {
                            "id": "resource1",
                            "path": "/orders",
                            "resourceMethods": {"GET": {}},
                        }
                    ],
                }
            return {
                "items": [
                    {
                        "id": "resource2",
                        "path": "/payments",
                        "resourceMethods": {"POST": {}},
                    }
                ]
            }

    result = explain_api_gateway_dependencies(
        RuntimeWithClients(rest=PaginatedResourcesRestClient(), http=EmptyHttpApiClient()),
        "rest1",
        api_type="rest",
    )

    assert [route["route_key"] for route in result["routes"]] == [
        "GET /orders",
        "POST /payments",
    ]
    assert result["summary"]["route_count"] == 2


def test_list_api_gateways_follows_rest_pagination_and_keeps_partial_warning() -> None:
    class PaginatedRestClient:
        def __init__(self) -> None:
            self.requests: list[dict[str, Any]] = []

        def get_rest_apis(self, **kwargs: Any) -> dict[str, Any]:
            self.requests.append(kwargs)
            if "position" not in kwargs:
                return {
                    "position": "next-page",
                    "items": [
                        {
                            "id": "rest1",
                            "name": "dev-rest-1",
                            "createdDate": datetime(2026, 1, 1, tzinfo=UTC),
                        }
                    ],
                }
            error = {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}
            raise ClientError(error, "GetRestApis")

    rest = PaginatedRestClient()
    result = list_api_gateways(
        RuntimeWithClients(rest=rest, http=EmptyHttpApiClient()),
        name_prefix="dev",
    )

    assert [item["api_id"] for item in result["apis"]] == ["rest1"]
    assert rest.requests == [{"limit": 50}, {"limit": 49, "position": "next-page"}]
    assert result["warnings"]
    assert "apigateway.GetRestApis" in result["warnings"][0]


def test_list_api_gateways_follows_v2_pagination() -> None:
    class PaginatedHttpClient:
        def __init__(self) -> None:
            self.requests: list[dict[str, Any]] = []

        def get_apis(self, **kwargs: Any) -> dict[str, Any]:
            self.requests.append(kwargs)
            if "NextToken" not in kwargs:
                return {
                    "NextToken": "page-2",
                    "Items": [
                        {
                            "ApiId": "http1",
                            "Name": "dev-http-1",
                            "ProtocolType": "HTTP",
                        }
                    ],
                }
            return {
                "Items": [
                    {
                        "ApiId": "ws1",
                        "Name": "dev-ws-1",
                        "ProtocolType": "WEBSOCKET",
                    }
                ]
            }

    http = PaginatedHttpClient()
    result = list_api_gateways(
        RuntimeWithClients(rest=EmptyRestApiClient(), http=http),
        name_prefix="dev",
    )

    assert [item["api_id"] for item in result["apis"]] == ["http1", "ws1"]
    assert http.requests == [{"MaxResults": "50"}, {"MaxResults": "49", "NextToken": "page-2"}]


def test_explain_api_gateway_dependencies_handles_non_lambda_rest_integration() -> None:
    class HttpIntegrationRestClient(FakeRestApiClient):
        def get_integration(self, **_: Any) -> dict[str, Any]:
            return {
                "type": "HTTP_PROXY",
                "httpMethod": "ANY",
                "uri": "https://example.internal/orders",
            }

    result = explain_api_gateway_dependencies(
        RuntimeWithClients(rest=HttpIntegrationRestClient(), http=EmptyHttpApiClient()),
        "rest1",
        api_type="rest",
    )

    assert result["summary"]["lambda_target_count"] == 0
    assert result["summary"]["non_lambda_route_count"] == 2
    assert {edge["target_type"] for edge in result["edges"]} == {"http"}
    assert result["permission_checks"]["checked_count"] == 0
    assert (
        result["permission_checks"]["summary"]["headline"]
        == "No Lambda target permissions to check."
    )


def test_explain_api_gateway_dependencies_reports_missing_v2_integration() -> None:
    class MissingIntegrationHttpClient(FakeHttpApiClient):
        def get_routes(self, **_: Any) -> dict[str, Any]:
            return {"Items": [{"RouteKey": "$default", "Target": None}]}

    result = explain_api_gateway_dependencies(
        RuntimeWithClients(rest=EmptyRestApiClient(), http=MissingIntegrationHttpClient()),
        "http1",
        api_type="http",
    )

    assert result["routes"][0]["method"] is None
    assert result["routes"][0]["path"] == "$default"
    assert result["routes"][0]["integration_available"] is False
    assert "Route did not reference an integration id" in result["routes"][0]["warnings"]
    assert result["edges"] == []


def test_explain_api_gateway_dependencies_reports_malformed_lambda_policy() -> None:
    class MalformedPolicyLambdaClient:
        def get_policy(self, **_: Any) -> dict[str, Any]:
            return {"Policy": "not-json"}

    result = explain_api_gateway_dependencies(
        RuntimeWithClients(
            rest=EmptyRestApiClient(),
            http=FakeHttpApiClient(),
            lambda_client=MalformedPolicyLambdaClient(),
        ),
        "http1",
        api_type="http",
    )

    assert result["permission_checks"]["summary"] == {
        "allowed": 0,
        "denied": 0,
        "unknown": 1,
        "explicit_denies": 0,
        "headline": "0 allowed, 0 not found, 1 unknown Lambda permission check(s).",
    }
    assert result["lambda_resource_policies"][0]["available"] is False
    assert result["warnings"] == ["Lambda resource policy was not valid JSON"]


def test_explain_api_gateway_dependencies_reports_policy_without_apigateway_allow() -> None:
    class DenyingPolicyLambdaClient:
        def get_policy(self, FunctionName: str) -> dict[str, Any]:
            return {
                "Policy": json.dumps(
                    {
                        "Statement": {
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": ["lambda:InvokeFunction"],
                            "Resource": FunctionName,
                        }
                    }
                )
            }

    result = explain_api_gateway_dependencies(
        RuntimeWithClients(
            rest=EmptyRestApiClient(),
            http=FakeHttpApiClient(),
            lambda_client=DenyingPolicyLambdaClient(),
        ),
        "http1",
        api_type="http",
    )

    assert result["permission_checks"]["summary"] == {
        "allowed": 0,
        "denied": 1,
        "unknown": 0,
        "explicit_denies": 0,
        "headline": "0 allowed, 1 not found, 0 unknown Lambda permission check(s).",
    }
    assert result["permission_checks"]["checks"][0]["decision"] == "not_found"


def test_explain_api_gateway_dependencies_rejects_mismatched_source_arn_allow() -> None:
    class MismatchedSourcePolicyLambdaClient:
        def get_policy(self, FunctionName: str) -> dict[str, Any]:
            return {
                "Policy": json.dumps(
                    {
                        "Statement": {
                            "Effect": "Allow",
                            "Principal": {"Service": "apigateway.amazonaws.com"},
                            "Action": ["lambda:InvokeFunction"],
                            "Resource": FunctionName,
                            "Condition": {
                                "ArnLike": {
                                    "AWS:SourceArn": (
                                        "arn:aws:execute-api:eu-west-2:123456789012:other-api/*/*/*"
                                    )
                                }
                            },
                        }
                    }
                )
            }

    result = explain_api_gateway_dependencies(
        RuntimeWithClients(
            rest=EmptyRestApiClient(),
            http=FakeHttpApiClient(),
            lambda_client=MismatchedSourcePolicyLambdaClient(),
        ),
        "http1",
        api_type="http",
    )

    assert result["permission_checks"]["summary"]["denied"] == 1
    assert result["permission_checks"]["checks"][0]["decision"] == "not_found"


def test_explain_api_gateway_dependencies_reports_matching_explicit_deny() -> None:
    class ExplicitDenyPolicyLambdaClient:
        def get_policy(self, FunctionName: str) -> dict[str, Any]:
            return {
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "apigateway.amazonaws.com"},
                                "Action": ["lambda:InvokeFunction"],
                                "Resource": FunctionName,
                            },
                            {
                                "Effect": "Deny",
                                "Principal": {"Service": "apigateway.amazonaws.com"},
                                "Action": ["lambda:InvokeFunction"],
                                "Resource": FunctionName,
                                "Condition": {
                                    "ArnLike": {
                                        "AWS:SourceArn": (
                                            "arn:aws:execute-api:eu-west-2:123456789012:http1/*/*/*"
                                        )
                                    }
                                },
                            },
                        ]
                    }
                )
            }

    result = explain_api_gateway_dependencies(
        RuntimeWithClients(
            rest=EmptyRestApiClient(),
            http=FakeHttpApiClient(),
            lambda_client=ExplicitDenyPolicyLambdaClient(),
        ),
        "http1",
        api_type="http",
    )

    assert result["permission_checks"]["summary"]["allowed"] == 0
    assert result["permission_checks"]["summary"]["explicit_denies"] == 1
    assert result["permission_checks"]["checks"][0]["decision"] == "explicitDeny"
