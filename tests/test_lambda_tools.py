from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.lambda_tools import (
    check_lambda_permission_path,
    explain_lambda_dependencies,
    explain_lambda_network_access,
    get_lambda_recent_errors,
    get_lambda_summary,
    investigate_lambda_failure,
    list_lambda_functions,
)


class FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages

    def paginate(self, **_: Any) -> list[dict[str, Any]]:
        return self.pages


class FakeLambdaClient:
    def __init__(self) -> None:
        self.pages = [
            {
                "Functions": [
                    {
                        "FunctionName": "dev-api",
                        "Runtime": "python3.12",
                        "LastModified": "2026-01-01T00:00:00.000+0000",
                        "MemorySize": 256,
                        "Timeout": 30,
                        "Role": "arn:aws:iam::123456789012:role/dev-lambda",
                        "Description": "API handler",
                    },
                    {
                        "FunctionName": "prod-api",
                        "Runtime": "python3.12",
                        "LastModified": "2026-01-01T00:00:00.000+0000",
                        "MemorySize": 512,
                        "Timeout": 20,
                        "Role": "arn:aws:iam::123456789012:role/prod-lambda",
                    },
                ]
            },
            {
                "Functions": [
                    {
                        "FunctionName": "dev-worker",
                        "Runtime": "nodejs22.x",
                        "LastModified": "2026-01-02T00:00:00.000+0000",
                        "MemorySize": 1024,
                        "Timeout": 120,
                        "Role": "arn:aws:iam::123456789012:role/dev-worker",
                    }
                ]
            },
        ]

    def get_paginator(self, operation_name: str) -> FakePaginator:
        assert operation_name == "list_functions"
        return FakePaginator(self.pages)

    def get_function_configuration(self, FunctionName: str) -> dict[str, Any]:
        assert FunctionName == "dev-api"
        return {
            "FunctionName": "dev-api",
            "FunctionArn": "arn:aws:lambda:eu-west-2:123456789012:function:dev-api",
            "Runtime": "python3.12",
            "Handler": "app.handler",
            "LastModified": "2026-01-01T00:00:00.000+0000",
            "MemorySize": 256,
            "Timeout": 30,
            "Role": "arn:aws:iam::123456789012:role/dev-lambda",
            "Description": "API handler",
            "Environment": {
                "Variables": {
                    "PUBLIC_NAME": "example",
                    "SECRET_TOKEN": "must-not-leak",
                }
            },
            "VpcConfig": {
                "VpcId": "vpc-123",
                "SubnetIds": ["subnet-1", "subnet-2"],
                "SecurityGroupIds": ["sg-1"],
            },
            "DeadLetterConfig": {"TargetArn": "arn:aws:sqs:eu-west-2:123456789012:dev-dlq"},
            "State": "Active",
            "LastUpdateStatus": "Successful",
        }

    def list_aliases(self, **_: Any) -> dict[str, Any]:
        return {"Aliases": [{"Name": "live", "FunctionVersion": "3"}]}

    def list_event_source_mappings(self, **_: Any) -> dict[str, Any]:
        return {
            "EventSourceMappings": [
                {
                    "UUID": "mapping-1",
                    "State": "Enabled",
                    "EventSourceArn": "arn:aws:sqs:eu-west-2:123456789012:queue",
                    "BatchSize": 10,
                }
            ]
        }


class NonVpcLambdaClient(FakeLambdaClient):
    def get_function_configuration(self, FunctionName: str) -> dict[str, Any]:
        response = super().get_function_configuration(FunctionName)
        response["VpcConfig"] = {}
        return response


class FakeCloudWatchClient:
    def get_metric_data(
        self,
        MetricDataQueries: list[dict[str, Any]],
        **_: Any,
    ) -> dict[str, Any]:
        assert [query["Id"] for query in MetricDataQueries] == [
            "errors",
            "throttles",
            "invocations",
            "duration",
        ]
        timestamp = datetime(2026, 1, 1, tzinfo=UTC)
        return {
            "MetricDataResults": [
                {
                    "Id": "errors",
                    "Values": [2.0],
                    "Timestamps": [timestamp],
                    "StatusCode": "Complete",
                },
                {"Id": "throttles", "Values": [], "Timestamps": [], "StatusCode": "Complete"},
                {
                    "Id": "invocations",
                    "Values": [10.0],
                    "Timestamps": [timestamp],
                    "StatusCode": "Complete",
                },
                {
                    "Id": "duration",
                    "Values": [1234.0],
                    "Timestamps": [timestamp],
                    "StatusCode": "Complete",
                },
            ]
        }


class FakeLogsClient:
    def __init__(self) -> None:
        self.last_request: dict[str, Any] | None = None

    def filter_log_events(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "events": [
                {
                    "timestamp": 1_767_225_600_000,
                    "logStreamName": "2026/01/01/[$LATEST]abc",
                    "message": "ERROR request 123 failed for user 456\nTraceback line",
                },
                {
                    "timestamp": 1_767_225_660_000,
                    "logStreamName": "2026/01/01/[$LATEST]abc",
                    "message": "ERROR request 789 failed for user 111",
                },
                {
                    "timestamp": 1_767_225_720_000,
                    "logStreamName": "2026/01/01/[$LATEST]def",
                    "message": "AccessDeniedException: not authorized to perform s3:GetObject "
                    "secret=must-not-leak " + ("x" * 250),
                },
            ]
        }


class FakeIamClient:
    def __init__(self) -> None:
        self.simulation_decision = "allowed"
        self.simulation_requests: list[dict[str, Any]] = []

    def get_role(self, RoleName: str) -> dict[str, Any]:
        assert RoleName == "dev-lambda"
        return {
            "Role": {
                "RoleName": RoleName,
                "Arn": "arn:aws:iam::123456789012:role/dev-lambda",
                "Path": "/",
                "CreateDate": datetime(2026, 1, 1, tzinfo=UTC),
            }
        }

    def get_paginator(self, operation_name: str) -> FakePaginator:
        if operation_name == "list_attached_role_policies":
            return FakePaginator(
                [
                    {
                        "AttachedPolicies": [
                            {
                                "PolicyName": "AWSLambdaBasicExecutionRole",
                                "PolicyArn": (
                                    "arn:aws:iam::aws:policy/service-role/"
                                    "AWSLambdaBasicExecutionRole"
                                ),
                            }
                        ]
                    }
                ]
            )
        if operation_name == "list_role_policies":
            return FakePaginator([{"PolicyNames": ["InlineDynamoAccess", "dev-api-s3"]}])
        raise AssertionError(f"Unexpected paginator {operation_name}")

    def simulate_principal_policy(
        self,
        PolicySourceArn: str,
        ActionNames: list[str],
        ResourceArns: list[str],
    ) -> dict[str, Any]:
        assert PolicySourceArn == "arn:aws:iam::123456789012:role/dev-lambda"
        self.simulation_requests.append(
            {
                "PolicySourceArn": PolicySourceArn,
                "ActionNames": ActionNames,
                "ResourceArns": ResourceArns,
            }
        )
        return {
            "EvaluationResults": [
                {
                    "EvalDecision": self.simulation_decision,
                    "MatchedStatements": [
                        {
                            "SourcePolicyId": "InlineDynamoAccess",
                            "SourcePolicyType": "IAM Policy",
                            "StartPosition": {"Line": 1, "Column": 1},
                            "EndPosition": {"Line": 1, "Column": 80},
                        }
                    ],
                    "MissingContextValues": [],
                }
            ]
        }


class FakeEc2Client:
    def __init__(
        self,
        *,
        subnets: list[dict[str, Any]] | None = None,
        security_groups: list[dict[str, Any]] | None = None,
        route_tables: list[dict[str, Any]] | None = None,
        network_acls: list[dict[str, Any]] | None = None,
        endpoints: list[dict[str, Any]] | None = None,
    ) -> None:
        self.subnets = subnets or [{"SubnetId": "subnet-1"}, {"SubnetId": "subnet-2"}]
        self.security_groups = security_groups or [
            {
                "GroupId": "sg-1",
                "GroupName": "lambda-egress",
                "IpPermissionsEgress": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
        self.route_tables = route_tables or [
            {
                "RouteTableId": "rtb-private",
                "Associations": [{"SubnetId": "subnet-1"}, {"SubnetId": "subnet-2"}],
                "Routes": [
                    {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"},
                    {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"},
                ],
            }
        ]
        self.network_acls = network_acls or []
        self.endpoints = endpoints or []

    def describe_subnets(self, **_: Any) -> dict[str, Any]:
        return {"Subnets": self.subnets}

    def describe_security_groups(self, **_: Any) -> dict[str, Any]:
        return {"SecurityGroups": self.security_groups}

    def describe_route_tables(self, **_: Any) -> dict[str, Any]:
        return {"RouteTables": self.route_tables}

    def describe_network_acls(self, **_: Any) -> dict[str, Any]:
        return {"NetworkAcls": self.network_acls}

    def describe_vpc_endpoints(self, **_: Any) -> dict[str, Any]:
        return {"VpcEndpoints": self.endpoints}


class FakeRuntime:
    def __init__(self) -> None:
        self.config = AwsSafeConfig(
            allowed_account_ids=["123456789012"],
            redaction={"max_string_length": 120},
            max_results=100,
            max_since_minutes=120,
        )
        self.region = "eu-west-2"
        self.lambda_client = FakeLambdaClient()
        self.cloudwatch_client = FakeCloudWatchClient()
        self.logs_client = FakeLogsClient()
        self.iam_client = FakeIamClient()
        self.ec2_client = FakeEc2Client()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert region == "eu-west-2"
        if service_name == "lambda":
            return self.lambda_client
        if service_name == "cloudwatch":
            return self.cloudwatch_client
        if service_name == "logs":
            return self.logs_client
        if service_name == "iam":
            return self.iam_client
        if service_name == "ec2":
            return self.ec2_client
        raise AssertionError(f"Unexpected service {service_name}")


def test_list_lambda_functions_returns_visible_names() -> None:
    result = list_lambda_functions(FakeRuntime())

    assert result["count"] == 3
    assert [item["function_name"] for item in result["functions"]] == [
        "dev-api",
        "prod-api",
        "dev-worker",
    ]


def test_list_lambda_functions_applies_prefix_and_limit() -> None:
    result = list_lambda_functions(FakeRuntime(), name_prefix="dev-w", max_results=1)

    assert result["count"] == 1
    assert result["functions"][0]["function_name"] == "dev-worker"


def test_list_lambda_functions_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.lambda_client = FailingListLambdaClient()

    with pytest.raises(AwsToolError, match="AWS lambda.ListFunctions AccessDenied"):
        list_lambda_functions(runtime)


def test_get_lambda_summary_never_returns_environment_values() -> None:
    result = get_lambda_summary(FakeRuntime(), "dev-api")

    assert result["environment_variable_keys"] == ["PUBLIC_NAME", "SECRET_TOKEN"]
    assert "must-not-leak" not in str(result)
    assert result["vpc"] == {
        "enabled": True,
        "vpc_id": "vpc-123",
        "subnet_count": 2,
        "security_group_count": 1,
    }
    assert result["recent_metrics"]["errors"]["value"] == 2.0
    assert result["recent_metrics"]["available"] is True
    assert result["recent_metrics"]["warnings"] == []
    assert result["recent_metrics"]["max_duration_ms"]["value"] == 1234.0


def test_get_lambda_summary_returns_config_when_metrics_fail() -> None:
    runtime = FakeRuntime()
    runtime.cloudwatch_client = FailingCloudWatchClient()

    result = get_lambda_summary(runtime, "dev-api")

    assert result["function_name"] == "dev-api"
    assert result["recent_metrics"]["available"] is False
    assert result["recent_metrics"]["errors"]["value"] == 0
    assert result["recent_metrics"]["warnings"]


def test_get_lambda_summary_normalizes_configuration_errors() -> None:
    runtime = FakeRuntime()
    runtime.lambda_client = FailingConfigurationLambdaClient()

    with pytest.raises(AwsToolError, match="AWS lambda.GetFunctionConfiguration AccessDenied"):
        get_lambda_summary(runtime, "dev-api")


def test_get_lambda_summary_reports_metric_data_warnings() -> None:
    runtime = FakeRuntime()
    runtime.cloudwatch_client = PartialMetricDataCloudWatchClient()

    result = get_lambda_summary(runtime, "dev-api")

    assert result["recent_metrics"]["available"] is True
    assert result["recent_metrics"]["warnings"] == ["Metric errors returned status PartialData"]


def test_explain_lambda_network_access_reports_non_vpc_runtime() -> None:
    runtime = FakeRuntime()
    runtime.lambda_client = NonVpcLambdaClient()

    result = explain_lambda_network_access(runtime, "dev-api")

    assert result["summary"]["network_mode"] == "aws_managed"
    assert result["summary"]["internet_access"] == "yes"
    assert result["network_context"]["vpc_id"] is None
    assert result["paths"] == []


def test_explain_lambda_network_access_reports_nat_internet_path() -> None:
    result = explain_lambda_network_access(FakeRuntime(), "dev-api")

    assert result["summary"]["network_mode"] == "vpc"
    assert result["summary"]["internet_access"] == "yes"
    assert result["egress"]["internet"]["via"] == ["nat-1"]
    assert {path["from_subnet"] for path in result["paths"] if path["verdict"] == "reachable"} == {
        "subnet-1",
        "subnet-2",
    }
    assert "wide_ipv4_egress" in result["summary"]["main_risks"]


def test_explain_lambda_network_access_reports_route_block() -> None:
    runtime = FakeRuntime()
    runtime.ec2_client = FakeEc2Client(
        route_tables=[
            {
                "RouteTableId": "rtb-isolated",
                "Associations": [{"SubnetId": "subnet-1"}, {"SubnetId": "subnet-2"}],
                "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}],
            }
        ]
    )

    result = explain_lambda_network_access(runtime, "dev-api")

    internet_paths = [path for path in result["paths"] if path["destination_class"] == "internet"]
    assert result["summary"]["internet_access"] == "no"
    assert {path["verdict"] for path in internet_paths} == {"blocked"}
    assert result["egress"]["blocked_or_unknown"][0]["reason"] == (
        "rtb-isolated has no ipv4 default route"
    )


def test_explain_lambda_network_access_reports_security_group_block() -> None:
    runtime = FakeRuntime()
    runtime.ec2_client = FakeEc2Client(
        security_groups=[
            {
                "GroupId": "sg-1",
                "GroupName": "private-only",
                "IpPermissionsEgress": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    }
                ],
            }
        ]
    )

    result = explain_lambda_network_access(runtime, "dev-api")

    internet_paths = [path for path in result["paths"] if path["destination_class"] == "internet"]
    assert result["summary"]["internet_access"] == "no"
    assert internet_paths[0]["limited_by"] == [
        "no security group egress rule allows tcp/443 to 0.0.0.0/0"
    ]


def test_explain_lambda_network_access_reports_mixed_subnet_routes() -> None:
    runtime = FakeRuntime()
    runtime.ec2_client = FakeEc2Client(
        route_tables=[
            {
                "RouteTableId": "rtb-nat",
                "Associations": [{"SubnetId": "subnet-1"}],
                "Routes": [
                    {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"},
                    {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"},
                ],
            },
            {
                "RouteTableId": "rtb-isolated",
                "Associations": [{"SubnetId": "subnet-2"}],
                "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}],
            },
        ]
    )

    result = explain_lambda_network_access(runtime, "dev-api")

    internet_paths = [path for path in result["paths"] if path["destination_class"] == "internet"]
    assert result["summary"]["internet_access"] == "partial"
    assert {path["from_subnet"]: path["verdict"] for path in internet_paths} == {
        "subnet-1": "reachable",
        "subnet-2": "blocked",
    }
    assert "subnet_route_mismatch" in result["summary"]["main_risks"]


def test_get_lambda_recent_errors_returns_bounded_grouped_events() -> None:
    runtime = FakeRuntime()

    result = get_lambda_recent_errors(runtime, "dev-api", since_minutes=999, max_events=2)

    assert result["function_name"] == "dev-api"
    assert result["log_group_name"] == "/aws/lambda/dev-api"
    assert result["window_minutes"] == 120
    assert result["count"] == 2
    assert runtime.logs_client.last_request is not None
    assert runtime.logs_client.last_request["limit"] == 2
    assert runtime.logs_client.last_request["filterPattern"]
    assert len(result["groups"]) == 1
    assert result["groups"][0]["count"] == 2
    assert "request <num> failed for user <num>" in result["groups"][0]["fingerprint"]


def test_get_lambda_recent_errors_follows_next_token_until_limit() -> None:
    runtime = FakeRuntime()
    runtime.logs_client = PaginatedLogsClient()

    result = get_lambda_recent_errors(runtime, "dev-api", max_events=2)

    assert result["count"] == 2
    assert runtime.logs_client.requests[1]["nextToken"] == "page-2"


def test_get_lambda_recent_errors_truncates_messages() -> None:
    result = get_lambda_recent_errors(FakeRuntime(), "dev-api", max_events=3)

    access_denied_event = result["events"][2]
    assert "chars omitted" in access_denied_event["message"]
    assert "must-not-leak" not in access_denied_event["message"]
    assert "secret=[REDACTED]" in access_denied_event["message"]
    assert access_denied_event["truncated"] is True
    assert len(access_denied_event["message"]) < 170


def test_get_lambda_recent_errors_normalizes_log_errors() -> None:
    runtime = FakeRuntime()
    runtime.logs_client = FailingLogsClient()

    with pytest.raises(AwsToolError, match="AWS logs.FilterLogEvents AccessDenied"):
        get_lambda_recent_errors(runtime, "dev-api")


def test_investigate_lambda_failure_summarizes_signals_and_next_checks() -> None:
    result = investigate_lambda_failure(FakeRuntime(), "dev-api")

    assert result["diagnostic_summary"] == (
        "Recent failures show permission or access-denied indicators."
    )
    assert result["signals"]["errors_last_hour"] == 2.0
    assert result["signals"]["permission_indicators"] is True
    assert result["signals"]["timeout_indicators"] is False
    assert result["warnings"] == []
    assert result["recent_error_count"] == 3
    assert any("execution role policy" in check for check in result["suggested_next_checks"])
    assert result["configuration"]["handler"] == "app.handler"
    assert result["configuration"]["aliases"]["count"] == 1
    assert result["configuration"]["event_sources"]["count"] == 1


def test_investigate_lambda_failure_reports_no_recent_errors() -> None:
    runtime = FakeRuntime()
    runtime.cloudwatch_client = QuietCloudWatchClient()
    runtime.logs_client = QuietLogsClient()

    result = investigate_lambda_failure(runtime, "dev-api")

    assert result["diagnostic_summary"].startswith("No recent Lambda error logs")
    assert result["signals"]["errors_last_hour"] == 0
    assert result["recent_error_count"] == 0


def test_investigate_lambda_failure_surfaces_metric_warnings() -> None:
    runtime = FakeRuntime()
    runtime.cloudwatch_client = FailingCloudWatchClient()

    result = investigate_lambda_failure(runtime, "dev-api")

    assert result["warnings"]


def test_explain_lambda_dependencies_returns_graph_and_permission_hints() -> None:
    result = explain_lambda_dependencies(FakeRuntime(), "dev-api")

    assert result["name"] == "dev-api"
    assert result["arn"] == "arn:aws:lambda:eu-west-2:123456789012:function:dev-api"
    assert result["function_name"] == "dev-api"
    assert result["nodes"]["execution_role"]["role_name"] == "dev-lambda"
    assert result["nodes"]["execution_role"]["attached_policy_count"] == 1
    assert result["nodes"]["execution_role"]["inline_policy_count"] == 2
    assert result["nodes"]["event_sources"]["count"] == 1
    assert any(edge["relationship"] == "uses_execution_role" for edge in result["edges"])
    assert any(edge["relationship"] == "triggers" for edge in result["edges"])
    assert any(
        "logs:PutLogEvents" in hint["actions_to_check"] for hint in result["permission_hints"]
    )
    assert any(
        "ec2:CreateNetworkInterface" in hint["actions_to_check"]
        for hint in result["permission_hints"]
    )
    assert any("sqs:SendMessage" in hint["actions_to_check"] for hint in result["permission_hints"])
    assert result["permission_checks"]["enabled"] is True
    checked_actions = {check["action"] for check in result["permission_checks"]["checks"]}
    assert "logs:PutLogEvents" in checked_actions
    assert "sqs:SendMessage" in checked_actions
    assert "sqs:ReceiveMessage" in checked_actions
    assert (
        result["permission_checks"]["summary"]["allowed"]
        == result["permission_checks"]["checked_count"]
    )
    assert result["graph_summary"]["edge_count"] == len(result["edges"])
    assert (
        result["graph_summary"]["permission_check_count"]
        == result["permission_checks"]["checked_count"]
    )
    hint_services = {
        (hint["source"], hint["likely_service"]) for hint in result["unresolved_resource_hints"]
    }
    assert ("environment_variable_key", "secretsmanager") in hint_services
    assert ("inline_policy_name", "dynamodb") in hint_services
    assert ("inline_policy_name", "s3") in hint_services
    assert result["warnings"] == []


def test_explain_lambda_dependencies_keeps_iam_failures_best_effort() -> None:
    runtime = FakeRuntime()
    runtime.iam_client = FailingIamClient()

    result = explain_lambda_dependencies(runtime, "dev-api")

    assert result["nodes"]["execution_role"]["available"] is False
    assert result["nodes"]["execution_role"]["role_name"] == "dev-lambda"
    assert result["permission_checks"]["summary"]["unknown"] > 0
    assert result["warnings"]


def test_explain_lambda_dependencies_can_skip_permission_checks() -> None:
    result = explain_lambda_dependencies(
        FakeRuntime(),
        "dev-api",
        include_permission_checks=False,
    )

    assert result["permission_checks"]["enabled"] is False
    assert result["permission_checks"]["checked_count"] == 0


def test_check_lambda_permission_path_reports_allowed_decision() -> None:
    result = check_lambda_permission_path(
        FakeRuntime(),
        "dev-api",
        "dynamodb:PutItem",
        "arn:aws:dynamodb:eu-west-2:123456789012:table/dev-table",
    )

    assert result["principal"]["role_name"] == "dev-lambda"
    assert result["action"] == "dynamodb:PutItem"
    assert result["decision"] == "allowed"
    assert result["allowed"] is True
    assert result["explicit_deny"] is False
    assert result["matched_statements"][0]["source_policy_id"] == "InlineDynamoAccess"
    assert result["warnings"] == []


def test_check_lambda_permission_path_reports_denied_decision() -> None:
    runtime = FakeRuntime()
    runtime.iam_client.simulation_decision = "implicitDeny"

    result = check_lambda_permission_path(
        runtime,
        "dev-api",
        "dynamodb:PutItem",
        "arn:aws:dynamodb:eu-west-2:123456789012:table/dev-table",
    )

    assert result["decision"] == "implicitDeny"
    assert result["allowed"] is False
    assert result["explicit_deny"] is False


def test_check_lambda_permission_path_keeps_simulation_failures_best_effort() -> None:
    runtime = FakeRuntime()
    runtime.iam_client = FailingSimulationIamClient()

    result = check_lambda_permission_path(
        runtime,
        "dev-api",
        "dynamodb:PutItem",
        "arn:aws:dynamodb:eu-west-2:123456789012:table/dev-table",
    )

    assert result["decision"] == "unknown"
    assert result["allowed"] is None
    assert result["principal"]["role_name"] == "dev-lambda"
    assert result["warnings"]


def test_check_lambda_permission_path_validates_inputs() -> None:
    with pytest.raises(ToolInputError, match="action must be an IAM action"):
        check_lambda_permission_path(
            FakeRuntime(),
            "dev-api",
            "PutItem",
            "arn:aws:dynamodb:eu-west-2:123456789012:table/dev-table",
        )

    with pytest.raises(ToolInputError, match="resource_arn must be an AWS ARN"):
        check_lambda_permission_path(
            FakeRuntime(),
            "dev-api",
            "dynamodb:PutItem",
            "dev-table",
        )


class QuietCloudWatchClient:
    def get_metric_data(self, **_: Any) -> dict[str, Any]:
        return {"MetricDataResults": []}


class FailingCloudWatchClient:
    def get_metric_data(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "metrics denied",
                }
            },
            "GetMetricData",
        )


class FailingListLambdaClient(FakeLambdaClient):
    def get_paginator(self, operation_name: str) -> FakePaginator:
        assert operation_name == "list_functions"
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "lambda denied token=must-not-leak",
                }
            },
            "ListFunctions",
        )


class FailingConfigurationLambdaClient(FakeLambdaClient):
    def get_function_configuration(self, FunctionName: str) -> dict[str, Any]:
        assert FunctionName == "dev-api"
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "configuration denied password=must-not-leak",
                }
            },
            "GetFunctionConfiguration",
        )


class FailingLogsClient:
    def filter_log_events(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "logs denied"}},
            "FilterLogEvents",
        )


class FailingIamClient:
    def get_role(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "iam denied"}},
            "GetRole",
        )

    def get_paginator(self, operation_name: str) -> FakePaginator:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": f"{operation_name} denied"}},
            operation_name,
        )

    def simulate_principal_policy(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "simulation denied"}},
            "SimulatePrincipalPolicy",
        )


class FailingSimulationIamClient(FakeIamClient):
    def simulate_principal_policy(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "simulation denied"}},
            "SimulatePrincipalPolicy",
        )


class PartialMetricDataCloudWatchClient:
    def get_metric_data(self, **_: Any) -> dict[str, Any]:
        return {
            "MetricDataResults": [
                {
                    "Id": "errors",
                    "Values": [1.0],
                    "Timestamps": [datetime(2026, 1, 1, tzinfo=UTC)],
                    "StatusCode": "PartialData",
                }
            ]
        }


class QuietLogsClient:
    def filter_log_events(self, **_: Any) -> dict[str, Any]:
        return {"events": []}


class PaginatedLogsClient:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def filter_log_events(self, **kwargs: Any) -> dict[str, Any]:
        self.requests.append(kwargs)
        if "nextToken" not in kwargs:
            return {
                "events": [
                    {
                        "timestamp": 1_767_225_600_000,
                        "logStreamName": "stream-a",
                        "message": "ERROR first",
                    }
                ],
                "nextToken": "page-2",
            }
        return {
            "events": [
                {
                    "timestamp": 1_767_225_660_000,
                    "logStreamName": "stream-b",
                    "message": "ERROR second",
                }
            ]
        }
