from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.stepfunctions import (
    _step_function_permission_hints,
    explain_step_function_dependencies,
    get_step_function_execution_summary,
    investigate_step_function_failure,
    list_step_functions,
)


class FakePaginator:
    def __init__(self, pages: list[dict[str, Any]] | None = None) -> None:
        self.pages = pages or [
            {
                "stateMachines": [
                    {
                        "name": "dev-order-flow",
                        "stateMachineArn": (
                            "arn:aws:states:eu-west-2:123456789012:stateMachine:dev-order-flow"
                        ),
                        "type": "STANDARD",
                        "creationDate": datetime(2026, 1, 1, tzinfo=UTC),
                    },
                    {
                        "name": "prod-order-flow",
                        "stateMachineArn": (
                            "arn:aws:states:eu-west-2:123456789012:stateMachine:prod-order-flow"
                        ),
                        "type": "EXPRESS",
                        "creationDate": datetime(2026, 1, 2, tzinfo=UTC),
                    },
                ]
            }
        ]

    def paginate(self, **_: Any) -> list[dict[str, Any]]:
        return self.pages


class FakeStepFunctionsClient:
    def get_paginator(self, operation_name: str) -> FakePaginator:
        assert operation_name == "list_state_machines"
        return FakePaginator()

    def describe_execution(self, executionArn: str) -> dict[str, Any]:
        assert executionArn.endswith(":dev-order-flow:exec-1")
        return {
            "executionArn": executionArn,
            "status": "FAILED",
            "startDate": datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
            "stopDate": datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
            "input": '{"orderId":"123","apiToken":"secret-value"}',
            "output": '{"result":"failed","password":"secret-value"}',
        }

    def describe_state_machine(self, stateMachineArn: str) -> dict[str, Any]:
        assert stateMachineArn.endswith(":stateMachine:dev-order-flow")
        return {
            "stateMachineArn": stateMachineArn,
            "name": "dev-order-flow",
            "type": "STANDARD",
            "status": "ACTIVE",
            "roleArn": "arn:aws:iam::123456789012:role/dev-sfn-role",
            "definition": json.dumps(
                {
                    "StartAt": "CallWorker",
                    "States": {
                        "CallWorker": {
                            "Type": "Task",
                            "Resource": (
                                "arn:aws:lambda:eu-west-2:123456789012:function:dev-worker"
                            ),
                            "Next": "ShouldNotify",
                        },
                        "ShouldNotify": {
                            "Type": "Choice",
                            "Choices": [
                                {
                                    "Variable": "$.notify",
                                    "BooleanEquals": True,
                                    "Next": "WaitBeforeNotify",
                                }
                            ],
                            "Default": "Done",
                        },
                        "WaitBeforeNotify": {
                            "Type": "Wait",
                            "Seconds": 30,
                            "Next": "Notify",
                        },
                        "Notify": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::sns:publish",
                            "Parameters": {
                                "TopicArn": "arn:aws:sns:eu-west-2:123456789012:dev-topic",
                                "Message.$": "$.message",
                            },
                            "Next": "Done",
                        },
                        "Done": {
                            "Type": "Succeed",
                        },
                    },
                }
            ),
        }

    def get_execution_history(self, **_: Any) -> dict[str, Any]:
        return {
            "events": [
                {
                    "id": 7,
                    "previousEventId": 6,
                    "timestamp": datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
                    "type": "TaskFailed",
                    "taskFailedEventDetails": {
                        "error": "Lambda.ServiceException",
                        "cause": "Worker failed",
                    },
                },
                {
                    "id": 6,
                    "previousEventId": 5,
                    "timestamp": datetime(2026, 1, 1, 12, 0, 55, tzinfo=UTC),
                    "type": "TaskStateEntered",
                    "taskStateEnteredEventDetails": {
                        "name": "CallWorker",
                        "input": "{}",
                    },
                },
            ]
        }


class FakeIamClient:
    def __init__(self) -> None:
        self.simulation_decision = "allowed"

    def get_role(self, RoleName: str) -> dict[str, Any]:
        assert RoleName == "dev-sfn-role"
        return {
            "Role": {
                "RoleName": RoleName,
                "Arn": "arn:aws:iam::123456789012:role/dev-sfn-role",
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
                                "PolicyName": "StepFunctionsInvokeTargets",
                                "PolicyArn": (
                                    "arn:aws:iam::123456789012:policy/StepFunctionsInvokeTargets"
                                ),
                            }
                        ]
                    }
                ]
            )
        if operation_name == "list_role_policies":
            return FakePaginator([{"PolicyNames": ["InlineSfnTargets"]}])
        raise AssertionError(f"Unexpected paginator {operation_name}")

    def simulate_principal_policy(
        self,
        PolicySourceArn: str,
        ActionNames: list[str],
        ResourceArns: list[str],
    ) -> dict[str, Any]:
        assert PolicySourceArn == "arn:aws:iam::123456789012:role/dev-sfn-role"
        assert ActionNames
        assert ResourceArns
        return {
            "EvaluationResults": [
                {
                    "EvalDecision": self.simulation_decision,
                    "MatchedStatements": [
                        {
                            "SourcePolicyId": "InlineSfnTargets",
                            "SourcePolicyType": "IAM Policy",
                        }
                    ],
                    "MissingContextValues": [],
                }
            ]
        }


class FakeRuntime:
    def __init__(self) -> None:
        self.config = AwsSafeConfig(
            allowed_account_ids=["123456789012"],
            max_results=100,
            redaction={"max_string_length": 200},
        )
        self.region = "eu-west-2"
        self.stepfunctions_client = FakeStepFunctionsClient()
        self.iam_client = FakeIamClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert region == "eu-west-2"
        if service_name == "stepfunctions":
            return self.stepfunctions_client
        if service_name == "iam":
            return self.iam_client
        raise AssertionError(f"Unexpected service {service_name}")


def test_list_step_functions_returns_visible_names() -> None:
    result = list_step_functions(FakeRuntime())

    assert result["count"] == 2
    assert result["state_machines"][0]["name"] == "dev-order-flow"
    assert result["state_machines"][0]["type"] == "STANDARD"


def test_list_step_functions_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.stepfunctions_client = FailingListStepFunctionsClient()

    with pytest.raises(AwsToolError, match="AWS states.ListStateMachines AccessDenied"):
        list_step_functions(runtime)


def test_execution_summary_redacts_input_output_and_reports_failed_state() -> None:
    result = get_step_function_execution_summary(
        FakeRuntime(),
        "arn:aws:states:eu-west-2:123456789012:execution:dev-order-flow:exec-1",
    )

    assert result["status"] == "FAILED"
    assert result["failed_state"]["state_name"] == "CallWorker"
    assert "secret-value" not in str(result)
    assert "apiToken" in result["input"]["value"]
    assert "[REDACTED]" in result["input"]["value"]
    assert "[REDACTED]" in result["output"]["value"]


def test_execution_summary_reads_paginated_history() -> None:
    runtime = FakeRuntime()
    runtime.stepfunctions_client = PaginatedStepFunctionsClient()

    result = get_step_function_execution_summary(
        runtime,
        "arn:aws:states:eu-west-2:123456789012:execution:dev-order-flow:exec-1",
    )

    assert result["failed_state"]["state_name"] == "SecondPageState"
    assert runtime.stepfunctions_client.requests[1]["nextToken"] == "page-2"


def test_execution_summary_normalizes_describe_errors() -> None:
    runtime = FakeRuntime()
    runtime.stepfunctions_client = FailingDescribeStepFunctionsClient()

    with pytest.raises(AwsToolError, match="AWS states.DescribeExecution AccessDenied"):
        get_step_function_execution_summary(
            runtime,
            "arn:aws:states:eu-west-2:123456789012:execution:dev-order-flow:exec-1",
        )


def test_execution_summary_normalizes_history_errors() -> None:
    runtime = FakeRuntime()
    runtime.stepfunctions_client = FailingHistoryStepFunctionsClient()

    with pytest.raises(AwsToolError, match="AWS states.GetExecutionHistory AccessDenied"):
        get_step_function_execution_summary(
            runtime,
            "arn:aws:states:eu-west-2:123456789012:execution:dev-order-flow:exec-1",
        )


def test_execution_summary_rejects_disallowed_account() -> None:
    with pytest.raises(ToolInputError, match="not allowed"):
        get_step_function_execution_summary(
            FakeRuntime(),
            "arn:aws:states:eu-west-2:999999999999:execution:dev-order-flow:exec-1",
        )


def test_explain_step_function_dependencies_maps_tasks_and_permissions() -> None:
    result = explain_step_function_dependencies(
        FakeRuntime(),
        "arn:aws:states:eu-west-2:123456789012:stateMachine:dev-order-flow",
    )

    assert result["name"] == "dev-order-flow"
    assert result["arn"] == "arn:aws:states:eu-west-2:123456789012:stateMachine:dev-order-flow"
    assert result["state_machine_name"] == "dev-order-flow"
    assert result["nodes"]["execution_role"]["role_name"] == "dev-sfn-role"
    assert result["summary"]["state_count"] == 5
    assert result["summary"]["task_state_count"] == 2
    assert {edge["target_type"] for edge in result["edges"]} == {"lambda", "sns"}
    assert result["flow_summary"]["start_at"] == "CallWorker"
    assert result["flow_summary"]["choice_states"] == ["ShouldNotify"]
    assert result["flow_summary"]["wait_states"] == ["WaitBeforeNotify"]
    assert result["flow_summary"]["terminal_states"] == ["Done"]
    assert [
        "CallWorker",
        "ShouldNotify",
        "WaitBeforeNotify",
        "Notify",
        "Done",
    ] in result["flow_summary"]["linear_paths"]
    assert ["CallWorker", "ShouldNotify", "Done"] in result["flow_summary"]["linear_paths"]
    assert len(result["permission_hints"]) == 2
    lambda_hint = next(
        hint for hint in result["permission_hints"] if hint["integration"] == "lambda"
    )
    assert lambda_hint["state_names"] == ["CallWorker"]
    assert lambda_hint["state_count"] == 1
    checked_actions = {check["action"] for check in result["permission_checks"]["checks"]}
    assert "lambda:InvokeFunction" in checked_actions
    assert "sns:Publish" in checked_actions
    assert result["permission_checks"]["summary"]["allowed"] == 2
    assert result["graph_summary"]["edge_count"] == len(result["edges"])
    assert (
        result["graph_summary"]["permission_check_count"]
        == result["permission_checks"]["checked_count"]
    )
    assert result["warnings"] == []


def test_explain_step_function_dependencies_can_skip_permission_checks() -> None:
    result = explain_step_function_dependencies(
        FakeRuntime(),
        "arn:aws:states:eu-west-2:123456789012:stateMachine:dev-order-flow",
        include_permission_checks=False,
    )

    assert result["permission_checks"]["enabled"] is False
    assert result["permission_checks"]["checked_count"] == 0


def test_explain_step_function_dependencies_rejects_disallowed_account() -> None:
    with pytest.raises(ToolInputError, match="not allowed"):
        explain_step_function_dependencies(
            FakeRuntime(),
            "arn:aws:states:eu-west-2:999999999999:stateMachine:dev-order-flow",
        )


def test_step_function_permission_hints_dedupe_repeated_targets() -> None:
    hints = _step_function_permission_hints(
        [
            {
                "to": "arn:aws:lambda:eu-west-2:123456789012:function:worker",
                "target_type": "lambda",
                "state_name": "A",
            },
            {
                "to": "arn:aws:lambda:eu-west-2:123456789012:function:worker",
                "target_type": "lambda",
                "state_name": "B",
            },
        ],
        "arn:aws:iam::123456789012:role/sfn",
    )

    assert len(hints) == 1
    assert hints[0]["state_names"] == ["A", "B"]
    assert hints[0]["state_count"] == 2
    assert hints[0]["actions_to_check"] == ["lambda:InvokeFunction"]


def test_investigate_step_function_failure_reports_task_failure() -> None:
    result = investigate_step_function_failure(
        FakeRuntime(),
        "arn:aws:states:eu-west-2:123456789012:execution:dev-order-flow:exec-1",
    )

    assert result["diagnostic_summary"] == (
        "Execution failed with Lambda/task failure, AWS service exception indicators."
    )
    assert result["signals"]["lambda_or_task_failure"] is True
    assert result["signals"]["service_exception"] is True
    assert result["warnings"] == []
    assert any("Lambda logs" in check for check in result["suggested_next_checks"])


def test_investigate_step_function_failure_reports_no_failed_state() -> None:
    runtime = FakeRuntime()
    runtime.stepfunctions_client = QuietStepFunctionsClient()

    result = investigate_step_function_failure(
        runtime,
        "arn:aws:states:eu-west-2:123456789012:execution:dev-order-flow:exec-1",
    )

    assert result["diagnostic_summary"].startswith("Execution status is SUCCEEDED")
    assert result["signals"]["has_failure"] is False


class QuietStepFunctionsClient(FakeStepFunctionsClient):
    def describe_execution(self, executionArn: str) -> dict[str, Any]:
        return {
            "executionArn": executionArn,
            "status": "SUCCEEDED",
            "startDate": datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
            "stopDate": datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
        }

    def get_execution_history(self, **_: Any) -> dict[str, Any]:
        return {"events": []}


class PaginatedStepFunctionsClient(FakeStepFunctionsClient):
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def get_execution_history(self, **kwargs: Any) -> dict[str, Any]:
        self.requests.append(kwargs)
        if "nextToken" not in kwargs:
            return {"events": [], "nextToken": "page-2"}
        return {
            "events": [
                {
                    "id": 3,
                    "previousEventId": 2,
                    "timestamp": datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
                    "type": "TaskFailed",
                    "taskFailedEventDetails": {"error": "States.TaskFailed"},
                },
                {
                    "id": 2,
                    "previousEventId": 1,
                    "timestamp": datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
                    "type": "TaskStateEntered",
                    "taskStateEnteredEventDetails": {"name": "SecondPageState"},
                },
            ]
        }


class FailingListStepFunctionsClient(FakeStepFunctionsClient):
    def get_paginator(self, operation_name: str) -> FakePaginator:
        assert operation_name == "list_state_machines"
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "list denied"}},
            "ListStateMachines",
        )


class FailingDescribeStepFunctionsClient(FakeStepFunctionsClient):
    def describe_execution(self, executionArn: str) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "describe denied"}},
            "DescribeExecution",
        )


class FailingHistoryStepFunctionsClient(FakeStepFunctionsClient):
    def get_execution_history(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "history denied"}},
            "GetExecutionHistory",
        )
