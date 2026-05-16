from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.ecs import get_ecs_service_summary, list_ecs_clusters, list_ecs_services


class FakeEcsClient:
    def list_clusters(self, **_: Any) -> dict[str, Any]:
        return {"clusterArns": ["arn:aws:ecs:eu-west-2:123456789012:cluster/dev"]}

    def list_services(self, **_: Any) -> dict[str, Any]:
        return {"serviceArns": ["arn:aws:ecs:eu-west-2:123456789012:service/dev/api"]}

    def describe_services(self, **_: Any) -> dict[str, Any]:
        return {
            "services": [
                {
                    "serviceName": "api",
                    "serviceArn": "arn:aws:ecs:eu-west-2:123456789012:service/dev/api",
                    "status": "ACTIVE",
                    "desiredCount": 2,
                    "runningCount": 1,
                    "pendingCount": 1,
                    "launchType": "FARGATE",
                    "platformVersion": "1.4.0",
                    "taskDefinition": "arn:aws:ecs:eu-west-2:123456789012:task-definition/api:3",
                    "deployments": [
                        {
                            "id": "ecs-svc/1",
                            "status": "PRIMARY",
                            "rolloutState": "IN_PROGRESS",
                            "desiredCount": 2,
                            "runningCount": 1,
                            "pendingCount": 1,
                        }
                    ],
                    "loadBalancers": [
                        {
                            "targetGroupArn": (
                                "arn:aws:elasticloadbalancing:eu-west-2:123456789012:"
                                "targetgroup/api/123"
                            ),
                            "containerName": "api",
                            "containerPort": 8080,
                        }
                    ],
                }
            ],
            "failures": [],
        }

    def describe_task_definition(self, **_: Any) -> dict[str, Any]:
        return {
            "taskDefinition": {
                "taskDefinitionArn": "arn:aws:ecs:eu-west-2:123456789012:task-definition/api:3",
                "family": "api",
                "revision": 3,
                "status": "ACTIVE",
                "networkMode": "awsvpc",
                "requiresCompatibilities": ["FARGATE"],
                "cpu": "256",
                "memory": "512",
                "taskRoleArn": "arn:aws:iam::123456789012:role/task",
                "executionRoleArn": "arn:aws:iam::123456789012:role/execution",
                "containerDefinitions": [
                    {
                        "name": "api",
                        "image": "example/api:latest",
                        "cpu": 0,
                        "memory": 512,
                        "essential": True,
                        "environment": [{"name": "SECRET", "value": "must-not-leak"}],
                        "secrets": [{"name": "TOKEN", "valueFrom": "arn"}],
                        "portMappings": [
                            {"containerPort": 8080, "hostPort": 8080, "protocol": "tcp"}
                        ],
                        "logConfiguration": {
                            "logDriver": "awslogs",
                            "options": {
                                "awslogs-group": "/ecs/api",
                                "awslogs-stream-prefix": "ecs",
                            },
                        },
                    }
                ],
            }
        }


class FakeRuntime:
    config = AwsSafeConfig(allowed_account_ids=["123456789012"])
    region = "eu-west-2"

    def __init__(self) -> None:
        self.ecs_client = FakeEcsClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert service_name == "ecs"
        assert region == "eu-west-2"
        return self.ecs_client


def test_list_ecs_clusters_returns_names() -> None:
    result = list_ecs_clusters(FakeRuntime())

    assert result["count"] == 1
    assert result["clusters"][0]["name"] == "dev"


def test_list_ecs_services_returns_names() -> None:
    result = list_ecs_services(FakeRuntime(), "dev")

    assert result["count"] == 1
    assert result["services"][0]["name"] == "api"


def test_get_ecs_service_summary_returns_safe_task_metadata() -> None:
    result = get_ecs_service_summary(FakeRuntime(), "dev", "api")

    assert result["service"]["desired_count"] == 2
    assert result["service"]["deployments"][0]["rollout_state"] == "IN_PROGRESS"
    assert result["service"]["load_balancers"][0]["container_port"] == 8080
    assert result["task_definition"]["task_role_arn"].endswith(":role/task")
    container = result["task_definition"]["containers"][0]
    assert container["name"] == "api"
    assert container["environment_key_count"] == 1
    assert container["secret_count"] == 1
    assert container["log_group"] == "/ecs/api"
    assert "must-not-leak" not in str(result)


def test_get_ecs_service_summary_rejects_empty_inputs() -> None:
    with pytest.raises(ToolInputError, match="cluster is required"):
        get_ecs_service_summary(FakeRuntime(), " ", "api")
    with pytest.raises(ToolInputError, match="service is required"):
        get_ecs_service_summary(FakeRuntime(), "dev", " ")


def test_list_ecs_clusters_normalizes_errors() -> None:
    runtime = FakeRuntime()
    runtime.ecs_client = FailingEcsClient()

    with pytest.raises(AwsToolError, match="AWS ecs.ListClusters AccessDenied"):
        list_ecs_clusters(runtime)


class FailingEcsClient(FakeEcsClient):
    def list_clusters(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "ListClusters",
        )
