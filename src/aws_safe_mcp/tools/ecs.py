from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.common import clamp_limit, resolve_region


def list_ecs_clusters(
    runtime: AwsRuntime,
    region: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    client = runtime.client("ecs", region=resolved_region)
    try:
        response = client.list_clusters(maxResults=min(limit, 100))
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "ecs.ListClusters") from exc
    clusters = response.get("clusterArns", [])[:limit]
    return {
        "region": resolved_region,
        "count": len(clusters),
        "is_truncated": bool(response.get("nextToken")),
        "clusters": [{"cluster_arn": arn, "name": str(arn).split("/")[-1]} for arn in clusters],
    }


def list_ecs_services(
    runtime: AwsRuntime,
    cluster: str,
    region: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_cluster = _require_value(cluster, "cluster")
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    client = runtime.client("ecs", region=resolved_region)
    try:
        response = client.list_services(cluster=required_cluster, maxResults=min(limit, 100))
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "ecs.ListServices") from exc
    services = response.get("serviceArns", [])[:limit]
    return {
        "region": resolved_region,
        "cluster": required_cluster,
        "count": len(services),
        "is_truncated": bool(response.get("nextToken")),
        "services": [{"service_arn": arn, "name": str(arn).split("/")[-1]} for arn in services],
    }


def get_ecs_service_summary(
    runtime: AwsRuntime,
    cluster: str,
    service: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_cluster = _require_value(cluster, "cluster")
    required_service = _require_value(service, "service")
    client = runtime.client("ecs", region=resolved_region)
    try:
        response = client.describe_services(cluster=required_cluster, services=[required_service])
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "ecs.DescribeServices") from exc
    services = response.get("services", [])
    service_item = services[0] if services else {}
    task_definition_arn = str(service_item.get("taskDefinition") or "")
    task_definition = _ecs_task_definition_summary(client, task_definition_arn)
    return {
        "region": resolved_region,
        "cluster": required_cluster,
        "service": _ecs_service_item(service_item),
        "task_definition": task_definition,
        "warnings": _ecs_failures(response.get("failures", [])),
    }


def _require_value(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ToolInputError(f"{label} is required")
    return normalized


def _ecs_service_item(item: dict[str, Any]) -> dict[str, Any]:
    deployments = item.get("deployments", [])
    return {
        "service_name": item.get("serviceName"),
        "service_arn": item.get("serviceArn"),
        "status": item.get("status"),
        "desired_count": item.get("desiredCount"),
        "running_count": item.get("runningCount"),
        "pending_count": item.get("pendingCount"),
        "launch_type": item.get("launchType"),
        "platform_version": item.get("platformVersion"),
        "task_definition": item.get("taskDefinition"),
        "deployment_count": len(deployments),
        "deployments": [_ecs_deployment_summary(deployment) for deployment in deployments],
        "load_balancers": [_ecs_load_balancer_summary(lb) for lb in item.get("loadBalancers", [])],
    }


def _ecs_task_definition_summary(client: Any, task_definition_arn: str) -> dict[str, Any]:
    if not task_definition_arn:
        return {"available": False, "warnings": ["Service did not include a task definition ARN"]}
    try:
        response = client.describe_task_definition(taskDefinition=task_definition_arn)
    except (BotoCoreError, ClientError) as exc:
        return {
            "available": False,
            "warnings": [str(normalize_aws_error(exc, "ecs.DescribeTaskDefinition"))],
        }
    task = response.get("taskDefinition", {})
    return {
        "available": True,
        "task_definition_arn": task.get("taskDefinitionArn"),
        "family": task.get("family"),
        "revision": task.get("revision"),
        "status": task.get("status"),
        "network_mode": task.get("networkMode"),
        "requires_compatibilities": task.get("requiresCompatibilities", []),
        "cpu": task.get("cpu"),
        "memory": task.get("memory"),
        "task_role_arn": task.get("taskRoleArn"),
        "execution_role_arn": task.get("executionRoleArn"),
        "container_count": len(task.get("containerDefinitions", [])),
        "containers": [
            _ecs_container_summary(container)
            for container in task.get("containerDefinitions", [])
        ],
        "warnings": [],
    }


def _ecs_deployment_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "status": item.get("status"),
        "rollout_state": item.get("rolloutState"),
        "desired_count": item.get("desiredCount"),
        "running_count": item.get("runningCount"),
        "pending_count": item.get("pendingCount"),
    }


def _ecs_load_balancer_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "target_group_arn": item.get("targetGroupArn"),
        "load_balancer_name": item.get("loadBalancerName"),
        "container_name": item.get("containerName"),
        "container_port": item.get("containerPort"),
    }


def _ecs_container_summary(item: dict[str, Any]) -> dict[str, Any]:
    log_config = item.get("logConfiguration") or {}
    options = log_config.get("options") or {}
    return {
        "name": item.get("name"),
        "image": item.get("image"),
        "cpu": item.get("cpu"),
        "memory": item.get("memory"),
        "essential": item.get("essential"),
        "port_mappings": [
            {
                "container_port": mapping.get("containerPort"),
                "host_port": mapping.get("hostPort"),
                "protocol": mapping.get("protocol"),
            }
            for mapping in item.get("portMappings", [])
        ],
        "environment_key_count": len(item.get("environment", [])),
        "secret_count": len(item.get("secrets", [])),
        "log_group": options.get("awslogs-group"),
        "log_stream_prefix": options.get("awslogs-stream-prefix"),
    }


def _ecs_failures(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        f"{item.get('arn') or item.get('reason')}: {item.get('detail') or item.get('reason')}"
        for item in value
        if isinstance(item, dict)
    ]
