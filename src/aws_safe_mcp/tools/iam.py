from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.common import isoformat, resolve_region


def get_iam_role_summary(
    runtime: AwsRuntime,
    role_name: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_role_name = _require_role_name(role_name)
    client = runtime.client("iam", region=runtime.region)
    warnings: list[str] = []
    role: dict[str, Any] = {}
    attached_policies: list[dict[str, Any]] = []
    inline_policy_names: list[str] = []

    try:
        response = client.get_role(RoleName=required_role_name)
        role = response.get("Role", {})
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "iam.GetRole") from exc

    try:
        paginator = client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(
            RoleName=required_role_name,
            PaginationConfig={"PageSize": 50},
        ):
            for item in page.get("AttachedPolicies", []):
                attached_policies.append(
                    {
                        "policy_name": item.get("PolicyName"),
                        "policy_arn": item.get("PolicyArn"),
                    }
                )
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "iam.ListAttachedRolePolicies")))

    try:
        paginator = client.get_paginator("list_role_policies")
        for page in paginator.paginate(
            RoleName=required_role_name,
            PaginationConfig={"PageSize": 50},
        ):
            inline_policy_names.extend(str(name) for name in page.get("PolicyNames", []))
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "iam.ListRolePolicies")))

    boundary = role.get("PermissionsBoundary") or {}
    return {
        "role_name": role.get("RoleName") or required_role_name,
        "role_arn": role.get("Arn"),
        "region": resolved_region,
        "path": role.get("Path"),
        "created_at": isoformat(role.get("CreateDate")),
        "trust_policy": _trust_policy_summary(role.get("AssumeRolePolicyDocument")),
        "attached_policy_count": len(attached_policies),
        "attached_policies": attached_policies,
        "inline_policy_count": len(inline_policy_names),
        "inline_policy_names": sorted(inline_policy_names),
        "permissions_boundary": {
            "present": bool(boundary),
            "type": boundary.get("PermissionsBoundaryType"),
            "arn": boundary.get("PermissionsBoundaryArn"),
        },
        "warnings": warnings,
    }


def _require_role_name(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ToolInputError("role_name is required")
    if normalized.startswith("arn:"):
        parsed = _role_name_from_arn(normalized)
        if not parsed:
            raise ToolInputError("role_name ARN must be an IAM role ARN")
        return parsed
    return normalized


def _role_name_from_arn(role_arn: str) -> str | None:
    marker = ":role/"
    if marker not in role_arn:
        return None
    return role_arn.split(marker, 1)[1].split("/")[-1] or None


def _trust_policy_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {
            "statement_count": 0,
            "actions": [],
            "service_principals": [],
            "aws_principals": [],
            "federated_principals": [],
        }
    statements = value.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    actions: set[str] = set()
    service_principals: set[str] = set()
    aws_principals: set[str] = set()
    federated_principals: set[str] = set()
    for statement in statements if isinstance(statements, list) else []:
        if not isinstance(statement, dict):
            continue
        actions.update(_string_set(statement.get("Action")))
        principal = statement.get("Principal")
        if isinstance(principal, dict):
            service_principals.update(_string_set(principal.get("Service")))
            aws_principals.update(_string_set(principal.get("AWS")))
            federated_principals.update(_string_set(principal.get("Federated")))
    return {
        "statement_count": len(statements) if isinstance(statements, list) else 0,
        "actions": sorted(actions),
        "service_principals": sorted(service_principals),
        "aws_principals": sorted(aws_principals),
        "federated_principals": sorted(federated_principals),
    }


def _string_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()
