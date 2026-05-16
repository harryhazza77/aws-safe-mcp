from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.common import clamp_limit, isoformat, resolve_region


def list_kms_keys(
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
    client = runtime.client("kms", region=resolved_region)
    keys: list[dict[str, Any]] = []
    marker: str | None = None
    try:
        while len(keys) < limit:
            request: dict[str, Any] = {"Limit": min(limit, 100)}
            if marker:
                request["Marker"] = marker
            response = client.list_keys(**request)
            for item in response.get("Keys", []):
                keys.append(_kms_key_list_item(client, item))
                if len(keys) >= limit:
                    break
            marker = response.get("NextMarker")
            if not marker or not response.get("Truncated"):
                break
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "kms.ListKeys") from exc

    return {
        "region": resolved_region,
        "count": len(keys),
        "is_truncated": bool(marker),
        "summary": _kms_inventory_summary(keys),
        "keys": keys,
    }


def get_kms_key_summary(
    runtime: AwsRuntime,
    key_id: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_key_id = _require_key_id(key_id)
    client = runtime.client("kms", region=resolved_region)
    warnings: list[str] = []
    try:
        response = client.describe_key(KeyId=required_key_id)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "kms.DescribeKey") from exc

    metadata = _kms_key_metadata(response.get("KeyMetadata", {}))
    rotation = _kms_rotation_status(client, required_key_id, warnings)
    aliases = _kms_aliases(client, required_key_id, warnings)
    policy_names = _kms_key_policy_names(client, required_key_id, warnings)
    return {
        "region": resolved_region,
        "key_id": required_key_id,
        "metadata": metadata,
        "aliases": aliases,
        "rotation": rotation,
        "policy": {
            "available": bool(policy_names),
            "policy_name_count": len(policy_names),
            "policy_names": policy_names,
        },
        "warnings": warnings,
    }


def check_kms_dependent_path(
    runtime: AwsRuntime,
    key_id: str,
    role_arn: str,
    service_principal: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_key_id = _require_key_id(key_id)
    required_role_arn = _require_role_arn(role_arn)
    client = runtime.client("kms", region=resolved_region)
    warnings: list[str] = []
    try:
        response = client.describe_key(KeyId=required_key_id)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "kms.DescribeKey") from exc

    metadata = _kms_key_metadata(response.get("KeyMetadata", {}))
    key_arn = str(metadata.get("arn") or required_key_id)
    role_checks = _kms_role_permission_checks(
        runtime=runtime,
        role_arn=required_role_arn,
        key_arn=key_arn,
        warnings=warnings,
    )
    service_check = _kms_service_principal_check(
        client=client,
        key_id=required_key_id,
        service_principal=service_principal,
        warnings=warnings,
    )
    return {
        "region": resolved_region,
        "key_id": required_key_id,
        "key": {
            "arn": metadata.get("arn"),
            "enabled": metadata.get("enabled"),
            "key_state": metadata.get("key_state"),
            "key_usage": metadata.get("key_usage"),
            "key_manager": metadata.get("key_manager"),
        },
        "role_arn": required_role_arn,
        "role_permission_checks": role_checks,
        "service_principal_check": service_check,
        "path_summary": _kms_path_summary(metadata, role_checks, service_check),
        "warnings": warnings,
    }


def _require_key_id(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ToolInputError("key_id is required")
    return normalized


def _require_role_arn(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ToolInputError("role_arn is required")
    if not normalized.startswith("arn:") or ":role/" not in normalized:
        raise ToolInputError("role_arn must be an IAM role ARN")
    return normalized


def _kms_key_list_item(client: Any, item: dict[str, Any]) -> dict[str, Any]:
    key_id = item.get("KeyId")
    try:
        response = client.describe_key(KeyId=key_id)
        metadata = _kms_key_metadata(response.get("KeyMetadata", {}))
    except (BotoCoreError, ClientError) as exc:
        metadata = {
            "key_id": key_id,
            "arn": item.get("KeyArn"),
            "warnings": [str(normalize_aws_error(exc, "kms.DescribeKey"))],
        }
    return metadata


def _kms_key_metadata(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "key_id": value.get("KeyId"),
        "arn": value.get("Arn"),
        "description": value.get("Description") or None,
        "enabled": value.get("Enabled"),
        "key_state": value.get("KeyState"),
        "key_usage": value.get("KeyUsage"),
        "key_manager": value.get("KeyManager"),
        "origin": value.get("Origin"),
        "creation_date": isoformat(value.get("CreationDate")),
        "deletion_date": isoformat(value.get("DeletionDate")),
        "multi_region": value.get("MultiRegion"),
    }


def _kms_rotation_status(client: Any, key_id: str, warnings: list[str]) -> dict[str, Any]:
    try:
        response = client.get_key_rotation_status(KeyId=key_id)
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "kms.GetKeyRotationStatus")))
        return {"available": False, "enabled": None}
    return {"available": True, "enabled": response.get("KeyRotationEnabled")}


def _kms_aliases(client: Any, key_id: str, warnings: list[str]) -> list[dict[str, Any]]:
    try:
        response = client.list_aliases(KeyId=key_id, Limit=100)
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "kms.ListAliases")))
        return []
    return [
        {
            "alias_name": item.get("AliasName"),
            "alias_arn": item.get("AliasArn"),
            "target_key_id": item.get("TargetKeyId"),
        }
        for item in response.get("Aliases", [])
    ]


def _kms_key_policy_names(client: Any, key_id: str, warnings: list[str]) -> list[str]:
    try:
        response = client.list_key_policies(KeyId=key_id, Limit=100)
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "kms.ListKeyPolicies")))
        return []
    return sorted(str(name) for name in response.get("PolicyNames", []))


def _kms_inventory_summary(keys: list[dict[str, Any]]) -> dict[str, Any]:
    by_state: dict[str, int] = {}
    by_usage: dict[str, int] = {}
    for key in keys:
        state = str(key.get("key_state") or "unknown")
        usage = str(key.get("key_usage") or "unknown")
        by_state[state] = by_state.get(state, 0) + 1
        by_usage[usage] = by_usage.get(usage, 0) + 1
    return {
        "key_count": len(keys),
        "by_state": by_state,
        "by_usage": by_usage,
    }


def _kms_role_permission_checks(
    *,
    runtime: AwsRuntime,
    role_arn: str,
    key_arn: str,
    warnings: list[str],
) -> list[dict[str, Any]]:
    iam = runtime.client("iam", region=runtime.region)
    checks: list[dict[str, Any]] = []
    for action in ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]:
        try:
            response = iam.simulate_principal_policy(
                PolicySourceArn=role_arn,
                ActionNames=[action],
                ResourceArns=[key_arn],
            )
        except (BotoCoreError, ClientError) as exc:
            warnings.append(str(normalize_aws_error(exc, "iam.SimulatePrincipalPolicy")))
            checks.append({"action": action, "decision": "unknown", "allowed": None})
            continue
        result = (response.get("EvaluationResults") or [{}])[0]
        decision = str(result.get("EvalDecision") or "unknown")
        checks.append(
            {
                "action": action,
                "decision": decision,
                "allowed": decision.lower() == "allowed",
                "missing_context_values": sorted(result.get("MissingContextValues") or []),
            }
        )
    return checks


def _kms_service_principal_check(
    *,
    client: Any,
    key_id: str,
    service_principal: str | None,
    warnings: list[str],
) -> dict[str, Any]:
    if not service_principal:
        return {"checked": False, "service_principal": None, "allowed_actions": []}
    try:
        response = client.get_key_policy(KeyId=key_id, PolicyName="default")
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "kms.GetKeyPolicy")))
        return {
            "checked": True,
            "service_principal": service_principal,
            "allowed_actions": [],
            "policy_readable": False,
        }
    policy = _json_object(response.get("Policy"))
    actions = _kms_allowed_actions_for_service(policy, service_principal)
    return {
        "checked": True,
        "service_principal": service_principal,
        "policy_readable": True,
        "allowed_actions": actions,
        "has_required_data_key_access": "kms:GenerateDataKey" in actions or "kms:*" in actions,
    }


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _kms_allowed_actions_for_service(
    policy: dict[str, Any],
    service_principal: str,
) -> list[str]:
    actions: set[str] = set()
    statements = policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if not _principal_matches(statement.get("Principal"), service_principal):
            continue
        for action in _string_list(statement.get("Action")):
            if action == "kms:*" or action.startswith("kms:"):
                actions.add(action)
    return sorted(actions)


def _principal_matches(principal: Any, service_principal: str) -> bool:
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    return service_principal in _string_list(principal.get("Service"))


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _kms_path_summary(
    metadata: dict[str, Any],
    role_checks: list[dict[str, Any]],
    service_check: dict[str, Any],
) -> dict[str, Any]:
    role_allowed = all(check.get("allowed") is True for check in role_checks)
    service_ok = (
        not service_check.get("checked")
        or bool(service_check.get("has_required_data_key_access"))
        or "kms:*" in service_check.get("allowed_actions", [])
    )
    return {
        "key_usable": metadata.get("enabled") is True and metadata.get("key_state") == "Enabled",
        "role_has_required_actions": role_allowed,
        "service_principal_has_data_key_access": service_ok,
        "likely_usable": bool(
            metadata.get("enabled") is True
            and metadata.get("key_state") == "Enabled"
            and role_allowed
            and service_ok
        ),
    }
