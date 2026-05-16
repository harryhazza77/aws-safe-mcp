from __future__ import annotations

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


def _require_key_id(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ToolInputError("key_id is required")
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
