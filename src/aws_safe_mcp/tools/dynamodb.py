from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import normalize_aws_error
from aws_safe_mcp.tools.common import (
    clamp_limit,
    isoformat,
    require_dynamodb_table_name,
    resolve_region,
)


def list_dynamodb_tables(
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
    client = runtime.client("dynamodb", region=resolved_region)
    tables: list[str] = []
    request: dict[str, Any] = {"Limit": min(limit, 100)}

    try:
        while len(tables) < limit:
            response = client.list_tables(**request)
            for table_name in response.get("TableNames", []):
                if name_prefix and not str(table_name).startswith(name_prefix):
                    continue
                tables.append(str(table_name))
                if len(tables) >= limit:
                    break
            last_name = response.get("LastEvaluatedTableName")
            if not last_name:
                break
            request["ExclusiveStartTableName"] = last_name
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "dynamodb.ListTables") from exc

    return {
        "region": resolved_region,
        "name_prefix": name_prefix,
        "max_results": limit,
        "count": len(tables),
        "is_truncated": bool(request.get("ExclusiveStartTableName")) and len(tables) >= limit,
        "tables": tables,
    }


def dynamodb_table_summary(
    runtime: AwsRuntime,
    table_name: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_table = require_dynamodb_table_name(table_name)
    client = runtime.client("dynamodb", region=resolved_region)

    try:
        response = client.describe_table(TableName=required_table)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "dynamodb.DescribeTable") from exc

    table = response.get("Table", {})
    return {
        "table_name": table.get("TableName"),
        "table_arn": table.get("TableArn"),
        "region": resolved_region,
        "status": table.get("TableStatus"),
        "creation_date": isoformat(table.get("CreationDateTime")),
        "key_schema": table.get("KeySchema", []),
        "attribute_definitions": table.get("AttributeDefinitions", []),
        "billing_mode": _billing_mode(table),
        "item_count": table.get("ItemCount"),
        "size_bytes": table.get("TableSizeBytes"),
        "global_secondary_indexes": _indexes(table.get("GlobalSecondaryIndexes", [])),
        "local_secondary_indexes": _indexes(table.get("LocalSecondaryIndexes", [])),
        "stream": _stream_summary(table),
        "sse": _sse_summary(table),
        "point_in_time_recovery": _pitr_summary(table),
    }


def _billing_mode(table: dict[str, Any]) -> str:
    billing = table.get("BillingModeSummary", {})
    if isinstance(billing, dict) and billing.get("BillingMode"):
        return str(billing["BillingMode"])
    return "PROVISIONED"


def _indexes(indexes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": item.get("IndexName"),
            "status": item.get("IndexStatus"),
            "key_schema": item.get("KeySchema", []),
            "projection": item.get("Projection", {}),
            "item_count": item.get("ItemCount"),
            "size_bytes": item.get("IndexSizeBytes"),
        }
        for item in indexes
    ]


def _stream_summary(table: dict[str, Any]) -> dict[str, Any]:
    spec = table.get("StreamSpecification", {})
    return {
        "enabled": bool(spec.get("StreamEnabled")),
        "view_type": spec.get("StreamViewType"),
        "stream_arn": table.get("LatestStreamArn"),
    }


def _sse_summary(table: dict[str, Any]) -> dict[str, Any]:
    sse = table.get("SSEDescription", {})
    return {
        "status": sse.get("Status"),
        "type": sse.get("SSEType"),
        "kms_master_key_arn": sse.get("KMSMasterKeyArn"),
    }


def _pitr_summary(table: dict[str, Any]) -> dict[str, Any] | None:
    restore = table.get("RestoreSummary")
    if not isinstance(restore, dict):
        return None
    return {
        "restore_in_progress": restore.get("RestoreInProgress"),
        "source_backup_arn": restore.get("SourceBackupArn"),
        "source_table_arn": restore.get("SourceTableArn"),
    }
