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


def check_dynamodb_stream_lambda_readiness(
    runtime: AwsRuntime,
    table_name: str,
    region: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    table = dynamodb_table_summary(runtime, table_name, region=resolved_region)
    stream = table.get("stream", {})
    stream_arn = stream.get("stream_arn") if isinstance(stream, dict) else None
    limit = clamp_limit(
        max_results,
        default=20,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    warnings: list[str] = []
    mappings = (
        _lambda_mappings_for_stream(runtime, resolved_region, str(stream_arn), limit, warnings)
        if stream_arn
        else []
    )
    permission_checks = _stream_lambda_permission_checks(
        runtime,
        resolved_region,
        mappings,
        str(stream_arn or ""),
        warnings,
    )
    signals = _stream_lambda_readiness_signals(stream, mappings, permission_checks)
    return {
        "table_name": table["table_name"],
        "table_arn": table["table_arn"],
        "region": resolved_region,
        "stream": stream,
        "lambda_mappings": mappings,
        "permission_checks": permission_checks,
        "summary": _stream_lambda_readiness_summary(signals),
        "signals": signals,
        "suggested_next_checks": _stream_lambda_readiness_next_checks(signals),
        "warnings": warnings,
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


def _lambda_mappings_for_stream(
    runtime: AwsRuntime,
    region: str,
    stream_arn: str,
    limit: int,
    warnings: list[str],
) -> list[dict[str, Any]]:
    client = runtime.client("lambda", region=region)
    try:
        response = client.list_event_source_mappings(
            EventSourceArn=stream_arn,
            MaxItems=min(limit, 100),
        )
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "lambda.ListEventSourceMappings")))
        return []
    return [
        {
            "uuid": item.get("UUID"),
            "state": item.get("State"),
            "function_arn": item.get("FunctionArn"),
            "function_name": str(item.get("FunctionArn") or "").rsplit(":", 1)[-1],
            "batch_size": item.get("BatchSize"),
            "maximum_batching_window_seconds": item.get("MaximumBatchingWindowInSeconds"),
            "bisect_batch_on_function_error": item.get("BisectBatchOnFunctionError"),
            "function_response_types": item.get("FunctionResponseTypes", []),
            "starting_position": item.get("StartingPosition"),
            "maximum_retry_attempts": item.get("MaximumRetryAttempts"),
            "maximum_record_age_seconds": item.get("MaximumRecordAgeInSeconds"),
            "destination_config": item.get("DestinationConfig") or {},
        }
        for item in response.get("EventSourceMappings", [])[:limit]
    ]


def _stream_lambda_permission_checks(
    runtime: AwsRuntime,
    region: str,
    mappings: list[dict[str, Any]],
    stream_arn: str,
    warnings: list[str],
) -> dict[str, Any]:
    checks = []
    for mapping in mappings:
        role_arn = _lambda_role_arn(
            runtime,
            region,
            str(mapping.get("function_arn") or ""),
            warnings,
        )
        for action in [
            "dynamodb:DescribeStream",
            "dynamodb:GetRecords",
            "dynamodb:GetShardIterator",
            "dynamodb:ListStreams",
        ]:
            checks.append(
                _simulate_stream_permission(
                    runtime,
                    role_arn,
                    action,
                    stream_arn,
                    str(mapping.get("uuid") or ""),
                    warnings,
                )
            )
    return {
        "enabled": True,
        "checked_count": len(checks),
        "checks": checks,
        "summary": {
            "allowed": sum(1 for check in checks if check.get("allowed") is True),
            "denied": sum(1 for check in checks if check.get("allowed") is False),
            "unknown": sum(1 for check in checks if check.get("allowed") is None),
        },
    }


def _lambda_role_arn(
    runtime: AwsRuntime,
    region: str,
    function_name: str,
    warnings: list[str],
) -> str | None:
    if not function_name:
        return None
    client = runtime.client("lambda", region=region)
    try:
        response = client.get_function_configuration(FunctionName=function_name)
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "lambda.GetFunctionConfiguration")))
        return None
    role = response.get("Role")
    return str(role) if role else None


def _simulate_stream_permission(
    runtime: AwsRuntime,
    role_arn: str | None,
    action: str,
    stream_arn: str,
    mapping_uuid: str,
    warnings: list[str],
) -> dict[str, Any]:
    if not role_arn:
        return {
            "mapping_uuid": mapping_uuid,
            "principal_arn": None,
            "action": action,
            "resource_arn": stream_arn,
            "allowed": None,
            "decision": "unknown",
        }
    iam = runtime.client("iam", region=runtime.region)
    try:
        response = iam.simulate_principal_policy(
            PolicySourceArn=role_arn,
            ActionNames=[action],
            ResourceArns=[stream_arn],
        )
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "iam.SimulatePrincipalPolicy")))
        return {
            "mapping_uuid": mapping_uuid,
            "principal_arn": role_arn,
            "action": action,
            "resource_arn": stream_arn,
            "allowed": None,
            "decision": "unknown",
        }
    result = (response.get("EvaluationResults") or [{}])[0]
    decision = str(result.get("EvalDecision") or "unknown")
    return {
        "mapping_uuid": mapping_uuid,
        "principal_arn": role_arn,
        "action": action,
        "resource_arn": stream_arn,
        "allowed": decision == "allowed",
        "decision": decision,
    }


def _stream_lambda_readiness_signals(
    stream: Any,
    mappings: list[dict[str, Any]],
    permission_checks: dict[str, Any],
) -> dict[str, Any]:
    stream_enabled = bool(stream.get("enabled")) if isinstance(stream, dict) else False
    risks = []
    if not stream_enabled:
        risks.append("stream_not_enabled")
    if stream_enabled and not mappings:
        risks.append("stream_enabled_without_lambda_mapping")
    if any(str(mapping.get("state") or "").lower() != "enabled" for mapping in mappings):
        risks.append("event_source_mapping_not_enabled")
    if any(not mapping.get("bisect_batch_on_function_error") for mapping in mappings):
        risks.append("bisect_batch_not_enabled")
    if any(
        "ReportBatchItemFailures" not in mapping.get("function_response_types", [])
        for mapping in mappings
    ):
        risks.append("partial_batch_response_not_enabled")
    if any(not mapping.get("destination_config") for mapping in mappings):
        risks.append("failure_destination_not_configured")
    if permission_checks.get("summary", {}).get("denied"):
        risks.append("stream_read_permission_denied")
    if permission_checks.get("summary", {}).get("unknown"):
        risks.append("stream_read_permission_unknown")
    return {
        "stream_enabled": stream_enabled,
        "mapping_count": len(mappings),
        "enabled_mapping_count": sum(
            1 for mapping in mappings if str(mapping.get("state") or "").lower() == "enabled"
        ),
        "risk_count": len(risks),
        "risks": sorted(set(risks)),
    }


def _stream_lambda_readiness_summary(signals: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "needs_attention" if signals["risk_count"] else "ready",
        "mapping_count": signals["mapping_count"],
        "risk_count": signals["risk_count"],
        "risks": signals["risks"],
    }


def _stream_lambda_readiness_next_checks(signals: dict[str, Any]) -> list[str]:
    checks = []
    if "stream_not_enabled" in signals["risks"]:
        checks.append("Enable DynamoDB Streams before configuring Lambda consumption.")
    if "stream_enabled_without_lambda_mapping" in signals["risks"]:
        checks.append("Create or repair a Lambda event source mapping for the stream.")
    if "stream_read_permission_denied" in signals["risks"]:
        checks.append("Grant the Lambda role DynamoDB stream read actions.")
    if "partial_batch_response_not_enabled" in signals["risks"]:
        checks.append("Consider ReportBatchItemFailures for stream batch processing.")
    if not checks:
        checks.append("No DynamoDB stream-to-Lambda readiness blocker found.")
    return checks


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
