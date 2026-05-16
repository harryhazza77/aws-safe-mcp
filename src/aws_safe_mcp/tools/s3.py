from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import normalize_aws_error
from aws_safe_mcp.tools.common import (
    clamp_limit,
    isoformat,
    require_bucket_name,
    resolve_region,
)


def list_s3_buckets(
    runtime: AwsRuntime,
    max_results: int | None = None,
) -> dict[str, Any]:
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    client = runtime.client("s3", region=runtime.region)

    try:
        response = client.list_buckets()
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "s3.ListBuckets") from exc

    buckets = [_bucket_summary(item) for item in response.get("Buckets", [])[:limit]]
    return {
        "region": runtime.region,
        "region_note": (
            "S3 bucket listing is account-level; region is the configured AWS client region, "
            "not a bucket-location filter."
        ),
        "max_results": limit,
        "count": len(buckets),
        "is_truncated": len(response.get("Buckets", [])) > limit,
        "buckets": buckets,
    }


def list_s3_objects(
    runtime: AwsRuntime,
    bucket: str,
    prefix: str | None = None,
    max_keys: int | None = 50,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_bucket = require_bucket_name(bucket)
    limit = clamp_limit(
        max_keys,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_keys",
    )
    client = runtime.client("s3", region=resolved_region)
    request: dict[str, Any] = {
        "Bucket": required_bucket,
        "MaxKeys": limit,
    }
    if prefix:
        request["Prefix"] = prefix

    try:
        response = client.list_objects_v2(**request)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "s3.ListObjectsV2") from exc

    objects = [_object_summary(item) for item in response.get("Contents", [])[:limit]]
    return {
        "bucket": required_bucket,
        "prefix": prefix,
        "region": resolved_region,
        "max_keys": limit,
        "count": len(objects),
        "is_truncated": bool(response.get("IsTruncated")),
        "objects": objects,
    }


def get_s3_bucket_summary(
    runtime: AwsRuntime,
    bucket: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_bucket = require_bucket_name(bucket)
    client = runtime.client("s3", region=resolved_region)
    warnings: list[str] = []

    return {
        "bucket": required_bucket,
        "region": resolved_region,
        "location": _safe_bucket_call(
            client,
            warnings,
            "s3.GetBucketLocation",
            lambda: _bucket_location_summary(client, required_bucket),
        ),
        "versioning": _safe_bucket_call(
            client,
            warnings,
            "s3.GetBucketVersioning",
            lambda: _bucket_versioning_summary(client, required_bucket),
        ),
        "encryption": _safe_bucket_call(
            client,
            warnings,
            "s3.GetBucketEncryption",
            lambda: _bucket_encryption_summary(client, required_bucket),
        ),
        "public_access_block": _safe_bucket_call(
            client,
            warnings,
            "s3.GetPublicAccessBlock",
            lambda: _bucket_public_access_summary(client, required_bucket),
        ),
        "lifecycle": _safe_bucket_call(
            client,
            warnings,
            "s3.GetBucketLifecycleConfiguration",
            lambda: _bucket_lifecycle_summary(client, required_bucket),
        ),
        "logging": _safe_bucket_call(
            client,
            warnings,
            "s3.GetBucketLogging",
            lambda: _bucket_logging_summary(client, required_bucket),
        ),
        "notifications": _safe_bucket_call(
            client,
            warnings,
            "s3.GetBucketNotificationConfiguration",
            lambda: _bucket_notification_summary(client, required_bucket),
        ),
        "warnings": warnings,
    }


def check_s3_notification_destination_readiness(
    runtime: AwsRuntime,
    bucket: str,
    region: str | None = None,
) -> dict[str, Any]:
    resolved_region = resolve_region(runtime, region)
    required_bucket = require_bucket_name(bucket)
    s3 = runtime.client("s3", region=resolved_region)
    warnings: list[str] = []
    try:
        notifications = s3.get_bucket_notification_configuration(Bucket=required_bucket)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "s3.GetBucketNotificationConfiguration") from exc
    destinations = _s3_notification_destinations(
        runtime,
        resolved_region,
        required_bucket,
        notifications,
        warnings,
    )
    signals = _s3_notification_readiness_signals(destinations)
    return {
        "bucket": required_bucket,
        "region": resolved_region,
        "summary": _s3_notification_readiness_summary(signals),
        "destinations": destinations,
        "signals": signals,
        "suggested_next_checks": _s3_notification_next_checks(signals),
        "warnings": warnings,
    }


def _bucket_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("Name"),
        "creation_date": isoformat(item.get("CreationDate")),
    }


def _safe_bucket_call(
    client: Any,
    warnings: list[str],
    context: str,
    call: Any,
) -> Any:
    try:
        return call()
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, context)))
        return None


def _bucket_location_summary(client: Any, bucket: str) -> dict[str, Any]:
    response = client.get_bucket_location(Bucket=bucket)
    constraint = response.get("LocationConstraint") or "us-east-1"
    return {"location_constraint": constraint}


def _bucket_versioning_summary(client: Any, bucket: str) -> dict[str, Any]:
    response = client.get_bucket_versioning(Bucket=bucket)
    return {
        "status": response.get("Status") or "Off",
        "mfa_delete": response.get("MFADelete"),
    }


def _bucket_encryption_summary(client: Any, bucket: str) -> dict[str, Any]:
    response = client.get_bucket_encryption(Bucket=bucket)
    rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    return {
        "enabled": bool(rules),
        "rules": [
            {
                "algorithm": rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm"),
                "bucket_key_enabled": rule.get("BucketKeyEnabled"),
            }
            for rule in rules
        ],
    }


def _bucket_public_access_summary(client: Any, bucket: str) -> dict[str, Any]:
    response = client.get_public_access_block(Bucket=bucket)
    config = response.get("PublicAccessBlockConfiguration", {})
    return {
        "block_public_acls": config.get("BlockPublicAcls"),
        "ignore_public_acls": config.get("IgnorePublicAcls"),
        "block_public_policy": config.get("BlockPublicPolicy"),
        "restrict_public_buckets": config.get("RestrictPublicBuckets"),
    }


def _bucket_lifecycle_summary(client: Any, bucket: str) -> dict[str, Any]:
    response = client.get_bucket_lifecycle_configuration(Bucket=bucket)
    rules = response.get("Rules", [])
    return {
        "rule_count": len(rules),
        "enabled_rule_count": sum(1 for rule in rules if rule.get("Status") == "Enabled"),
    }


def _bucket_logging_summary(client: Any, bucket: str) -> dict[str, Any]:
    response = client.get_bucket_logging(Bucket=bucket)
    logging = response.get("LoggingEnabled")
    return {
        "enabled": bool(logging),
        "target_bucket": logging.get("TargetBucket") if isinstance(logging, dict) else None,
        "target_prefix": logging.get("TargetPrefix") if isinstance(logging, dict) else None,
    }


def _bucket_notification_summary(client: Any, bucket: str) -> dict[str, Any]:
    response = client.get_bucket_notification_configuration(Bucket=bucket)
    return {
        "lambda_configurations": len(response.get("LambdaFunctionConfigurations", [])),
        "queue_configurations": len(response.get("QueueConfigurations", [])),
        "topic_configurations": len(response.get("TopicConfigurations", [])),
        "event_bridge_enabled": bool(response.get("EventBridgeConfiguration")),
    }


def _s3_notification_destinations(
    runtime: AwsRuntime,
    region: str,
    bucket: str,
    notifications: dict[str, Any],
    warnings: list[str],
) -> list[dict[str, Any]]:
    destinations = []
    for item in notifications.get("LambdaFunctionConfigurations", []):
        arn = item.get("LambdaFunctionArn")
        destinations.append(
            {
                "id": item.get("Id"),
                "destination_type": "lambda",
                "arn": arn,
                "events": item.get("Events", []),
                "filter_rules": _notification_filter_rules(item),
                "policy_decision": _s3_lambda_policy_decision(
                    runtime,
                    region,
                    bucket,
                    str(arn or ""),
                    warnings,
                ),
            }
        )
    for item in notifications.get("QueueConfigurations", []):
        arn = item.get("QueueArn")
        destinations.append(
            {
                "id": item.get("Id"),
                "destination_type": "sqs",
                "arn": arn,
                "events": item.get("Events", []),
                "filter_rules": _notification_filter_rules(item),
                "policy_decision": _s3_sqs_policy_decision(
                    runtime,
                    region,
                    bucket,
                    str(arn or ""),
                    warnings,
                ),
            }
        )
    for item in notifications.get("TopicConfigurations", []):
        arn = item.get("TopicArn")
        destinations.append(
            {
                "id": item.get("Id"),
                "destination_type": "sns",
                "arn": arn,
                "events": item.get("Events", []),
                "filter_rules": _notification_filter_rules(item),
                "policy_decision": _s3_sns_policy_decision(
                    runtime,
                    region,
                    bucket,
                    str(arn or ""),
                    warnings,
                ),
            }
        )
    return destinations


def _notification_filter_rules(item: dict[str, Any]) -> list[dict[str, Any]]:
    rules = (
        (item.get("Filter") or {})
        .get("Key", {})
        .get("FilterRules", [])
    )
    return [{"name": rule.get("Name"), "value": rule.get("Value")} for rule in rules]


def _s3_lambda_policy_decision(
    runtime: AwsRuntime,
    region: str,
    bucket: str,
    function_arn: str,
    warnings: list[str],
) -> str:
    if not function_arn:
        return "unknown"
    client = runtime.client("lambda", region=region)
    try:
        response = client.get_policy(FunctionName=function_arn)
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "lambda.GetPolicy")))
        return "unknown"
    policy = _json_policy(response.get("Policy"))
    return _resource_policy_decision(
        policy,
        "s3.amazonaws.com",
        "lambda:InvokeFunction",
        function_arn,
        f"arn:aws:s3:::{bucket}",
    )


def _s3_sqs_policy_decision(
    runtime: AwsRuntime,
    region: str,
    bucket: str,
    queue_arn: str,
    warnings: list[str],
) -> str:
    queue_url = _queue_url_from_arn(queue_arn)
    if not queue_url:
        return "unknown"
    client = runtime.client("sqs", region=region)
    try:
        response = client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "sqs.GetQueueAttributes")))
        return "unknown"
    policy = _json_policy(response.get("Attributes", {}).get("Policy"))
    return _resource_policy_decision(
        policy,
        "s3.amazonaws.com",
        "sqs:SendMessage",
        queue_arn,
        f"arn:aws:s3:::{bucket}",
    )


def _s3_sns_policy_decision(
    runtime: AwsRuntime,
    region: str,
    bucket: str,
    topic_arn: str,
    warnings: list[str],
) -> str:
    if not topic_arn:
        return "unknown"
    client = runtime.client("sns", region=region)
    try:
        response = client.get_topic_attributes(TopicArn=topic_arn)
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "sns.GetTopicAttributes")))
        return "unknown"
    policy = _json_policy(response.get("Attributes", {}).get("Policy"))
    return _resource_policy_decision(
        policy,
        "s3.amazonaws.com",
        "sns:Publish",
        topic_arn,
        f"arn:aws:s3:::{bucket}",
    )


def _json_policy(value: Any) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _resource_policy_decision(
    policy: dict[str, Any] | None,
    principal_service: str,
    action: str,
    resource_arn: str,
    source_arn: str,
) -> str:
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return "unknown"
    allowed = any(
        _statement_matches(statement, principal_service, action, resource_arn, source_arn)
        for statement in statements
    )
    return "allowed" if allowed else "not_found"


def _statement_matches(
    statement: Any,
    principal_service: str,
    action: str,
    resource_arn: str,
    source_arn: str,
) -> bool:
    if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
        return False
    principals = _string_set((statement.get("Principal") or {}).get("Service"))
    actions = _string_set(statement.get("Action"))
    resources = _string_set(statement.get("Resource"))
    source_values = _condition_values(statement.get("Condition"), "AWS:SourceArn")
    return (
        principal_service in principals
        and (action in actions or "*" in actions)
        and (resource_arn in resources or "*" in resources or not resources)
        and (not source_values or source_arn in source_values)
    )


def _condition_values(condition: Any, key: str) -> set[str]:
    values: set[str] = set()
    if not isinstance(condition, dict):
        return values
    for clause in condition.values():
        if isinstance(clause, dict):
            values.update(_string_set(clause.get(key)))
    return values


def _string_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()


def _queue_url_from_arn(queue_arn: str) -> str | None:
    parts = queue_arn.split(":")
    if len(parts) < 6 or parts[2] != "sqs":
        return None
    return f"https://sqs.{parts[3]}.amazonaws.com/{parts[4]}/{parts[5]}"


def _s3_notification_readiness_signals(destinations: list[dict[str, Any]]) -> dict[str, Any]:
    risks = []
    if not destinations:
        risks.append("no_notification_destinations")
    if any(destination["policy_decision"] == "not_found" for destination in destinations):
        risks.append("destination_policy_not_found")
    if any(destination["policy_decision"] == "unknown" for destination in destinations):
        risks.append("destination_policy_unknown")
    return {
        "destination_count": len(destinations),
        "policy_not_found_count": sum(
            1 for destination in destinations if destination["policy_decision"] == "not_found"
        ),
        "policy_unknown_count": sum(
            1 for destination in destinations if destination["policy_decision"] == "unknown"
        ),
        "risk_count": len(risks),
        "risks": sorted(set(risks)),
    }


def _s3_notification_readiness_summary(signals: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "needs_attention" if signals["risk_count"] else "ready",
        "destination_count": signals["destination_count"],
        "risk_count": signals["risk_count"],
        "risks": signals["risks"],
    }


def _s3_notification_next_checks(signals: dict[str, Any]) -> list[str]:
    checks = []
    if "destination_policy_not_found" in signals["risks"]:
        checks.append("Fix Lambda/SQS/SNS destination policies to trust s3.amazonaws.com.")
    if "destination_policy_unknown" in signals["risks"]:
        checks.append("Inspect destination existence, policy readability, and KMS configuration.")
    if not checks:
        checks.append("No S3 notification destination readiness blocker found.")
    return checks


def _object_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "key": item.get("Key"),
        "size_bytes": item.get("Size"),
        "last_modified": isoformat(item.get("LastModified")),
        "storage_class": item.get("StorageClass"),
        "etag": item.get("ETag"),
    }
