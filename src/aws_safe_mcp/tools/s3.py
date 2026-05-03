from __future__ import annotations

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


def _object_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "key": item.get("Key"),
        "size_bytes": item.get("Size"),
        "last_modified": isoformat(item.get("LastModified")),
        "storage_class": item.get("StorageClass"),
        "etag": item.get("ETag"),
    }
