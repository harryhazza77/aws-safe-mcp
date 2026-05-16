from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import AwsToolError, ToolInputError
from aws_safe_mcp.tools.s3 import (
    check_s3_notification_destination_readiness,
    get_s3_bucket_summary,
    list_s3_buckets,
    list_s3_objects,
)


class FakeS3Client:
    def __init__(self) -> None:
        self.last_request: dict[str, Any] | None = None

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
        self.last_request = kwargs
        return {
            "IsTruncated": False,
            "Contents": [
                {
                    "Key": "logs/a.json",
                    "Size": 123,
                    "LastModified": datetime(2026, 1, 1, tzinfo=UTC),
                    "StorageClass": "STANDARD",
                    "ETag": '"abc"',
                },
                {
                    "Key": "logs/b.json",
                    "Size": 456,
                    "LastModified": datetime(2026, 1, 2, tzinfo=UTC),
                    "StorageClass": "STANDARD",
                    "ETag": '"def"',
                },
            ],
        }

    def list_buckets(self) -> dict[str, Any]:
        return {
            "Buckets": [
                {
                    "Name": "alpha-dev",
                    "CreationDate": datetime(2026, 1, 1, tzinfo=UTC),
                },
                {
                    "Name": "beta-dev",
                    "CreationDate": datetime(2026, 1, 2, tzinfo=UTC),
                },
            ]
        }

    def get_bucket_location(self, **_: Any) -> dict[str, Any]:
        return {"LocationConstraint": "eu-west-2"}

    def get_bucket_versioning(self, **_: Any) -> dict[str, Any]:
        return {"Status": "Enabled"}

    def get_bucket_encryption(self, **_: Any) -> dict[str, Any]:
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                        "BucketKeyEnabled": True,
                    }
                ]
            }
        }

    def get_public_access_block(self, **_: Any) -> dict[str, Any]:
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def get_bucket_lifecycle_configuration(self, **_: Any) -> dict[str, Any]:
        return {"Rules": [{"Status": "Enabled"}, {"Status": "Disabled"}]}

    def get_bucket_logging(self, **_: Any) -> dict[str, Any]:
        return {"LoggingEnabled": {"TargetBucket": "logs", "TargetPrefix": "s3/"}}

    def get_bucket_notification_configuration(self, **_: Any) -> dict[str, Any]:
        return {
            "LambdaFunctionConfigurations": [
                {
                    "Id": "lambda",
                    "LambdaFunctionArn": "arn:aws:lambda:eu-west-2:123456789012:function:fn",
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {"Key": {"FilterRules": [{"Name": "suffix", "Value": ".json"}]}},
                }
            ],
            "QueueConfigurations": [
                {
                    "Id": "queue",
                    "QueueArn": "arn:aws:sqs:eu-west-2:123456789012:bucket-events",
                    "Events": ["s3:ObjectCreated:*"],
                }
            ],
            "EventBridgeConfiguration": {},
        }


class FakeRuntime:
    def __init__(self) -> None:
        self.config = AwsSafeConfig(
            allowed_account_ids=["123456789012"],
            max_results=100,
        )
        self.region = "eu-west-2"
        self.s3_client = FakeS3Client()
        self.lambda_client = FakeLambdaClient()
        self.sqs_client = FakeSqsClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert region == "eu-west-2"
        if service_name == "s3":
            return self.s3_client
        if service_name == "lambda":
            return self.lambda_client
        if service_name == "sqs":
            return self.sqs_client
        raise AssertionError(service_name)


class FakeLambdaClient:
    def get_policy(self, FunctionName: str) -> dict[str, Any]:
        return {
            "Policy": (
                '{"Statement":{"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},'
                '"Action":"lambda:InvokeFunction","Resource":"'
                + FunctionName
                + '","Condition":{"ArnLike":{"AWS:SourceArn":"arn:aws:s3:::allowed-bucket"}}}}'
            )
        }


class FakeSqsClient:
    def get_queue_attributes(self, **_: Any) -> dict[str, Any]:
        return {
            "Attributes": {
                "Policy": (
                    '{"Statement":{"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},'
                    '"Action":"sqs:SendMessage","Resource":"*",'
                    '"Condition":{"ArnLike":{"AWS:SourceArn":"arn:aws:s3:::allowed-bucket"}}}}'
                )
            }
        }


def test_list_s3_buckets_returns_metadata_only() -> None:
    result = list_s3_buckets(FakeRuntime(), max_results=1)

    assert result == {
        "region": "eu-west-2",
        "region_note": (
            "S3 bucket listing is account-level; region is the configured AWS client region, "
            "not a bucket-location filter."
        ),
        "max_results": 1,
        "count": 1,
        "is_truncated": True,
        "buckets": [
            {
                "name": "alpha-dev",
                "creation_date": "2026-01-01T00:00:00+00:00",
            }
        ],
    }


def test_list_s3_objects_returns_metadata_only() -> None:
    runtime = FakeRuntime()

    result = list_s3_objects(runtime, "allowed-bucket", prefix="logs/", max_keys=1)

    assert result["bucket"] == "allowed-bucket"
    assert result["prefix"] == "logs/"
    assert result["max_keys"] == 1
    assert result["count"] == 1
    assert result["objects"][0] == {
        "key": "logs/a.json",
        "size_bytes": 123,
        "last_modified": "2026-01-01T00:00:00+00:00",
        "storage_class": "STANDARD",
        "etag": '"abc"',
    }
    assert runtime.s3_client.last_request == {
        "Bucket": "allowed-bucket",
        "MaxKeys": 1,
        "Prefix": "logs/",
    }


def test_get_s3_bucket_summary_returns_metadata_only() -> None:
    result = get_s3_bucket_summary(FakeRuntime(), "allowed-bucket")

    assert result["bucket"] == "allowed-bucket"
    assert result["location"] == {"location_constraint": "eu-west-2"}
    assert result["versioning"]["status"] == "Enabled"
    assert result["encryption"]["enabled"] is True
    assert result["public_access_block"]["block_public_policy"] is True
    assert result["lifecycle"] == {"rule_count": 2, "enabled_rule_count": 1}
    assert result["logging"]["target_bucket"] == "logs"
    assert result["notifications"]["lambda_configurations"] == 1
    assert result["warnings"] == []


def test_check_s3_notification_destination_readiness_checks_policies() -> None:
    result = check_s3_notification_destination_readiness(FakeRuntime(), "allowed-bucket")

    assert result["summary"] == {
        "status": "ready",
        "destination_count": 2,
        "risk_count": 0,
        "risks": [],
    }
    assert result["destinations"][0]["destination_type"] == "lambda"
    assert result["destinations"][0]["filter_rules"] == [{"name": "suffix", "value": ".json"}]
    assert result["destinations"][0]["policy_decision"] == "allowed"
    assert result["destinations"][1]["policy_decision"] == "allowed"
    assert "Statement" not in str(result)


def test_list_s3_objects_clamps_max_keys_to_configured_limit() -> None:
    runtime = FakeRuntime()
    runtime.config.max_results = 1

    result = list_s3_objects(runtime, "allowed-bucket", max_keys=999)

    assert result["count"] == 1
    assert result["max_keys"] == 1
    assert runtime.s3_client.last_request is not None
    assert runtime.s3_client.last_request["MaxKeys"] == 1


def test_list_s3_objects_rejects_blank_bucket() -> None:
    with pytest.raises(ToolInputError, match="bucket is required"):
        list_s3_objects(FakeRuntime(), " ")


def test_list_s3_objects_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.s3_client = FailingS3Client()

    with pytest.raises(AwsToolError, match="AWS s3.ListObjectsV2 AccessDenied"):
        list_s3_objects(runtime, "bucket")


class FailingS3Client:
    def list_buckets(self) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "ListBuckets",
        )

    def list_objects_v2(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "ListObjectsV2",
        )

    def get_bucket_location(self, **_: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetBucketLocation",
        )

    get_bucket_versioning = get_bucket_location
    get_bucket_encryption = get_bucket_location
    get_public_access_block = get_bucket_location
    get_bucket_lifecycle_configuration = get_bucket_location
    get_bucket_logging = get_bucket_location
    get_bucket_notification_configuration = get_bucket_location


def test_list_s3_buckets_normalizes_aws_errors() -> None:
    runtime = FakeRuntime()
    runtime.s3_client = FailingS3Client()

    with pytest.raises(AwsToolError, match="AWS s3.ListBuckets AccessDenied"):
        list_s3_buckets(runtime)


def test_get_s3_bucket_summary_is_best_effort() -> None:
    runtime = FakeRuntime()
    runtime.s3_client = FailingS3Client()

    result = get_s3_bucket_summary(runtime, "bucket")

    assert result["location"] is None
    assert result["warnings"]
