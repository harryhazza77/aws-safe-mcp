"""Pin that policy summarisers never leak raw AWS policy documents.

The MCP tool surface deliberately summarises IAM / SQS / KMS policy
documents instead of echoing them. Echoing back raw statements would
re-expose sensitive principals, conditions, and resources to the LLM
even when the caller never asked for them. These tests pin the summary
contract for each summariser: only the documented summary keys come out,
and none of the raw policy keys (``Statement`` / ``Effect`` / ``Principal``
/ ``Resource``) survive in the JSON-serialised result.
"""

from __future__ import annotations

import json
from typing import Any

from aws_safe_mcp.tools.iam import _trust_policy_summary
from aws_safe_mcp.tools.kms import _kms_service_principal_check
from aws_safe_mcp.tools.sqs import _policy_summary

RAW_POLICY_KEYS = ("Statement", "Effect", "Principal", "Resource", "Condition", "Sid")


def _assert_no_raw_policy_keys(result: Any) -> None:
    serialised = json.dumps(result)
    for key in RAW_POLICY_KEYS:
        assert f'"{key}"' not in serialised, (
            f"raw policy key {key!r} leaked into summariser output: {serialised}"
        )


# ---------------------------------------------------------------------------
# iam._trust_policy_summary
# ---------------------------------------------------------------------------


EXPECTED_TRUST_KEYS = {
    "statement_count",
    "actions",
    "service_principals",
    "aws_principals",
    "federated_principals",
}


def test_trust_policy_summary_typical_multi_statement() -> None:
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            },
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:oidc-provider/example.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
            },
        ],
    }

    result = _trust_policy_summary(document)

    assert set(result.keys()) == EXPECTED_TRUST_KEYS
    assert result["statement_count"] == 3
    assert result["service_principals"] == ["lambda.amazonaws.com"]
    assert result["aws_principals"] == ["arn:aws:iam::123456789012:root"]
    assert result["federated_principals"] == [
        "arn:aws:iam::123456789012:oidc-provider/example.com"
    ]
    assert "sts:AssumeRole" in result["actions"]
    _assert_no_raw_policy_keys(result)


def test_trust_policy_summary_single_statement_dict_form() -> None:
    document = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"Service": ["ec2.amazonaws.com", "ecs-tasks.amazonaws.com"]},
            "Action": "sts:AssumeRole",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
        },
    }

    result = _trust_policy_summary(document)

    assert set(result.keys()) == EXPECTED_TRUST_KEYS
    # Single-statement dict form is normalised to a one-element list.
    assert result["statement_count"] == 1
    assert result["service_principals"] == [
        "ec2.amazonaws.com",
        "ecs-tasks.amazonaws.com",
    ]
    assert result["actions"] == ["sts:AssumeRole"]
    _assert_no_raw_policy_keys(result)


def test_trust_policy_summary_malformed_or_empty_input() -> None:
    for malformed in (None, "", "not-a-dict", 42, [], {"Statement": "garbage"}):
        result = _trust_policy_summary(malformed)
        assert set(result.keys()) == EXPECTED_TRUST_KEYS
        assert result["statement_count"] == 0
        assert result["actions"] == []
        assert result["service_principals"] == []
        assert result["aws_principals"] == []
        assert result["federated_principals"] == []
        _assert_no_raw_policy_keys(result)


# ---------------------------------------------------------------------------
# sqs._policy_summary
# ---------------------------------------------------------------------------


EXPECTED_SQS_KEYS_OK = {"available", "statement_count"}
EXPECTED_SQS_KEYS_WARN = {"available", "statement_count", "warning"}


def test_sqs_policy_summary_typical_multi_statement() -> None:
    raw = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowSNSPublish",
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": "arn:aws:sqs:eu-west-2:123456789012:queue",
                    "Condition": {
                        "ArnEquals": {
                            "aws:SourceArn": "arn:aws:sns:eu-west-2:123456789012:topic"
                        }
                    },
                },
                {
                    "Sid": "DenyInsecureTransport",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "sqs:*",
                    "Resource": "arn:aws:sqs:eu-west-2:123456789012:queue",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
            ],
        }
    )

    result = _policy_summary(raw)

    assert set(result.keys()) == EXPECTED_SQS_KEYS_OK
    assert result["available"] is True
    assert result["statement_count"] == 2
    _assert_no_raw_policy_keys(result)


def test_sqs_policy_summary_single_statement_dict_form() -> None:
    raw = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sqs:SendMessage",
                "Resource": "arn:aws:sqs:eu-west-2:123456789012:queue",
            },
        }
    )

    result = _policy_summary(raw)

    assert set(result.keys()) == EXPECTED_SQS_KEYS_OK
    assert result["available"] is True
    assert result["statement_count"] == 1
    _assert_no_raw_policy_keys(result)


def test_sqs_policy_summary_malformed_or_empty_input() -> None:
    empty_result = _policy_summary(None)
    assert set(empty_result.keys()) == EXPECTED_SQS_KEYS_OK
    assert empty_result == {"available": False, "statement_count": 0}
    _assert_no_raw_policy_keys(empty_result)

    blank_result = _policy_summary("")
    assert blank_result == {"available": False, "statement_count": 0}
    _assert_no_raw_policy_keys(blank_result)

    bad_json_result = _policy_summary("not-json {{{")
    assert set(bad_json_result.keys()) == EXPECTED_SQS_KEYS_WARN
    assert bad_json_result["available"] is False
    assert bad_json_result["statement_count"] == 0
    assert "JSON" in bad_json_result["warning"]
    _assert_no_raw_policy_keys(bad_json_result)


# ---------------------------------------------------------------------------
# kms._kms_service_principal_check
# ---------------------------------------------------------------------------


class _FakeKmsClient:
    """Minimal stand-in for a KMS client returning a fixed policy body."""

    def __init__(self, policy: Any) -> None:
        self._policy = policy

    def get_key_policy(self, *, KeyId: str, PolicyName: str) -> dict[str, Any]:  # noqa: N803
        if isinstance(self._policy, Exception):
            raise self._policy
        return {"Policy": self._policy}


EXPECTED_KMS_KEYS_OK = {
    "checked",
    "service_principal",
    "policy_readable",
    "allowed_actions",
    "has_required_data_key_access",
}


def test_kms_service_principal_check_typical_multi_statement() -> None:
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableRoot",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowLambdaUse",
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                    "Resource": "*",
                },
                {
                    "Sid": "AllowS3Use",
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
            ],
        }
    )

    warnings: list[str] = []
    result = _kms_service_principal_check(
        client=_FakeKmsClient(policy),
        key_id="abc-key",
        service_principal="lambda.amazonaws.com",
        warnings=warnings,
    )

    assert set(result.keys()) == EXPECTED_KMS_KEYS_OK
    assert result["checked"] is True
    assert result["policy_readable"] is True
    assert result["service_principal"] == "lambda.amazonaws.com"
    assert result["allowed_actions"] == ["kms:Decrypt", "kms:GenerateDataKey"]
    assert result["has_required_data_key_access"] is True
    assert warnings == []
    _assert_no_raw_policy_keys(result)


def test_kms_service_principal_check_single_statement_dict_form() -> None:
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "kms:Decrypt",
                "Resource": "*",
            },
        }
    )

    warnings: list[str] = []
    result = _kms_service_principal_check(
        client=_FakeKmsClient(policy),
        key_id="abc-key",
        service_principal="lambda.amazonaws.com",
        warnings=warnings,
    )

    assert set(result.keys()) == EXPECTED_KMS_KEYS_OK
    assert result["allowed_actions"] == ["kms:Decrypt"]
    assert result["has_required_data_key_access"] is False
    _assert_no_raw_policy_keys(result)


def test_kms_service_principal_check_malformed_or_missing_input() -> None:
    # No service_principal: short-circuits without calling the client.
    skipped = _kms_service_principal_check(
        client=_FakeKmsClient("{}"),
        key_id="abc-key",
        service_principal=None,
        warnings=[],
    )
    assert skipped == {
        "checked": False,
        "service_principal": None,
        "allowed_actions": [],
    }
    _assert_no_raw_policy_keys(skipped)

    # Garbage policy body — _json_object swallows the JSONDecodeError and
    # the summariser returns an empty action list, never the raw body.
    warnings: list[str] = []
    garbage = _kms_service_principal_check(
        client=_FakeKmsClient("not-json {{{"),
        key_id="abc-key",
        service_principal="lambda.amazonaws.com",
        warnings=warnings,
    )
    assert set(garbage.keys()) == EXPECTED_KMS_KEYS_OK
    assert garbage["policy_readable"] is True
    assert garbage["allowed_actions"] == []
    assert garbage["has_required_data_key_access"] is False
    _assert_no_raw_policy_keys(garbage)
