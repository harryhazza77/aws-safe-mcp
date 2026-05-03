from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.errors import normalize_aws_error


def test_normalize_aws_error_handles_botocore_error() -> None:
    error = normalize_aws_error(BotoCoreError(error_msg="network broke"))

    assert "AWS SDK error" in str(error)


def test_normalize_aws_error_handles_unknown_error() -> None:
    error = normalize_aws_error(RuntimeError("boom"))

    assert str(error) == "AWS request failed: boom"


def test_normalize_aws_error_handles_client_error_without_message() -> None:
    error = normalize_aws_error(ClientError({"Error": {}}, "SomeOperation"))

    assert str(error) == "AWS ClientError: AWS request failed"


def test_normalize_aws_error_includes_operation_context() -> None:
    error = normalize_aws_error(
        ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "ListFunctions",
        ),
        "lambda.ListFunctions",
    )

    assert str(error) == "AWS lambda.ListFunctions AccessDenied: denied"


def test_normalize_aws_error_redacts_and_truncates_message() -> None:
    error = normalize_aws_error(
        ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "bad request token=abc123 password:supersecret " + ("x" * 600),
                }
            },
            "SomeOperation",
        ),
        "service.Operation",
    )

    rendered = str(error)
    assert "abc123" not in rendered
    assert "supersecret" not in rendered
    assert "token=[REDACTED]" in rendered
    assert "password:[REDACTED]" in rendered
    assert "[TRUNCATED]" in rendered
