from __future__ import annotations

import re

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.redaction import truncate_string


class ToolInputError(ValueError):
    """Raised when a tool input violates configured safety rules."""


class AwsToolError(RuntimeError):
    """Raised when AWS returns an error that should be shown concisely to the MCP client."""


def normalize_aws_error(exc: Exception, context: str | None = None) -> AwsToolError:
    prefix = f"AWS {context}" if context else "AWS"
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        code = str(error.get("Code", "ClientError"))
        message = _safe_error_message(str(error.get("Message", "AWS request failed")))
        return AwsToolError(f"{prefix} {code}: {message}")
    if isinstance(exc, BotoCoreError):
        return AwsToolError(f"{prefix} SDK error: {_safe_error_message(str(exc))}")
    return AwsToolError(f"{prefix} request failed: {_safe_error_message(str(exc))}")


def _safe_error_message(message: str) -> str:
    redacted = re.sub(
        r"(?i)\b(secret|token|password|passwd|credential|private|auth|key)(\s*[=:]\s*)\S+",
        r"\1\2[REDACTED]",
        message,
    )
    return truncate_string(redacted, 500)
