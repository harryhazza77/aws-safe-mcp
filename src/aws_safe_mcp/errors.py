from __future__ import annotations

import re

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.redaction import REDACTED, SECRET_KEYWORDS, truncate_string


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


# AWS access key IDs: AKIA / ASIA / AGPA / AROA / AIDA / ANPA / ANVA / ASCA
# followed by 16 uppercase alphanumeric chars.
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|AGPA|AROA|AIDA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b")
# Long base64-ish runs (>= 32 chars) typical of secret access keys, session
# tokens, and bearer tokens. Conservative length floor keeps false positives
# rare (most non-secret tokens like ARNs use `:` separators that are not in
# the character class).
_LONG_OPAQUE_TOKEN_RE = re.compile(r"\b[A-Za-z0-9/+=_-]{32,}\b")
# Match a `<key>=<value>` or `<key>:<value>` pair where `<key>` contains one
# of the secret keywords. Mirrors `redaction.redact_text` so error messages
# enforce the same boundary as tool outputs.
_KEYWORD_VALUE_RE = re.compile(
    r"(?i)([A-Z0-9_.-]*(?:" + "|".join(re.escape(k) for k in SECRET_KEYWORDS) + r")[A-Z0-9_.-]*)"
    r"(\s*[=:]\s*)\S+"
)


def _safe_error_message(message: str) -> str:
    redacted = _KEYWORD_VALUE_RE.sub(rf"\1\2{REDACTED}", message)
    redacted = _AWS_ACCESS_KEY_RE.sub(REDACTED, redacted)
    redacted = _LONG_OPAQUE_TOKEN_RE.sub(REDACTED, redacted)
    return truncate_string(redacted, 500)
