from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from aws_safe_mcp.config import RedactionConfig

SECRET_KEYWORDS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "KEY",
    "CREDENTIAL",
    "PRIVATE",
    "AUTH",
)

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"


def is_secret_like_key(key: str) -> bool:
    normalized = key.upper()
    return any(keyword in normalized for keyword in SECRET_KEYWORDS)


def redact_value(key: str, value: Any, config: RedactionConfig) -> Any:
    if config.redact_secret_like_keys and is_secret_like_key(key):
        return REDACTED
    return redact_data(value, config)


def redact_environment(environment: Mapping[str, Any], config: RedactionConfig) -> dict[str, Any]:
    if config.redact_environment_values:
        return {key: REDACTED for key in environment}
    return {key: redact_value(key, value, config) for key, value in environment.items()}


def redact_data(value: Any, config: RedactionConfig) -> Any:
    if isinstance(value, str):
        return truncate_string(value, config.max_string_length)
    if isinstance(value, Mapping):
        return {str(key): redact_value(str(key), nested, config) for key, nested in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact_data(item, config) for item in value]
    return value


def redact_text(value: str, config: RedactionConfig) -> str:
    """Redact secret-like key/value fragments in unstructured text."""

    redacted = value
    if config.redact_secret_like_keys:
        keyword_pattern = "|".join(re.escape(keyword) for keyword in SECRET_KEYWORDS)
        redacted = re.sub(
            rf"(?i)\b([A-Z0-9_.-]*(?:{keyword_pattern})[A-Z0-9_.-]*)(\s*[=:]\s*)\S+",
            rf"\1\2{REDACTED}",
            redacted,
        )
    return truncate_string(redacted, config.max_string_length)


def truncate_string(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    omitted = len(value) - max_length
    return f"{value[:max_length]}...{TRUNCATED} {omitted} chars omitted"
