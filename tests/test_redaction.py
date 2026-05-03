from __future__ import annotations

from aws_safe_mcp.config import RedactionConfig
from aws_safe_mcp.redaction import REDACTED, is_secret_like_key, redact_data, redact_environment


def test_secret_like_keys_are_detected_case_insensitively() -> None:
    assert is_secret_like_key("apiToken")
    assert is_secret_like_key("private_key")
    assert not is_secret_like_key("ordinary_name")


def test_redact_data_redacts_secret_like_mapping_values() -> None:
    result = redact_data(
        {"token": "abc", "nested": {"password": "def", "name": "worker"}},
        RedactionConfig(max_string_length=100),
    )

    assert result == {"token": REDACTED, "nested": {"password": REDACTED, "name": "worker"}}


def test_redact_environment_hides_all_values_by_default() -> None:
    result = redact_environment({"PUBLIC": "ok", "SECRET": "bad"}, RedactionConfig())

    assert result == {"PUBLIC": REDACTED, "SECRET": REDACTED}


def test_redact_data_truncates_long_strings() -> None:
    result = redact_data({"message": "x" * 150}, RedactionConfig(max_string_length=100))

    assert str(result["message"]).startswith("x" * 100)
    assert "50 chars omitted" in result["message"]
