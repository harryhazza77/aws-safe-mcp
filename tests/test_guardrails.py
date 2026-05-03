from __future__ import annotations

import pytest

from aws_safe_mcp.config import AwsSafeConfig, ConfigError


def config() -> AwsSafeConfig:
    return AwsSafeConfig(
        allowed_account_ids=["123456789012"],
    )


def test_account_allowlist_is_enforced() -> None:
    with pytest.raises(ConfigError, match="account '999999999999' is not allowed"):
        config().require_account_allowed("999999999999")
