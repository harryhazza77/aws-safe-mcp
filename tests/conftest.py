"""Shared helpers for moto-based integration tests.

Builds a real ``AwsRuntime`` against a moto mock environment so the tool
modules exercise actual boto3 client shapes (capitalization, pagination
tokens, ARN formats) rather than hand-rolled fakes that can drift.

Account: ``123456789012`` (moto default). Region: ``eu-west-2``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from aws_safe_mcp.auth import AwsRuntime


MOTO_ACCOUNT_ID = "123456789012"
MOTO_REGION = "eu-west-2"


@pytest.fixture
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject dummy AWS credentials so boto3 + moto resolve without a profile."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", MOTO_REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def moto_runtime(aws_credentials: None) -> Iterator[AwsRuntime]:
    """Yield an ``AwsRuntime`` resolved against moto-mocked AWS."""
    from moto import mock_aws

    from aws_safe_mcp.auth import AwsRuntime
    from aws_safe_mcp.config import AwsSafeConfig

    with mock_aws():
        config = AwsSafeConfig(
            allowed_account_ids=[MOTO_ACCOUNT_ID],
            readonly=True,
        )
        runtime = AwsRuntime(config=config, profile=None, region=MOTO_REGION)
        yield runtime


def absent_env(key: str) -> bool:
    return os.environ.get(key) is None
