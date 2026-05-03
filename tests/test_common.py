from __future__ import annotations

import pytest

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import ToolInputError
from aws_safe_mcp.tools.common import (
    clamp_limit,
    clamp_since_minutes,
    parse_step_functions_execution_arn,
    require_bucket_name,
    require_dynamodb_table_name,
    require_lambda_name,
    require_log_group_name,
    require_step_function_name,
    require_step_functions_execution,
)


class FakeRuntime:
    def __init__(self) -> None:
        self.config = AwsSafeConfig(allowed_account_ids=["123456789012"])
        self.region = "eu-west-2"


def test_limit_helpers_reject_non_positive_values() -> None:
    with pytest.raises(ToolInputError, match="max_results must be at least 1"):
        clamp_limit(0, default=50, configured_max=100, label="max_results")
    with pytest.raises(ToolInputError, match="since_minutes must be at least 1"):
        clamp_since_minutes(0, default=60, configured_max=120)


def test_required_name_helpers_reject_blank_values() -> None:
    for helper, message in [
        (require_lambda_name, "function_name is required"),
        (require_log_group_name, "log_group_name is required"),
        (require_bucket_name, "bucket is required"),
        (require_dynamodb_table_name, "table_name is required"),
        (require_step_function_name, "state_machine_name is required"),
    ]:
        with pytest.raises(ToolInputError, match=message):
            helper(" ")


def test_parse_step_functions_execution_arn_rejects_invalid_arn() -> None:
    with pytest.raises(ToolInputError, match="valid Step Functions execution ARN"):
        parse_step_functions_execution_arn("not-an-arn")


def test_step_functions_execution_validation_rejects_wrong_account() -> None:
    with pytest.raises(ToolInputError, match="not allowed"):
        require_step_functions_execution(
            FakeRuntime(),
            "arn:aws:states:eu-west-2:999999999999:execution:flow:run",
        )
