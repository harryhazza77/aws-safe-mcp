from __future__ import annotations

import os
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.server import create_server


class FakeIdentity:
    account = "123456789012"
    arn = "arn:aws:sts::123456789012:assumed-role/dev/session"
    user_id = "AROATEST:session"
    profile = None
    region = "eu-west-2"
    readonly = True

    def as_dict(self) -> dict[str, str | bool | None]:
        return {
            "account": self.account,
            "arn": self.arn,
            "user_id": self.user_id,
            "profile": self.profile,
            "region": self.region,
            "readonly": self.readonly,
        }


class FakeRuntime:
    def __init__(self) -> None:
        self.config = AwsSafeConfig(allowed_account_ids=["123456789012"])
        self.identity = FakeIdentity()
        self.auth_error = None
        self.profile = None
        self.region = "eu-west-2"

    def refresh_identity(self) -> FakeIdentity:
        return self.identity

    def require_identity(self) -> FakeIdentity:
        return self.identity


@pytest.mark.anyio
async def test_mcp_smoke_lists_tools_and_calls_identity() -> None:
    server = create_server(FakeRuntime())

    tools = await server.list_tools()
    tool_names = {tool.name for tool in tools}
    _, status_result = await server.call_tool("aws_auth_status", {})
    _, identity_result = await server.call_tool("aws_identity", {})

    assert tool_names == {
        "aws_auth_status",
        "aws_identity",
        "list_lambda_functions",
        "get_lambda_summary",
        "get_lambda_recent_errors",
        "investigate_lambda_failure",
        "explain_lambda_dependencies",
        "check_lambda_permission_path",
        "list_step_functions",
        "get_step_function_execution_summary",
        "investigate_step_function_failure",
        "explain_step_function_dependencies",
        "list_s3_buckets",
        "get_s3_bucket_summary",
        "list_s3_objects",
        "list_dynamodb_tables",
        "dynamodb_table_summary",
        "list_cloudwatch_log_groups",
        "cloudwatch_log_search",
        "list_api_gateways",
        "get_api_gateway_summary",
        "explain_api_gateway_dependencies",
        "list_eventbridge_rules",
        "explain_eventbridge_rule_dependencies",
        "investigate_eventbridge_rule_delivery",
        "explain_event_driven_flow",
        "search_aws_resources",
    }
    assert status_result["authenticated"] is True
    assert status_result["principal_type"] == "assumed_role"
    assert status_result["principal_name"] == "dev"
    assert identity_result["account"] == "123456789012"


@pytest.mark.anyio
async def test_mcp_stdio_smoke_starts_when_aws_auth_is_missing(
    tmp_path,
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        """
allowed_account_ids:
  - "123456789012"
readonly: true
""",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    env.pop("AWS_PROFILE", None)
    env.pop("AWS_REGION", None)
    env.pop("AWS_DEFAULT_REGION", None)
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "aws_safe_mcp.main",
            "--config",
            str(config),
            "--profile",
            "missing-profile-for-stdio-smoke",
            "--region",
            "eu-west-2",
            "--readonly",
        ],
        env=env,
    )

    async with (
        stdio_client(params) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()
        result = await session.call_tool("aws_auth_status", {})

    tool_names = {tool.name for tool in tools.tools}
    assert "aws_auth_status" in tool_names
    assert result.structuredContent is not None
    assert result.structuredContent["authenticated"] is False
    assert "missing-profile-for-stdio-smoke" in str(result.structuredContent["message"])
