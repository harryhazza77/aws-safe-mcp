from __future__ import annotations

import argparse
import os
import sys

from aws_safe_mcp.audit import configure_logging
from aws_safe_mcp.auth import AwsAuthError, AwsRuntime
from aws_safe_mcp.config import ConfigError, load_config
from aws_safe_mcp.server import create_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-safe-mcp",
        description="Read-only MCP server for safe AWS investigation.",
    )
    parser.add_argument("--config", default=os.environ.get("AWS_SAFE_MCP_CONFIG"))
    parser.add_argument("--profile", default=os.environ.get("AWS_PROFILE"))
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
    )
    parser.add_argument(
        "--readonly",
        action="store_true",
        help="Required in v1; write tools are not available.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.config:
        parser.error("--config is required, or set AWS_SAFE_MCP_CONFIG")
    if not args.region:
        parser.error("--region is required, or set AWS_REGION/AWS_DEFAULT_REGION")
    if not args.readonly:
        parser.error("--readonly is required in v1")

    try:
        config = load_config(args.config)
        if not config.readonly:
            raise ConfigError("readonly must be true in v1")
        runtime = AwsRuntime(config=config, profile=args.profile, region=args.region)
        server = create_server(runtime)
        server.run(transport="stdio")
    except (ConfigError, AwsAuthError) as exc:
        print(f"aws-safe-mcp: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
