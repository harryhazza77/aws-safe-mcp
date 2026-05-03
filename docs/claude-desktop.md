# Claude Desktop Setup

See [AI client notes](ai-clients.md) for provider-neutral live smoke prompts and
expected behavior across MCP clients.

Add an MCP server entry like this:

```json
{
  "mcpServers": {
    "aws": {
      "command": "uvx",
      "args": [
        "--from",
        "/path/to/aws-sdk-mcp",
        "aws-safe-mcp",
        "--profile",
        "dev",
        "--region",
        "eu-west-2",
        "--readonly",
        "--config",
        "~/.config/aws-safe-mcp/config.yaml"
      ]
    }
  }
}
```

Restart Claude Desktop after changing the config. If `aws_auth_status` reports
`authenticated: false`, run the login command for your AWS profile:

```bash
aws login --profile dev
# or:
aws sso login --profile dev
```

The MCP server re-checks STS on the next tool call, so a full app restart is not
normally needed after login.
