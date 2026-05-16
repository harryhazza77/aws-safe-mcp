# Claude Desktop Setup

See [AI client notes](ai-clients.md) for provider-neutral live smoke prompts and
expected behavior across MCP clients.

## Config file path

Claude Desktop reads MCP server entries from a per-OS JSON file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

The file may need to be created if it does not exist.

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

Restart Claude Desktop after editing this file (Claude Desktop reads MCP servers
only at startup).

See [authentication.md](authentication.md) for the auth flow and
[troubleshooting.md](troubleshooting.md) for common errors.
