# Cursor Setup

See [AI client notes](ai-clients.md) for provider-neutral live smoke prompts and
expected behavior across MCP clients.

## Config file location

Cursor stores MCP server configuration in either:

- Global: `~/.cursor/mcp.json`
- Per-project: `<project>/.cursor/mcp.json`

Both files use the same `mcpServers` JSON shape as Claude Desktop.

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

Reload Cursor after editing the file (Command Palette → "Reload Window").

## Running from a local checkout

While iterating on a checkout, prefer the `uv --directory` form in the
`command`/`args` instead of `uvx --from`:

```bash
uv --directory /path/to/aws-sdk-mcp run aws-safe-mcp \
  --profile dev \
  --region eu-west-2 \
  --readonly \
  --config ~/.config/aws-safe-mcp/config.yaml
```

For package-mode testing, use:

```bash
uvx --from /path/to/aws-sdk-mcp aws-safe-mcp \
  --profile dev \
  --region eu-west-2 \
  --readonly \
  --config ~/.config/aws-safe-mcp/config.yaml
```

See [authentication.md](authentication.md) and
[troubleshooting.md](troubleshooting.md).
