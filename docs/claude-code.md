# Claude Code Setup

See [AI client notes](ai-clients.md) for provider-neutral live smoke prompts and
expected behavior across MCP clients.

Use local scope while iterating on this checkout:

```bash
claude mcp add --transport stdio --scope local aws-safe-mcp-dev -- \
  uv --directory /path/to/aws-sdk-mcp run aws-safe-mcp \
  --profile dev \
  --region eu-west-2 \
  --readonly \
  --config ~/.config/aws-safe-mcp/config.yaml
```

Use Claude Code's `/mcp` command to inspect status and reconnect after code or
dependency changes.

For package-mode testing:

```bash
claude mcp remove aws-safe-mcp-dev
claude mcp add --transport stdio --scope local aws-safe-mcp-local-package -- \
  uvx --from /path/to/aws-sdk-mcp aws-safe-mcp \
  --profile dev \
  --region eu-west-2 \
  --readonly \
  --config ~/.config/aws-safe-mcp/config.yaml
```

Good first prompts:

- `Call aws_auth_status.`
- `Search AWS resources for "api".`
- `List S3 buckets.`
- `List CloudWatch log groups with max 5 results.`
- `Explain the dependencies for Lambda <function-name>.`
- `Explain the dependencies for Step Function <state-machine-arn>.`
