# Cursor Setup

See [AI client notes](ai-clients.md) for provider-neutral live smoke prompts and
expected behavior across MCP clients.

Configure Cursor to run the server over stdio using the local checkout while
iterating:

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

Use `aws_auth_status` first. If it is not authenticated, refresh the AWS profile
outside Cursor and call `aws_auth_status` again:

```bash
aws login --profile dev
# or:
aws sso login --profile dev
```
