# Quickstart

From zero to a successful tool call in under five minutes.

## What this is

`aws-safe-mcp` is a local, read-only MCP server that lets an AI client
investigate your AWS account through a small set of bounded, structured tools.
It uses your existing AWS profile, never writes, and never exposes raw SDK
access.

## Prerequisites

- AWS CLI installed and a working profile (IAM user or SSO) you can call from
  your terminal.
- Either `uv` (recommended) or `pipx` installed. `uvx` ships with `uv`.
- An MCP-capable AI client: Claude Code, Claude Desktop, or Cursor.

Confirm your profile works before continuing:

```bash
aws sts get-caller-identity --profile dev
```

If that prints an account ID, you are ready.

## Step 1 — Install

No global install is required. `uvx` fetches and runs the published package on
demand:

```bash
uvx aws-safe-mcp --help
```

That command also serves as a self-test for `uv` and network reachability to
PyPI.

## Step 2 — Create the config

Create the config file at:

- macOS: `~/.config/aws-safe-mcp/config.yaml`
- Linux: `~/.config/aws-safe-mcp/config.yaml`

Contents:

```yaml
allowed_account_ids:
  - "123456789012"

readonly: true
```

Replace `123456789012` with the AWS account ID you want the server to be allowed
to talk to. Calls against any other account ID are refused.

```bash
mkdir -p ~/.config/aws-safe-mcp
$EDITOR ~/.config/aws-safe-mcp/config.yaml
```

## Step 3 — Pick your AI client

- [Claude Code](claude-code.md) — use this if you live in a terminal and want
  `claude mcp add` driven setup.
- [Claude Desktop](claude-desktop.md) — use this if you want a chat UI and a
  JSON-configured MCP server entry.
- [Cursor](cursor.md) — use this if you want MCP tools available inside your
  editor while coding.

Each page has a copy-paste command or JSON block. Use the `uvx aws-safe-mcp`
form with your real profile and region.

## Step 4 — Verify auth

In your AI client, paste:

```text
Check my AWS auth status.
```

The client should call `get_aws_auth_status` and return something shaped like:

```json
{
  "authenticated": true,
  "account_id": "123456789012",
  "arn": "arn:aws:sts::123456789012:assumed-role/...",
  "profile": "dev",
  "region": "eu-west-2"
}
```

If `authenticated` is `false`, run `aws sso login --profile dev` (or
`aws login --profile dev`) in another terminal and ask the same question again.
No server restart needed.

## Step 5 — Your first investigation

Try identity first:

```text
What AWS identity am I using right now?
```

Then list a few Lambda functions:

```text
List Lambda functions with max 5 results.
```

Example output shape:

```json
{
  "functions": [
    {
      "name": "orders-api-handler",
      "runtime": "python3.12",
      "last_modified": "2026-04-30T10:14:22Z"
    }
  ],
  "next_token": null,
  "warnings": []
}
```

If you see a list and an empty `warnings` array, the install is working end to
end.

## If something goes wrong

See [troubleshooting.md](troubleshooting.md) for the common first-run failures
and how to fix them.
