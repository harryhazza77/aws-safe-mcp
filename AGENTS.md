# Agent Instructions

This file contains coding-agent instructions for working in this repository. It
is not user-facing setup documentation; start with `README.md` for that.

<!-- codebase-memory-mcp:start -->
# Codebase Knowledge Graph (codebase-memory-mcp)

This project uses codebase-memory-mcp to maintain a knowledge graph of the codebase.
ALWAYS prefer MCP graph tools over grep/glob/file-search for code discovery.

## Priority Order

1. `search_graph` - find functions, classes, routes, variables by pattern
2. `trace_path` - trace who calls a function or what it calls
3. `get_code_snippet` - read specific function/class source code
4. `query_graph` - run Cypher queries for complex patterns
5. `get_architecture` - high-level project summary

## When to fall back to grep/glob

- Searching for string literals, error messages, config values
- Searching non-code files (Dockerfiles, shell scripts, configs)
- When MCP tools return insufficient results

## Examples

- Find a handler: `search_graph(name_pattern=".*OrderHandler.*")`
- Who calls it: `trace_path(function_name="OrderHandler", direction="inbound")`
- Read source: `get_code_snippet(qualified_name="pkg/orders.OrderHandler")`
<!-- codebase-memory-mcp:end -->

# Codex Project Workflow

## Release Readiness

Before recommending, tagging, publishing, or otherwise preparing a release, read
`docs/release.md` and follow it as the release runbook.

For a release check, agents should:

- Run the pre-publish repository checks.
- Run the full required verification suite.
- Inspect source and wheel package contents.
- Run the live MCP end-to-end smoke test when local non-production AWS smoke
  settings are available.
- Clearly report every command result and any skipped check before saying the
  release is ready.

## Local Private Notes

If `.codex.local.md` exists, read it at the start of release or live smoke-test
work. It may contain local machine-specific profile names, account IDs, resource
names, or temporary config paths needed for this checkout.

Never commit, quote, paste, summarize with real values, or publish
`.codex.local.md` contents. Public or tracked notes must use placeholders such
as `SMOKE_PROFILE`, `SMOKE_REGION`, `SMOKE_ACCOUNT_ID`, and `SMOKE_CONFIG`.
