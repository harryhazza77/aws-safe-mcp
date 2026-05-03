# Development Guide

This guide covers the local workflow for developing `aws-safe-mcp`.

## Setup

Install `uv`, then install the project and development dependencies:

```bash
uv sync --all-groups
```

Check the CLI:

```bash
uv run aws-safe-mcp --help
```

## Daily Checks

Run these before committing:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run bandit -q -r src
uv run pip-audit
uv run pytest --cov=aws_safe_mcp --cov-report=term-missing
uv build
```

To format code:

```bash
uv run ruff format .
```

## Tooling

- Ruff handles linting and formatting.
- Mypy runs in strict mode for package code.
- Pytest runs unit and smoke tests with stubbed AWS clients.
- Bandit scans source code for common Python security issues.
- Pip-audit checks installed dependencies for known vulnerabilities.
- Coverage reports branch coverage and missing lines.

## Code Style

- Prefer typed, small functions with explicit inputs and outputs.
- Keep AWS responses summarized and bounded.
- Avoid returning raw AWS JSON unless it has been deliberately shaped.
- Use concise comments only where the behavior or AWS edge case is not obvious.
- Use docstrings for public tools and non-obvious helpers. Avoid boilerplate
  docstrings that only repeat parameter names.

## Adding A Tool

Before adding a tool, check whether it provides a higher-level answer than the
AWS SDK or CLI already provides. Prefer tools that combine AWS metadata into a
useful investigation result.

New tools should:

- Use read-only AWS SDK calls only.
- Validate AWS identity through the runtime before resource access.
- Keep pagination, result counts, time windows, and string lengths bounded.
- Redact secret-like values.
- Return concise summaries.
- Preserve partial results when optional AWS permissions are missing.
- Include tests for success, missing permissions, pagination, redaction, and
  limit behavior.
- Be registered in `server.py`.
- Be documented in `README.md` when user-facing.

## AWS Authentication During Development

The server must be able to start without valid AWS credentials. Do not add
startup behavior that requires STS or live AWS access.

AWS identity should be checked lazily when a tool needs AWS access. If
credentials are missing or expired, tools should return a clear authentication
error that the AI client can show to the user.

## Documentation Expectations

Documentation should explain safe usage and design intent, not every internal
line of code.

Good places for documentation:

- `README.md` for the project overview, quickstart, and user-facing commands.
- `docs/tools.md` for the full MCP tool catalog.
- `docs/architecture.md` for design decisions and extension direction.
- `docs/release.md` for release safety.
- Docstrings for public tool functions and tricky parsing/inference helpers.
