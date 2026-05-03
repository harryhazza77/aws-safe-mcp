# Contributing

Thanks for helping improve `aws-safe-mcp`.

This project aims to be a small, safe, opinionated MCP server for AWS
investigation. The most valuable contributions preserve that shape: fewer,
richer tools that help AI clients reason about AWS systems without exposing a
raw AWS SDK escape hatch.

## Design Principles

- Keep v1 read-only.
- Do not add a generic `aws_call(service, operation, params)` tool.
- Prefer opinionated investigation tools over one-to-one SDK wrappers.
- Use AWS IAM as the resource authorization boundary.
- Keep account allowlisting in place to prevent wrong-account use.
- Never return secret values, environment values, credentials, or private keys.
- Return concise summaries instead of huge AWS JSON responses.
- Bound pagination, time windows, result counts, and string lengths.
- Audit every tool call with redaction.

## Development Setup

Install `uv`, then run:

```bash
uv sync
uv run aws-safe-mcp --help
```

Run the full local check suite before opening a pull request:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run bandit -q -r src
uv run pip-audit
uv run pytest --cov=aws_safe_mcp --cov-report=term-missing
uv build
```

## Local AWS Testing

Use a development AWS account and a read-only role or profile. The server should
also behave well when AWS credentials are missing or expired, so avoid adding
startup checks that require live AWS authentication.

Use a minimal config similar to:

```yaml
allowed_account_ids:
  - "123456789012"

readonly: true

redaction:
  redact_environment_values: true
  redact_secret_like_keys: true
  max_string_length: 2000
```

## Adding Tools

Before adding a new tool, ask whether it gives the AI client a higher-level
answer than the AWS SDK already provides. Good tools usually:

- Combine `list` and `describe` style AWS metadata.
- Explain dependencies, permissions, failure modes, or likely next checks.
- Hide AWS implementation detail from junior developers and non-specialists.
- Return bounded, redacted, structured summaries.

New tools should include:

- Typed implementation code.
- Unit tests with stubbed AWS clients.
- Guardrail tests for redaction, limits, and missing permissions where relevant.
- README documentation and an example prompt if the tool changes user workflow.

## Pull Request Checklist

- No write-capable AWS operation was added.
- No raw SDK passthrough was added.
- Tool outputs are concise, bounded, and redacted.
- Missing or expired AWS credentials do not prevent server startup.
- Account allowlist enforcement remains intact for AWS resource calls.
- `uv run ruff format --check .` passes.
- `uv run ruff check .` passes.
- `uv run mypy` passes.
- `uv run bandit -q -r src` passes.
- `uv run pip-audit` passes.
- `uv run pytest --cov=aws_safe_mcp --cov-report=term-missing` passes.
- `uv build` passes.
