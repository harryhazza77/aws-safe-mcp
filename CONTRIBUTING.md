# Contributing

Thanks for helping improve `aws-safe-mcp`.

This project aims to be a small, safe, opinionated MCP server for AWS
investigation. The most valuable contributions preserve that shape: fewer,
richer tools that help AI clients reason about AWS systems without exposing a
raw AWS SDK escape hatch.

## Start Here

- [docs/development.md](docs/development.md) — daily checks, code style.
- [docs/contributing/add-a-tool.md](docs/contributing/add-a-tool.md) — worked
  example of adding a tool.
- [docs/naming-conventions.md](docs/naming-conventions.md) — function and MCP
  tool naming rules.
- [docs/standards.md](docs/standards.md) — non-negotiable safety, feature, and
  release rules.

## Design Principles

Every change must satisfy [docs/standards.md](docs/standards.md). The short
version: keep v1 read-only, prefer opinionated investigation tools over
one-to-one SDK wrappers, keep account allowlisting in place, and never return
secret values, environment values, credentials, or private keys.

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
answer than the AWS SDK already provides. Good tools combine `list` and
`describe` metadata, explain dependencies or failure modes, and return bounded,
redacted, structured summaries.

See [docs/contributing/add-a-tool.md](docs/contributing/add-a-tool.md) for an
end-to-end worked example, and [docs/development.md](docs/development.md) for
the daily verification commands.

## Pull Request Checklist

- [ ] Updated `CHANGELOG.md` under `## [Unreleased]` per [docs/changelog-convention.md](docs/changelog-convention.md).
- [ ] Confirmed `python -m pytest tests/test_invariants.py tests/test_naming_conventions.py tests/test_redaction_properties.py` is green.
- [ ] Decided the version impact per [docs/semver-policy.md](docs/semver-policy.md).
- [ ] Change satisfies [docs/standards.md](docs/standards.md) (no write verbs, no raw SDK passthrough, redaction and allowlist intact).
- [ ] Tool outputs are concise, bounded, and redacted.
- [ ] Missing or expired AWS credentials do not prevent server startup.
- [ ] `uv run ruff format --check .` passes.
- [ ] `uv run ruff check .` passes.
- [ ] `uv run mypy` passes.
- [ ] `uv run bandit -q -r src` passes.
- [ ] `uv run pip-audit` passes.
- [ ] `uv run pytest --cov=aws_safe_mcp --cov-report=term-missing` passes.
- [ ] `uv build` passes.

Review etiquette: keep PRs focused on a single change, one logical commit per
concern, and request review from a maintainer before merging. Only repository
maintainers merge to `main`.
