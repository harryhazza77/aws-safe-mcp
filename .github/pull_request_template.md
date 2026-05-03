## Summary

- 

## Safety Checklist

- [ ] No write-capable AWS operation was added.
- [ ] No generic AWS SDK passthrough was added.
- [ ] Tool outputs are bounded, concise, and redacted.
- [ ] No credentials, local profile names, account IDs, ARNs, logs, or private
      resource names were committed.
- [ ] Missing or expired AWS credentials do not prevent server startup.
- [ ] Account allowlist enforcement remains intact for AWS resource calls.

## Verification

- [ ] `uv run ruff format --check .`
- [ ] `uv run ruff check .`
- [ ] `uv run mypy`
- [ ] `uv run bandit -q -r src`
- [ ] `uv run pip-audit`
- [ ] `uv run pytest --cov=aws_safe_mcp --cov-report=term-missing`
- [ ] `uv build`
