# Security Policy

`aws-safe-mcp` is designed as a local, read-only MCP server for investigating AWS
resources through the caller's existing AWS credentials. AWS IAM remains the
primary authorization boundary.

## Supported Versions

Security fixes are currently provided for the latest released `0.x` version.
Because the project is pre-1.0, public APIs may still change while the safety
model is being hardened.

## Reporting a Vulnerability

Please report security issues privately using GitHub Security Advisories:

https://github.com/harryhazza77/aws-safe-mcp/security/advisories/new

If GitHub Security Advisories are unavailable, open a GitHub issue with only a
high-level description and avoid including exploit details, credentials, account
IDs, logs containing secrets, or sensitive AWS resource names.

## What Counts As Security Sensitive

Please report issues such as:

- Secret values, environment values, tokens, credentials, or private keys being
  returned by a tool.
- A write-capable AWS operation exposed by the server.
- A way to bypass the read-only mode.
- A raw AWS SDK passthrough being exposed.
- Missing account allowlist enforcement before AWS resource access.
- Audit logs containing unredacted sensitive values.
- Excessively large or unbounded responses that may leak sensitive logs or
  destabilize an MCP client.

See [docs/security/threat-model.md](docs/security/threat-model.md) for the
STRIDE-shaped analysis and
[docs/security/redaction-scope.md](docs/security/redaction-scope.md) for the
concrete per-tool-family redaction blocklist.

## Safe Disclosure Guidance

When reporting, include:

- The package version or commit SHA.
- The tool name and sanitized input that triggered the issue.
- A short description of the expected and actual behavior.
- Sanitized output showing the problem.

Do not include live AWS credentials, full secret values, private customer data,
or complete production log dumps.

## Project Safety Boundaries

The full, canonical project safety rules live in
[docs/standards.md](docs/standards.md).

## Release Safety Audit

Every release must be green on the gates below before tagging. CI runs each
enforcing test on every pull request; the release checklist re-verifies them
manually as a second gate — see
[docs/release-checklist.md](docs/release-checklist.md).

| Gate | Enforcing test or code path | Description |
| --- | --- | --- |
| Read-only invariant | [`tests/test_invariants.py`](tests/test_invariants.py) | Statically rejects any mutating boto3 verb in tool modules and asserts every `@mcp.tool` is wrapped with `@audit.tool`. |
| Redaction invariants | [`tests/test_redaction_properties.py`](tests/test_redaction_properties.py) | Hypothesis property tests pin case-insensitive secret-key detection, env-locked redaction, idempotent text redaction, and recursive shape preservation. |
| Naming convention | [`tests/test_naming_conventions.py`](tests/test_naming_conventions.py) | Enforces approved verb prefixes, `_summary` / `list_*` suffix rules, per-module subject keywords, and unique MCP tool names. |
| Account allowlist | [`src/aws_safe_mcp/auth.py::AwsRuntime._load_and_validate_identity`](src/aws_safe_mcp/auth.py) | Refreshes the STS identity on every `client(...)` and rejects accounts outside `allowed_account_ids`. |
| Test surface | [`tests/test_mcp_smoke.py`](tests/test_mcp_smoke.py) | Pins the exact set of registered MCP tools; accidental drop or addition fails fast. |
