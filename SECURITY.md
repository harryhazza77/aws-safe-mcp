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

## Safe Disclosure Guidance

When reporting, include:

- The package version or commit SHA.
- The tool name and sanitized input that triggered the issue.
- A short description of the expected and actual behavior.
- Sanitized output showing the problem.

Do not include live AWS credentials, full secret values, private customer data,
or complete production log dumps.

## Project Safety Boundaries

Version 1 intentionally does not include:

- Write-capable AWS tools.
- A generic `aws_call` or raw SDK passthrough.
- S3 object body reads.
- DynamoDB item reads, scans, or queries.
- Secret Manager or SSM Parameter value reads.
- Full Lambda environment variable values.
