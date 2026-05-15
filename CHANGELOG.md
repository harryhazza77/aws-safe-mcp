# Changelog

## Unreleased

## 0.2.0 - 2026-05-15

- Added Lambda network access tracing for inferred internet, private network, and VPC endpoint reachability.
- Clarified README positioning alongside the official AWS MCP server.
- Updated the lockfile to use `urllib3` 2.7.0.

## 0.1.0 - 2026-05-03

- Added read-only AWS MCP server with stdio transport.
- Added lazy AWS auth status and identity tools.
- Added IAM-first config with required AWS account allowlist.
- Added Lambda summaries, recent error search, failure investigation, dependency mapping, unresolved dependency hints, and explicit IAM permission checks.
- Added Step Functions listing, execution summaries, failure investigation, dependency mapping, flow summaries, and inferred IAM permission checks.
- Added API Gateway listing, summaries, route dependency mapping, and Lambda invoke policy checks.
- Added S3 bucket/object summaries, DynamoDB table summaries, CloudWatch log group listing, bounded log search, and cross-service resource search.
- Added structured audit logging, redaction, result limits, pagination coverage, MCP smoke tests, and client setup docs.
