# Limitations

`aws-safe-mcp` is designed to make AWS investigation safer for AI clients, not
to replace AWS IAM, CloudTrail, service consoles, or human review. The server
returns bounded, redacted summaries from read-only AWS APIs.

## Best-Effort Graphs

Dependency tools infer relationships from visible metadata. They can map common
serverless paths such as API Gateway to Lambda, EventBridge to targets, Step
Functions to task resources, and Lambda to execution-role hints.

They may miss relationships that are only visible in application code, dynamic
configuration, opaque payloads, external systems, or IAM policy documents that
the caller cannot read. Treat graph output as a strong starting point, not a
complete source of truth.

## IAM And Policy Checks

Permission checks are diagnostic helpers. They use read-only APIs such as IAM
simulation or resource-policy reads where available.

Results can be:

- `allowed`: the checked path appears to be allowed for the modeled action and
  resource.
- `not_found` or denied: the tool did not find the expected allow path, or IAM
  simulation reported a deny.
- `unknown`: the tool could not verify the path because permissions, policy
  shape, missing context, or service limitations prevented a confident answer.

IAM decisions can depend on condition keys, session policies, permission
boundaries, service control policies, resource policies, tags, request context,
and runtime values. When the answer matters operationally, verify with AWS IAM
tools, CloudTrail, and the target service.

For the per-tool list of AWS read actions a caller must hold (and which ones
are optional), see [iam-per-tool.md](iam-per-tool.md).

## Visibility Follows The Active Credentials

The server does not maintain its own resource allowlist beyond the mandatory AWS
account allowlist. AWS IAM decides which resources are visible. If a role cannot
list a service, read a resource policy, or call an IAM simulation API, the tool
should return partial results, warnings, or `unknown` checks instead of guessing.

This also means empty lists can be valid. They may mean no matching resources
exist, or that the active identity cannot see them.

## Logs And Sensitive Data

Log tools clamp time windows and result counts, compact messages, redact
secret-like key/value fragments, and truncate long strings. They do not fetch S3
objects, DynamoDB items, Secrets Manager secret values, SSM parameter values, or
KMS plaintext.

Application logs can still contain sensitive business context, identifiers, or
values that do not look like obvious secrets. Use non-production accounts for
live smoke testing and avoid broad log searches unless you know the log group
and filter pattern are appropriate.

## Freshness And Consistency

AWS APIs can be eventually consistent. Metrics, logs, recently changed
permissions, new resources, and deleted resources may lag. Re-run tools after a
short delay if the output does not match a recent change.

## Scope

Version 1 intentionally excludes write-capable tools, raw SDK passthrough, S3
object reads, DynamoDB item reads/scans/queries, full Lambda environment values,
and secret or parameter value reads.

Future tools should preserve the same shape: read-only AWS calls, bounded
outputs, redaction, account allowlisting, and tests for limits and failure
behavior.
