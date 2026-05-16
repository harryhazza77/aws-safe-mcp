# Backlog

This backlog collects high-value feature ideas for `aws-safe-mcp`. It is a
planning aid, not a commitment to build every item in order.

## Evaluation Rules

Prefer features that:

- Preserve the read-only, bounded, redacted tool model.
- Help developers investigate failures, permissions, and dependencies.
- Reuse the dependency-tool contract where a graph is useful.
- Can be verified against local fixtures in `../aws-sdk-mcp-tf`.
- Work against Floci when practical, and MiniStack when Floci lacks service
  support.

Avoid features that:

- Add raw AWS SDK passthrough.
- Read S3 object bodies, DynamoDB items, secret values, or decrypted KMS data.
- Return full policy documents or full state machine definitions.
- Expand scope without a clear diagnostic workflow.

## Feature Candidates

### 1. Cross-Service Incident Brief

Add an incident-brief tool that accepts a resource name fragment and produces a
compact investigation bundle from existing safe tools: matching resources,
dependency graphs, recent errors, alarms if available, and suggested next
checks.

- Value: this is the "start here" workflow when the user only knows a workload
  name.
- Existing coverage: `search_aws_resources` and `explain_event_driven_flow`
  already provide pieces of this. This feature should compose them into a
  concise, bounded incident entry point.
- Fixture: baseline event-driven workload with Lambda, API Gateway,
  EventBridge, SQS, and DynamoDB.
- Emulator: Floci and MiniStack.
- Acceptance: tool composes existing safe summaries without adding raw reads.

## Existing Feature Cross-Check

This backlog was cross-checked against the current public MCP tool registrations
and tool modules. Existing public tools already cover:

- Identity: `aws_auth_status`, `aws_identity`.
- Runtime configuration: global `endpoint_url` and service-specific endpoint
  overrides.
- Lambda: listing, summary, recent errors, failure investigation, dependency
  graph, network access, and role permission path checks.
- Step Functions: listing, execution summary, failure investigation, dependency
  graph, ASL parsing, role summary, and permission hints/checks.
- S3: bucket listing, object metadata listing, and bucket summary.
- DynamoDB: table listing and table summary.
- SQS: queue listing and queue summary without receiving messages.
- CloudWatch Logs: log group listing and bounded filter search.
- API Gateway: API listing, summary, route/integration dependency graph, and
  Lambda resource-policy checks.
- EventBridge: rule listing, rule dependency graph, delivery investigation, and
  event-driven flow stitching through EventBridge, Step Functions, and Lambda.
- Cross-service search: safe name search across currently supported services.

The backlog items above are therefore biased toward public tools for services
that only have private helper coverage today, or workflow upgrades that compose
existing tools into higher-value diagnostics.

## Suggested Order

1. SQS queue dependency explanation.
2. Step Functions execution diagnostics upgrade.
3. API Gateway route diagnostics.
4. SNS topic inventory and summary.
5. SNS topic dependency explanation.
6. Cross-service incident brief.
