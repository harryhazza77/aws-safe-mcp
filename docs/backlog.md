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

### 1. EventBridge Archive, Replay, And Schedule Awareness

Extend EventBridge tools to summarize archives, replay configuration, Scheduler
schedules, and rule schedule expressions where visible.

- Value: time-driven and replay-driven events are important hidden producers.
- Fixture: scheduled rule or Scheduler schedule, archive if emulator supports
  it.
- Emulator: Floci first.
- Acceptance: no events are published or replayed.

### 2. EventBridge Delivery Diagnostics Upgrade

Improve `investigate_eventbridge_rule_delivery` with better target-specific
metrics, retry/DLQ interpretation, disabled rule detection, and policy mismatch
headlines.

- Value: helps debug dropped or undelivered events.
- Fixture: rule with SQS target, DLQ, and intentionally missing permission
  variant.
- Emulator: Floci.
- Acceptance: diagnostic summary separates configuration, permission, and
  metric signals.

### 3. Lambda Event Source Mapping Diagnostics

Add a focused tool for Lambda event source mappings that summarizes source
type, state, batch/window settings, last processing result, failure destination,
and likely permission checks.

- Value: common source of SQS/DynamoDB/Kinesis Lambda delivery problems.
- Fixture: Lambda with SQS event source mapping.
- Emulator: Floci or MiniStack.
- Acceptance: no queue messages or stream records are read.

### 4. Lambda Alias And Version Summary

Add a Lambda alias/version summary that reports aliases, weighted routing,
published versions, provisioned concurrency presence, and policy hints.

- Value: production Lambda traffic often flows through aliases, not `$LATEST`.
- Fixture: Lambda with aliases and weighted alias where emulator supports it.
- Emulator: MiniStack likely.
- Acceptance: no code package contents are fetched.

### 5. CloudWatch Alarm Inventory And Diagnostics

Add `list_cloudwatch_alarms` and an alarm summary/diagnostic tool for metric
alarms tied to Lambda, API Gateway, Step Functions, SQS, or EventBridge.

- Value: alarms are operational intent and can point directly at symptoms.
- Fixture: alarms for Lambda errors and SQS queue depth.
- Emulator: MiniStack or Floci, depending on CloudWatch alarm support.
- Acceptance: output links alarms to likely resource names/ARNs.

### 6. CloudWatch Logs Insights Query Helper

Add a bounded Logs Insights helper that starts from a known log group and a
safe query template, with strict time/result limits and redaction.

- Value: `filter_log_events` is useful but weak for grouped diagnostics.
- Fixture: seeded Lambda log group events.
- Emulator: MiniStack or Floci if Logs Insights is supported.
- Acceptance: query text and results are bounded; no broad account-wide query.

### 7. Resource Tag Search And Grouping

Add a tag-based safe resource search that uses the Resource Groups Tagging API
where available and falls back to service-specific summaries.

- Value: teams often know tags, not exact resource names.
- Fixture: tagged baseline resources.
- Emulator: Floci or MiniStack.
- Acceptance: output is bounded and grouped by service/resource type.

### 8. IAM Role Summary Tool

Add a read-only IAM role summary for execution roles, including trust policy
shape, attached/inline policy counts, service principals, and permission
boundary presence without returning full policy JSON.

- Value: many dependency tools need role context; a direct tool helps users
  inspect the role safely.
- Existing coverage: Lambda and Step Functions dependency tools include private
  role summaries for their execution roles. This feature should expose a
  generic role summary tool and reuse the same safety shape.
- Fixture: Lambda and Step Functions roles.
- Emulator: Floci and MiniStack.
- Acceptance: full policy documents are not returned.

### 9. KMS Key Metadata Summary

Add KMS key inventory/summary for key state, usage, rotation, aliases, and
policy availability without decrypting or generating data keys.

- Value: encryption configuration appears across S3, SQS, SNS, Lambda, and
  logs.
- Existing coverage: downstream hints can list KMS aliases to match unresolved
  Lambda environment-name hints. There is no public KMS key metadata tool.
- Fixture: customer-managed key attached to one supported resource.
- Emulator: MiniStack or Floci depending on KMS support.
- Acceptance: no cryptographic material or decrypt operations are used.

### 10. ECS Task And Service Summary

Add bounded ECS cluster/service/task definition summaries, focusing on desired
count, deployment state, task role, execution role, containers, log groups, and
load balancer wiring.

- Value: expands beyond serverless while preserving safe metadata inspection.
- Fixture: minimal ECS service if emulator support is sufficient.
- Emulator: MiniStack likely.
- Acceptance: no container env values or secrets are returned.

### 11. Cross-Service Incident Brief

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
6. Lambda event source mapping diagnostics.
7. EventBridge delivery diagnostics upgrade.
8. Cross-service incident brief.
