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

### Deep Diagnostic Workflows

Ordered by estimated feature size, smallest first. Each item accounts for the
current public tool surface in `src/aws_safe_mcp/server.py` and
`src/aws_safe_mcp/tools/*`; scopes focus on new diagnostic value beyond existing
single-resource summaries, dependency graphs, and permission checks.

1. **Dead-letter and retry topology audit** _(XLarge)_
    - Build a graph of Lambda destinations, SQS redrive policies, SNS/SQS
      DLQs, EventBridge DLQs, and Step Functions catches. Flag loops,
      unconsumed DLQs, too-low max receive counts, and missing alarms.
    - Compose existing DLQ fragments from Lambda, SQS, SNS, EventBridge, Step
      Functions, and CloudWatch alarm tools into one topology audit.

2. **End-to-end transaction trace plan** _(XLarge)_
    - Given a seed resource name, stitch likely path across API Gateway,
      EventBridge, Step Functions, Lambda, SQS, SNS, DynamoDB streams, and logs.
      Return ordered checks, probable breakpoints, and safe commands/tools to
      run next.
    - Extend current event-driven flow stitching and incident brief beyond
      EventBridge-centered paths.

3. **Risk-scored dependency health summary** _(XLarge)_
    - For an application prefix, assemble discovered resources into a redacted
      graph and score each edge for callability, network reachability, policy
      completeness, retry safety, observability, and drift from expected naming
      or region conventions.
    - Compose current name/tag search, incident brief, dependency graphs, alarm
      summaries, and permission checks into an application-level health view.

## Suggested Order

Use the feature candidate order above.
