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

1. **Application dependency graph exporter** _(Large)_
    - For an application prefix, assemble a redacted graph across discovered
      API Gateway, EventBridge, Step Functions, Lambda, SQS, SNS, DynamoDB, S3,
      CloudWatch Logs, IAM roles, and KMS.
    - Return nodes, edges, confidence, and unresolved hints using the existing
      dependency graph contract without raw policies or secret values.

2. **First-blocked-edge incident runner** _(Large)_
    - Given a seed resource and symptom, run relevant existing diagnostics in a
      bounded sequence and stop at the first blocked or unknown high-confidence
      edge.
    - Output checked, blocked, unknown, and next safest tool without invoking
      workloads or performing mutating actions.

3. **Resource policy condition mismatch analyzer** _(Large)_
    - Normalize source ARN/account/region condition checks across Lambda, SQS,
      SNS, S3 notifications, EventBridge targets, and KMS service principals.
    - Flag wildcard overreach, missing source constraints, and mismatched source
      conditions without returning full resource policies.

4. **Multi-region drift and failover readiness audit** _(Large)_
    - Compare discovered resources and dependency hints across configured
      regions for missing peers, region-encoded env var drift, endpoint override
      drift, and KMS/multi-region key mismatch.
    - Remain read-only with no failover actions, resource creation, or payload
      reads.

5. **Queue/DLQ replay readiness analyzer** _(Large)_
    - For SQS DLQs and Lambda/EventBridge failure destinations, inspect redrive
      policy, source queue mapping, consumer presence, retention, KMS hints, and
      approximate age/depth.
    - Explain whether replay is likely safe and what edge must be checked first
      without reading or replaying messages.

6. **Application health narrative generator** _(XLarge)_
    - Combine dependency graph, risk scores, alarm gaps, retry topology,
      callability proofs, network reachability, and recent failure signals into
      a concise incident-ready narrative.
    - Output executive summary, ranked risks, evidence, and exact follow-up
      tools without returning raw policy documents, payloads, or secret values.

## Suggested Order

Use the feature candidate order above.
