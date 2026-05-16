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

1. **IAM explicit deny explainer** _(Medium)_
   - When IAM simulation returns deny, summarize matched statement metadata,
     missing context keys, permission-boundary/SCP uncertainty, and likely
     policy layer.
   - Do not return raw policy documents, trust policies, or permission
     documents.

2. **Lambda deployment drift investigator** _(Medium)_
   - Compare aliases, versions, weighted routing, last update status, runtime,
     architecture, environment key set, and provisioned concurrency.
   - Flag stale aliases, failed updates, unexpected canary weights, and
     `$LATEST` exposure without returning code packages or environment values.

3. **API Gateway authorizer failure analyzer** _(Medium)_
   - Inspect route auth config, authorizer type, identity sources, Lambda
     authorizer resource policy, TTL/cache settings, and recent authorizer
     Lambda errors.
   - Explain 401/403 risks without invoking the API or returning raw Lambda
     policies.

4. **Step Functions retry/catch safety audit** _(Medium)_
   - Summarize per-task retry/catch coverage, terminal failure states, missing
     catches on external integrations, and high-risk no-retry tasks.
   - Build on existing ASL parsing without returning full state machine
     definitions, execution payloads, or secret values.

5. **DynamoDB stream-to-Lambda readiness check** _(Medium)_
   - Check stream status, Lambda event source mapping, batch/window config,
     bisect/partial failure support, starting position, retry age,
     DLQ/failure destination, and role permissions.
   - Do not read stream records, DynamoDB items, or raw IAM policy documents.

6. **S3 notification-to-destination readiness check** _(Medium)_
   - Inspect bucket notification targets, Lambda/SQS/SNS policies, filter
     rules, destination existence, region/account alignment, and KMS hints.
   - Do not read S3 objects or return bucket policy documents verbatim.

7. **SNS fanout delivery readiness audit** _(Medium)_
   - For one topic, evaluate subscriptions, protocol mix, DLQ coverage, raw
     message delivery, endpoint summaries, topic policy shape, encrypted-topic
     KMS hints, and downstream SQS/Lambda policy trust.
   - Flag weak fanout edges without publishing messages or returning raw topic
     policies.

8. **KMS key lifecycle blast-radius finder** _(Medium)_
    - For customer-managed keys, identify known dependent resources from
      summaries and hints, then flag disabled/pending-deletion keys and affected
      service paths.
    - Never decrypt, generate data keys, or return raw key policies.

9. **Log signal correlation timeline** _(Large)_
    - Build a bounded timeline across CloudWatch alarms, Lambda error groups,
      EventBridge failed invocations, SQS age/backlog, and Step Functions failed
      executions.
    - Return ordered symptoms and likely first-failure point without returning
      payloads, full log streams, or secret values.

10. **Application dependency graph exporter** _(Large)_
    - For an application prefix, assemble a redacted graph across discovered
      API Gateway, EventBridge, Step Functions, Lambda, SQS, SNS, DynamoDB, S3,
      CloudWatch Logs, IAM roles, and KMS.
    - Return nodes, edges, confidence, and unresolved hints using the existing
      dependency graph contract without raw policies or secret values.

11. **First-blocked-edge incident runner** _(Large)_
    - Given a seed resource and symptom, run relevant existing diagnostics in a
      bounded sequence and stop at the first blocked or unknown high-confidence
      edge.
    - Output checked, blocked, unknown, and next safest tool without invoking
      workloads or performing mutating actions.

12. **Resource policy condition mismatch analyzer** _(Large)_
    - Normalize source ARN/account/region condition checks across Lambda, SQS,
      SNS, S3 notifications, EventBridge targets, and KMS service principals.
    - Flag wildcard overreach, missing source constraints, and mismatched source
      conditions without returning full resource policies.

13. **Multi-region drift and failover readiness audit** _(Large)_
    - Compare discovered resources and dependency hints across configured
      regions for missing peers, region-encoded env var drift, endpoint override
      drift, and KMS/multi-region key mismatch.
    - Remain read-only with no failover actions, resource creation, or payload
      reads.

14. **Queue/DLQ replay readiness analyzer** _(Large)_
    - For SQS DLQs and Lambda/EventBridge failure destinations, inspect redrive
      policy, source queue mapping, consumer presence, retention, KMS hints, and
      approximate age/depth.
    - Explain whether replay is likely safe and what edge must be checked first
      without reading or replaying messages.

15. **Application health narrative generator** _(XLarge)_
    - Combine dependency graph, risk scores, alarm gaps, retry topology,
      callability proofs, network reachability, and recent failure signals into
      a concise incident-ready narrative.
    - Output executive summary, ranked risks, evidence, and exact follow-up
      tools without returning raw policy documents, payloads, or secret values.

## Suggested Order

Use the feature candidate order above.
