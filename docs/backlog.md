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

1. **Step Functions task permission proof** _(Medium)_
   - Parse redacted ASL task states into service actions and resource hints,
     then check execution role permissions, target resource policies, KMS
     needs, timeout/retry/catch coverage, and recent failed state names.
   - Extend existing Step Functions dependency parsing and IAM simulation with
     richer task-level proof.

2. **KMS-dependent path checker** _(Large)_
   - For SQS, SNS, S3, DynamoDB streams, Lambda env encryption, and logs,
     identify customer-managed KMS keys and check whether the Lambda role and
     AWS service principal have the decrypt/encrypt/data-key permissions needed
     for the specific path.
   - Build beyond current KMS key summaries and service-specific permission
     hints without returning key policies or decrypted data.

3. **Lambda invocation path proof** _(Large)_
    - Given a Lambda function and suspected caller, walk every required edge:
      trigger mapping, Lambda resource policy, caller identity policy, service
      principal, condition keys, KMS dependencies, and region/account checks.
      Explain the first blocked edge.
    - Compose existing Lambda dependency, permission path, event source, API
      Gateway, EventBridge, SQS, and SNS helpers instead of duplicating them.

4. **Lambda VPC outbound URL reachability check** _(Large)_
    - Detect URL-like env vars, classify destination as public internet,
      private DNS, AWS service endpoint, or VPC-local host, then inspect Lambda
      subnets, route tables, NAT gateways, security groups, NACLs, and VPC
      endpoints for likely egress failure.
    - Extend existing Lambda network access output with target-aware URL
      classification.

5. **Private AWS API reachability check** _(Large)_
    - For Lambdas in private subnets using AWS SDK clients, infer needed AWS
      services from code/config hints and verify matching interface/gateway
      endpoints, endpoint policies, private DNS, and security group ingress from
      Lambda ENIs.
    - Build on existing Lambda VPC endpoint discovery and service endpoint
      override awareness.

6. **Security group path simulator for Lambda** _(Large)_
    - Given a Lambda and target host/port from env vars or integration config,
      evaluate Lambda ENI security group egress, target security group ingress,
      NACLs, subnet routes, and endpoint security groups.
    - Deepen existing network access diagnostics from broad egress posture to a
      specific path simulation.

7. **DNS and split-horizon risk detector** _(Large)_
    - For URL env vars and private hosted zone records, inspect VPC DNS
      settings, resolver rules, private hosted zone associations, interface
      endpoint private DNS, and conflicting public/private names.
    - Add DNS-specific reasoning not present in current Lambda network checks.

8. **Concurrency bottleneck investigator** _(Large)_
    - Correlate Lambda reserved/provisioned concurrency, account concurrency,
      event source maximum concurrency, SQS backlog age, throttles, async retry
      age, and downstream service limits to explain delivery stalls.
    - Compose existing Lambda, SQS, CloudWatch metric, and event source
      diagnostics into a capacity-focused workflow.

9. **Cross-account invocation analyzer** _(Large)_
    - When a Lambda references queues, topics, buses, buckets, or functions in
      another account, check both sides of IAM/resource policy trust and flag
      missing principals, source ARN/account conditions, organization
      condition mismatches, KMS gaps, and partition/region drift.
    - Extend current same-account and service-specific permission checks.

10. **Dead-letter and retry topology audit** _(XLarge)_
    - Build a graph of Lambda destinations, SQS redrive policies, SNS/SQS
      DLQs, EventBridge DLQs, and Step Functions catches. Flag loops,
      unconsumed DLQs, too-low max receive counts, and missing alarms.
    - Compose existing DLQ fragments from Lambda, SQS, SNS, EventBridge, Step
      Functions, and CloudWatch alarm tools into one topology audit.

11. **End-to-end transaction trace plan** _(XLarge)_
    - Given a seed resource name, stitch likely path across API Gateway,
      EventBridge, Step Functions, Lambda, SQS, SNS, DynamoDB streams, and logs.
      Return ordered checks, probable breakpoints, and safe commands/tools to
      run next.
    - Extend current event-driven flow stitching and incident brief beyond
      EventBridge-centered paths.

12. **Risk-scored dependency health summary** _(XLarge)_
    - For an application prefix, assemble discovered resources into a redacted
      graph and score each edge for callability, network reachability, policy
      completeness, retry safety, observability, and drift from expected naming
      or region conventions.
    - Compose current name/tag search, incident brief, dependency graphs, alarm
      summaries, and permission checks into an application-level health view.

## Suggested Order

Use the feature candidate order above.
