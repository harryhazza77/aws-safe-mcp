# Prompt Catalogue

Copy-paste prompts grouped by symptom. Use these as starting points when
talking to an AI client connected to `aws-safe-mcp`. See [tools.md](tools.md)
for the underlying tool contracts.

## How to use

Paste a prompt into your AI client. Replace placeholders in `<angle brackets>`
with real resource names, ARNs, region codes, or time windows. Each prompt
notes which tool(s) the AI is expected to call so you can verify it picked the
right one. Keep result limits small on production accounts.

## First-session prompts

Auth status:

```text
Check my AWS auth status. Use AWS MCP only.
```

Expected tool: `get_aws_auth_status`.

List functions in this region:

```text
List Lambda functions in <region> with a small result limit. Use AWS MCP only.
```

Expected tool: `list_lambda_functions`.

Who am I:

```text
Show my AWS identity. Use AWS MCP only.
```

Expected tool: `get_aws_identity`.

## Lambda failing intermittently

Bird's-eye summary:

```text
Summarize Lambda <function-name> in <region>. Include recent errors over the last 60 minutes. Use AWS MCP only.
```

Expected tools: `get_lambda_summary`, `get_lambda_recent_errors`.

Deep failure investigation:

```text
Investigate Lambda <function-name> failures over the last 60 minutes. Use AWS MCP only.
```

Expected tool: `investigate_lambda_failure`.

Cold-start specific:

```text
Investigate cold-start and init issues for Lambda <function-name> over the last 60 minutes. Use AWS MCP only.
```

Expected tool: `investigate_lambda_cold_start_init`.

## Lambda timing out

Timeout root cause:

```text
Investigate the timeout root cause for Lambda <function-name> over the last 60 minutes. Use AWS MCP only.
```

Expected tool: `investigate_lambda_timeout_root_cause`.

Network reachability to a specific URL:

```text
Explain network access for Lambda <function-name> with target URL <https://example.com/path>. Use AWS MCP only.
```

Expected tool: `explain_lambda_network_access`.

Concurrency bottleneck:

```text
Investigate concurrency bottlenecks for Lambda <function-name>. Use AWS MCP only.
```

Expected tool: `investigate_lambda_concurrency_bottlenecks`.

## EventBridge rule not firing or not delivering

Investigate delivery:

```text
Investigate EventBridge rule <rule-name> on bus <event-bus-name> over the last 60 minutes. Use AWS MCP only.
```

Expected tool: `investigate_eventbridge_rule_delivery`.

Retry / DLQ audit:

```text
Audit retry and DLQ safety for EventBridge rule <rule-name> on bus <event-bus-name> over the last 60 minutes. Use AWS MCP only.
```

Expected tool: `audit_eventbridge_target_retry_dlq_safety`.

## SQS queue stuck or backlog growing

Backlog stall:

```text
Investigate the SQS backlog stall for queue <queue-url>. Use AWS MCP only.
```

Expected tool: `investigate_sqs_backlog_stall`.

SQS-to-Lambda delivery check:

```text
Check whether SQS queue <queue-url> can deliver to its Lambda consumer. Use AWS MCP only.
```

Expected tool: `check_sqs_to_lambda_delivery`.

DLQ replay readiness:

```text
Analyze DLQ replay readiness for queue <dlq-queue-url>. Source queues: <source-queue-url-1>, <source-queue-url-2>. Use AWS MCP only.
```

Expected tool: `analyze_queue_dlq_replay_readiness`.

## Step Functions execution failed

Execution summary:

```text
Summarize Step Functions execution <execution-arn>. Use AWS MCP only.
```

Expected tool: `get_step_function_execution_summary`.

Failure investigation:

```text
Investigate Step Functions execution failure <execution-arn>. Use AWS MCP only.
```

Expected tool: `investigate_step_function_failure`.

Retry / catch safety audit:

```text
Audit retry and catch safety for state machine <state-machine-arn>. Use AWS MCP only.
```

Expected tool: `audit_step_function_retry_catch_safety`.

## API Gateway 4XX / 5XX

Route investigation:

```text
Investigate API Gateway route <method> <path> on API <api-id>. Use AWS MCP only.
```

Expected tool: `investigate_api_gateway_route`.

Authorizer failure analysis:

```text
Analyze authorizer failures for API <api-id> route <route-key>. Use AWS MCP only.
```

Expected tool: `analyze_api_gateway_authorizer_failures`.

## Cross-service triage

Incident brief:

```text
Build a cross-service incident brief for <resource-name-fragment>. Use AWS MCP only.
```

Expected tool: `get_cross_service_incident_brief`.

First blocked edge:

```text
Run the first-blocked-edge incident diagnostic from seed <resource-name> with symptom "<symptom>". Use AWS MCP only.
```

Expected tool: `run_first_blocked_edge_incident`.

End-to-end transaction trace:

```text
Plan an end-to-end transaction trace from seed <resource-name>. Use AWS MCP only.
```

Expected tool: `plan_end_to_end_transaction_trace`.

Application health narrative:

```text
Generate an application health narrative for prefix <app-prefix>. Use AWS MCP only.
```

Expected tool: `generate_application_health_narrative`.

## Permission denials

Lambda permission path:

```text
Check whether Lambda <function-name> can perform <iam-action> on <resource-arn>. Use AWS MCP only.
```

Expected tool: `check_lambda_permission_path`.

Cross-account invocation:

```text
Analyze cross-account invocation of Lambda <function-name> from caller <caller-principal> with source ARN <source-arn>. Use AWS MCP only.
```

Expected tool: `analyze_cross_account_lambda_invocation`.

IAM simulation denial explainer:

```text
Explain the IAM simulation denial for principal <principal-arn> performing <action> on <resource-arn>. Use AWS MCP only.
```

Expected tool: `explain_iam_simulation_denial`.

## Multi-region and drift

Multi-region drift audit:

```text
Audit multi-region drift and failover readiness for application prefix <app-prefix> across regions <region-1>, <region-2>. Use AWS MCP only.
```

Expected tool: `audit_multi_region_drift_failover_readiness`.

Region / partition mismatch diagnose:

```text
Diagnose region and partition mismatches for: <arn-or-url-1>, <arn-or-url-2>. Expected region: <region>. Use AWS MCP only.
```

Expected tool: `diagnose_region_partition_mismatches`.

## Dependency-graph exploration

Lambda dependencies:

```text
Explain dependencies for Lambda <function-name>. Use AWS MCP only.
```

Expected tool: `explain_lambda_dependencies`.

SQS queue dependencies:

```text
Explain dependencies for SQS queue <queue-url>. Use AWS MCP only.
```

Expected tool: `explain_sqs_queue_dependencies`.

SNS topic dependencies:

```text
Explain dependencies for SNS topic <topic-arn>. Use AWS MCP only.
```

Expected tool: `explain_sns_topic_dependencies`.

EventBridge rule dependencies:

```text
Explain dependencies for EventBridge rule <rule-name> on bus <event-bus-name>. Use AWS MCP only.
```

Expected tool: `explain_eventbridge_rule_dependencies`.

API Gateway dependencies:

```text
Explain dependencies for API Gateway <api-id>. Use AWS MCP only.
```

Expected tool: `explain_api_gateway_dependencies`.

Step Functions dependencies:

```text
Explain dependencies for state machine <state-machine-arn>. Use AWS MCP only.
```

Expected tool: `explain_step_function_dependencies`.
