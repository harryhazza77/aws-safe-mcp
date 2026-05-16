# Features

`aws-safe-mcp` helps AI clients investigate AWS resources without turning into a
raw AWS SDK passthrough. The tools are read-only, bounded, redacted, and scoped
to an explicit AWS account allowlist.

Use this page to find capabilities by user intent. See the
[tool catalog](tools.md) for exact tool names, inputs, and output contracts.

## Authentication And Safety

- Check whether the active AWS credentials are valid.
- See the active account, ARN, principal type, profile, region, and read-only
  status.
- Fail closed when the active account is not in the configured allowlist.
- Re-check STS identity on tool calls after credentials are refreshed.

Related tools:

- `aws_auth_status`
- `aws_identity`

## Lambda Investigation

- List visible Lambda functions with concise configuration summaries.
- Summarize one Lambda without returning environment variable values.
- Find recent error-like CloudWatch log events for a Lambda.
- Combine Lambda config, metrics, grouped logs, aliases, and event source
  mappings into a failure investigation.
- Map Lambda dependencies such as execution role, log group, VPC attachment,
  dead-letter target, aliases, event source mappings, and inferred permission
  checks.
- Summarize Lambda aliases, weighted traffic routing, published versions,
  provisioned concurrency presence, and resource policy hints without fetching
  code package contents or returning full policy JSON.
- Diagnose Lambda event source mappings with source state, batch/window
  settings, failure destination, filter presence, and inferred role permission
  checks without reading queue messages or stream records.
- Trace inferred Lambda network reachability from static VPC configuration.
- Check whether a Lambda execution role appears allowed to perform a specific
  IAM action on a specific resource ARN.

Related tools:

- `list_lambda_functions`
- `get_lambda_summary`
- `get_lambda_event_source_mapping_diagnostics`
- `get_lambda_alias_version_summary`
- `get_lambda_recent_errors`
- `investigate_lambda_failure`
- `explain_lambda_dependencies`
- `explain_lambda_network_access`
- `check_lambda_permission_path`

## Step Functions Investigation

- List visible state machines.
- Summarize one execution with redacted, truncated input and output.
- Diagnose one failed execution using execution history, failed-state context,
  previous event context, retry/catch shape, downstream target linkage,
  error/cause text, and suggested next checks.
- Map a state machine into a dependency graph from its ASL definition without
  returning the full definition.
- Extract task targets for common integrations such as Lambda, SNS, SQS,
  EventBridge PutEvents, DynamoDB, ECS, Batch, and nested Step Functions.
- Summarize execution role metadata and inferred permission checks.

Related tools:

- `list_step_functions`
- `get_step_function_execution_summary`
- `investigate_step_function_failure`
- `explain_step_function_dependencies`

## API Gateway Investigation

- List visible REST, HTTP, and WebSocket APIs.
- Summarize one API without invoking it.
- Summarize API Gateway authorizers, identity sources, attached routes, and
  Lambda authorizer targets without returning secrets.
- Map API Gateway routes and methods to integrations.
- Detect Lambda targets and summarize whether Lambda resource policies appear
  to allow API Gateway invoke.
- Diagnose one route with integration details, Lambda invoke permission, Lambda
  configuration, and recent Lambda error signals.
- Report route and integration warnings without returning raw Lambda policies.

Related tools:

- `list_api_gateways`
- `get_api_gateway_summary`
- `get_api_gateway_authorizer_summary`
- `explain_api_gateway_dependencies`
- `investigate_api_gateway_route`

## EventBridge And Event-Driven Flow

- List EventBridge rules across visible event buses or a specific event bus.
- Summarize rule event patterns safely.
- Summarize scheduled rules, Scheduler schedules, archives, and replays where
  visible.
- Map a rule to targets, DLQs, target roles, and permission checks.
- Diagnose rule delivery using configuration, target permissions, CloudWatch
  metrics, and SQS DLQ metadata where visible.
- Separate delivery findings into configuration, permission, and metric signal
  groups with target-level retry/DLQ context.
- Start from a workload name, event source, detail type, or event-pattern path
  and stitch EventBridge, Step Functions, Lambda dependencies, downstream
  hints, and safe resource candidate matches into one flow view.

Related tools:

- `list_eventbridge_rules`
- `get_eventbridge_time_sources`
- `explain_eventbridge_rule_dependencies`
- `investigate_eventbridge_rule_delivery`
- `explain_event_driven_flow`

## Safe Storage And Data-Service Metadata

- List S3 buckets and S3 object metadata without fetching object bodies.
- Summarize S3 bucket location, versioning, encryption, public access block,
  lifecycle, logging, and notification counts.
- List DynamoDB table names without scanning, querying, or reading items.
- Summarize DynamoDB table metadata such as billing mode, keys, indexes,
  streams, server-side encryption, and point-in-time recovery.
- List SQS queues and summarize queue metadata without receiving messages.
- Inspect queue timing attributes, approximate message counts, DLQ/redrive
  configuration, encryption shape, and queue policy statement count.
- Explain SQS queue dependencies, including DLQ/redrive relationships,
  EventBridge producers, Lambda event source consumers, and likely permission
  needs.
- List SNS topics and summarize topic metadata without publishing messages.
- Inspect SNS display name, encryption shape, delivery-policy presence, topic
  policy statement count, and bounded safe subscription endpoint summaries.
- Explain SNS topic dependencies, including subscriptions, downstream
  Lambda/SQS/HTTP targets, subscription DLQs where visible, and inferred
  delivery permission checks.

Related tools:

- `list_s3_buckets`
- `list_s3_objects`
- `get_s3_bucket_summary`
- `list_dynamodb_tables`
- `dynamodb_table_summary`
- `list_sqs_queues`
- `get_sqs_queue_summary`
- `explain_sqs_queue_dependencies`
- `list_sns_topics`
- `get_sns_topic_summary`
- `explain_sns_topic_dependencies`

## Logs And Failure Signals

- List CloudWatch alarms and summarize a named alarm with state, metric shape,
  action counts, and likely linked resources from dimensions.
- List CloudWatch log groups by prefix.
- Search one known log group with bounded `filter_log_events`.
- Compact, truncate, and redact log messages before returning them.
- Group similar Lambda error messages during Lambda failure investigation.

Related tools:

- `list_cloudwatch_alarms`
- `get_cloudwatch_alarm_summary`
- `list_cloudwatch_log_groups`
- `cloudwatch_log_search`
- `get_lambda_recent_errors`
- `investigate_lambda_failure`

## Cross-Service Search

- Search visible resources by name fragment across supported services.
- Find candidate Lambda functions, Step Functions state machines, S3 buckets,
  DynamoDB tables, CloudWatch log groups, API Gateway APIs, and EventBridge
  rules without using raw AWS API passthrough.

Related tools:

- `search_aws_resources`

## Local Emulator Workflows

The main package can be pointed at local AWS-compatible emulators with
`endpoint_url` in the config file, plus optional `service_endpoint_urls`
overrides. The companion fixture repo at `../aws-sdk-mcp-tf` provides Terraform
scenarios for MiniStack.

Current verified local paths:

- MiniStack on `http://127.0.0.1:4566` for the same baseline plus Step
  Functions fixtures.

The emulator fixture repo is intentionally separate from this Python package so
Terraform scenarios do not accidentally ship to PyPI.
