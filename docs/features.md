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

- `get_aws_auth_status`
- `get_aws_identity`

## IAM Inspection

- Summarize IAM roles by name or ARN without returning full trust or permission
  policy documents.
- Report trust-policy shape, service/AWS/federated principals, attached and
  inline policy counts/names, and permission-boundary presence.
- Explain IAM simulation denies with matched statement metadata, missing
  context keys, and likely policy layer without returning raw policy documents.

Related tools:

- `get_iam_role_summary`
- `explain_iam_simulation_denial`

## KMS Inspection

- List KMS keys with bounded safe metadata, including state, usage, manager,
  origin, and creation/deletion timestamps.
- Summarize one KMS key with aliases, rotation status, and policy name count
  without decrypting, generating data keys, or returning key policy JSON.
- Check whether an IAM role and optional AWS service principal have the KMS
  actions needed for encrypted service paths without returning key policy JSON.
- Find KMS key lifecycle blast radius for disabled or pending-deletion
  customer-managed keys from supplied dependent-resource hints without
  decrypting or returning key policies.

Related tools:

- `list_kms_keys`
- `get_kms_key_summary`
- `check_kms_dependent_path`
- `find_kms_key_lifecycle_blast_radius`

## ECS Inspection

- List ECS clusters and services with bounded metadata.
- Summarize an ECS service and task definition with desired/running counts,
  deployment state, task role, execution role, containers, log groups, and load
  balancer wiring without returning container environment or secret values.

Related tools:

- `list_ecs_clusters`
- `list_ecs_services`
- `get_ecs_service_summary`

## Lambda Investigation

- List visible Lambda functions with concise configuration summaries.
- Summarize one Lambda without returning environment variable values.
- Find recent error-like CloudWatch log events for a Lambda.
- Combine Lambda config, metrics, grouped logs, aliases, and event source
  mappings into a failure investigation.
- Investigate cold-start and init failure signals from runtime/package shape,
  memory, VPC attachment, init duration metrics, and bounded init log patterns.
- Analyze Lambda timeout root causes by combining timeout config, max duration
  metrics, recent timeout log fingerprints, dependency hints, VPC/network
  posture, and event source batch pressure.
- Audit async Lambda failure paths, including retry age/attempt settings,
  on-failure destinations, DLQ fallback, reserved concurrency, and recent
  throttles, plus a retry topology graph of Lambda destinations, DLQ, and event
  source mappings.
- Investigate Lambda concurrency bottlenecks by correlating reserved
  concurrency, recent throttles/invocations, and event source mapping state.
- Map Lambda dependencies such as execution role, log group, VPC attachment,
  dead-letter target, aliases, event source mappings, and inferred permission
  checks.
- Classify redacted Lambda environment dependency values such as ARNs, SQS
  queue URLs, HTTP URLs, literal names, and secret-like keys without returning
  the values themselves.
- Summarize Lambda aliases, weighted traffic routing, published versions,
  provisioned concurrency presence, and resource policy hints without fetching
  code package contents or returning full policy JSON.
- Investigate Lambda deployment drift across aliases, versions, weighted
  routing, update status, runtime/architecture, environment key set,
  provisioned concurrency, and `$LATEST` policy exposure without returning
  environment values or code packages.
- Diagnose Lambda event source mappings with source state, batch/window
  settings, failure destination, filter presence, and inferred role permission
  checks without reading queue messages or stream records.
- Trace inferred Lambda network reachability from static VPC configuration,
  including target-aware URL classification for explicit URLs and redacted
  URL-like environment values.
- Infer AWS API targets from redacted Lambda URL environment hints and report
  whether matching VPC endpoints, private DNS, endpoint policy presence, and
  endpoint security groups make private AWS API access plausible.
- Simulate Lambda security-group paths to a target CIDR and port, including
  Lambda egress and optional target security-group ingress from Lambda subnets.
- Flag DNS risks for private-DNS URL targets and interface VPC endpoints with
  private DNS disabled, without reading DNS records or resolver rules.
- Check whether a Lambda execution role appears allowed to perform a specific
  IAM action on a specific resource ARN.
- Check whether one Lambda appears able to send messages to one SQS queue,
  including execution-role IAM, queue policy, region/account, FIFO, and KMS
  hints.
- Prove a suspected Lambda invocation path by checking trigger evidence,
  Lambda resource policy, optional caller IAM policy, source conditions, and
  region/account alignment.
- Analyze cross-account Lambda invocation paths and flag caller/source account
  drift alongside the invocation proof result.

Related tools:

- `list_lambda_functions`
- `get_lambda_summary`
- `get_lambda_event_source_mapping_diagnostics`
- `get_lambda_alias_version_summary`
- `investigate_lambda_deployment_drift`
- `get_lambda_recent_errors`
- `investigate_lambda_failure`
- `investigate_lambda_cold_start_init`
- `investigate_lambda_timeout_root_cause`
- `audit_async_lambda_failure_path`
- `investigate_lambda_concurrency_bottlenecks`
- `explain_lambda_dependencies`
- `explain_lambda_network_access`
- `simulate_lambda_security_group_path`
- `check_lambda_permission_path`
- `check_lambda_to_sqs_sendability`
- `prove_lambda_invocation_path`
- `analyze_cross_account_lambda_invocation`

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
- Report task-level permission proof with per-state integration, target,
  retry/catch counts, checked actions, and blocked states.
- Audit Step Functions retry/catch safety per task, terminal Fail states, and
  external integrations missing catches without returning full definitions,
  execution payloads, or secret values.

Related tools:

- `list_step_functions`
- `get_step_function_execution_summary`
- `investigate_step_function_failure`
- `audit_step_function_retry_catch_safety`
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
- Analyze API Gateway authorizer 401/403 risks from route auth config,
  authorizer type, identity sources, Lambda authorizer policy, TTL/cache, and
  recent authorizer Lambda errors without invoking the API.
- Report explicit API Gateway-to-Lambda callability signals and blockers from
  integration availability, Lambda resource policy, Lambda state/update status,
  timeout, and recent error count.
- Report route and integration warnings without returning raw Lambda policies.

Related tools:

- `list_api_gateways`
- `get_api_gateway_summary`
- `get_api_gateway_authorizer_summary`
- `analyze_api_gateway_authorizer_failures`
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
- Report EventBridge target delivery readiness with explicit blockers,
  cautions, target DLQ coverage, permission status, failed invocation metrics,
  and DLQ activity.
- Audit EventBridge retry and DLQ loss-safety per target, including retry
  attempts, max event age, DLQ queue-policy/KMS hints, failed-to-DLQ metrics,
  and likely silent-drop edges without raw policies or payloads.
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
- `audit_eventbridge_target_retry_dlq_safety`
- `explain_event_driven_flow`

## Safe Storage And Data-Service Metadata

- List S3 buckets and S3 object metadata without fetching object bodies.
- Summarize S3 bucket location, versioning, encryption, public access block,
  lifecycle, logging, and notification counts.
- Check S3 notification destination readiness for Lambda, SQS, and SNS targets,
  including filter rules and destination policy trust without reading objects or
  returning bucket policies verbatim.
- List DynamoDB table names without scanning, querying, or reading items.
- Summarize DynamoDB table metadata such as billing mode, keys, indexes,
  streams, server-side encryption, and point-in-time recovery.
- Check DynamoDB stream-to-Lambda readiness, including stream status, event
  source mapping settings, partial failure support, failure destinations, and
  role permissions without reading stream records or table items.
- List SQS queues and summarize queue metadata without receiving messages.
- Inspect queue timing attributes, approximate message counts, DLQ/redrive
  configuration, encryption shape, and queue policy statement count.
- Explain SQS queue dependencies, including DLQ/redrive relationships,
  EventBridge producers, Lambda event source consumers, and likely permission
  needs.
- Check SQS-to-Lambda delivery readiness, including event source mapping state,
  Lambda timeout vs queue visibility timeout, batch partial-failure response,
  redrive policy, and scaling/failure destination hints.
- Investigate SQS backlog stalls by correlating queue depth and age, Lambda
  mappings, visibility timeout, DLQ redrive, partial batch response, and Lambda
  throttles without receiving messages.
- Analyze SQS DLQ replay readiness by checking source redrive links, active DLQ
  consumers, retention, KMS hints, and approximate depth without reading or
  replaying messages.
- List SNS topics and summarize topic metadata without publishing messages.
- Inspect SNS display name, encryption shape, delivery-policy presence, topic
  policy statement count, and bounded safe subscription endpoint summaries.
- Explain SNS topic dependencies, including subscriptions, downstream
  Lambda/SQS/HTTP targets, subscription DLQs where visible, and inferred
  delivery permission checks.
- Audit SNS fanout delivery readiness across subscriptions, protocol mix,
  subscription DLQs, encrypted-topic KMS hints, and downstream policy trust
  without publishing messages or returning raw topic policies.

Related tools:

- `list_s3_buckets`
- `list_s3_objects`
- `get_s3_bucket_summary`
- `check_s3_notification_destination_readiness`
- `list_dynamodb_tables`
- `get_dynamodb_table_summary`
- `check_dynamodb_stream_lambda_readiness`
- `list_sqs_queues`
- `get_sqs_queue_summary`
- `explain_sqs_queue_dependencies`
- `check_sqs_to_lambda_delivery`
- `investigate_sqs_backlog_stall`
- `analyze_queue_dlq_replay_readiness`
- `list_sns_topics`
- `get_sns_topic_summary`
- `explain_sns_topic_dependencies`
- `audit_sns_fanout_delivery_readiness`

## Logs And Failure Signals

- List CloudWatch alarms and summarize a named alarm with state, metric shape,
  action counts, and likely linked resources from dimensions.
- Find CloudWatch alarm coverage gaps for Lambda, SQS, EventBridge rules, and
  API Gateway routes, returning suggested metric dimensions without creating
  alarms.
- List CloudWatch log groups by prefix.
- Search one known log group with bounded `filter_log_events`.
- Run bounded Logs Insights queries against one explicit log group with
  clamped windows/results, redaction, and broad-query guards.
- Check whether an IAM role appears able to write to a specific CloudWatch Logs
  log group and report retention/KMS context.
- Compact, truncate, and redact log messages before returning them.
- Group similar Lambda error messages during Lambda failure investigation.

Related tools:

- `list_cloudwatch_alarms`
- `get_cloudwatch_alarm_summary`
- `find_cloudwatch_alarm_coverage_gaps`
- `list_cloudwatch_log_groups`
- `search_cloudwatch_logs`
- `query_cloudwatch_logs_insights`
- `check_cloudwatch_logs_writeability`
- `get_lambda_recent_errors`
- `investigate_lambda_failure`

## Cross-Service Search

- Diagnose region and partition drift across explicit ARNs, AWS URLs, queue
  URLs, endpoint hosts, and configured endpoint overrides.
- Search visible resources by name fragment across supported services.
- Find candidate Lambda functions, Step Functions state machines, S3 buckets,
  DynamoDB tables, CloudWatch log groups, API Gateway APIs, and EventBridge
  rules without using raw AWS API passthrough.
- Search tagged resources with the Resource Groups Tagging API and group matches
  by service and resource type.
- Build a compact incident brief from existing safe tools, including matching
  resources, matching alarms, bounded Lambda error/dependency context, and
  suggested next checks.
- Build a bounded log-signal correlation timeline from matching CloudWatch
  alarms and Lambda error groups, returning ordered symptoms and likely first
  failure point without payloads, full log streams, or secret values.
- Plan an end-to-end transaction trace from a seed resource, ordered across
  API Gateway, EventBridge, Step Functions, Lambda, SQS, DynamoDB, and S3.
- Export a redacted application dependency graph from discovered resources and
  existing dependency edges, including confidence and unresolved hints without
  raw policies or secret values.
- Run a bounded first-blocked-edge incident diagnostic from a seed resource and
  symptom, stopping at the first blocked or unknown edge with a next safe tool.
- Analyze redacted resource-policy source condition summaries for wildcard
  overreach, missing source constraints, and source ARN/account mismatches.
- Audit multi-region drift and failover readiness by comparing discovered
  application resources for missing peers and region-encoded naming drift.
- Generate an incident-ready application health narrative from dependency
  graph, risk score, and recent signal timeline evidence.
- Produce a risk-scored dependency health summary for an application prefix
  using discovered resources and service-specific follow-up risks.

Related tools:

- `diagnose_region_partition_mismatches`
- `search_aws_resources`
- `search_aws_resources_by_tag`
- `get_cross_service_incident_brief`
- `build_log_signal_correlation_timeline`
- `plan_end_to_end_transaction_trace`
- `get_risk_scored_dependency_health_summary`
- `export_application_dependency_graph`
- `run_first_blocked_edge_incident`
- `analyze_resource_policy_condition_mismatches`
- `audit_multi_region_drift_failover_readiness`
- `generate_application_health_narrative`

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
