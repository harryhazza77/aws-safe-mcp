# Tool Catalog

`aws-safe-mcp` exposes curated, read-only tools rather than a generic AWS SDK
passthrough. Tools validate the active AWS identity before resource access,
respect the configured account allowlist, and return bounded, redacted summaries.

## Dependency Tool Contract

The `explain_*_dependencies` tools share a common output shape so AI clients can
reason across Lambda, Step Functions, API Gateway, and EventBridge consistently:

- `resource_type`
- `name`
- `arn` or `id`
- `region`
- `summary`
- `graph_summary`
- `nodes`
- `edges`
- `permission_hints`
- `permission_checks`
- `warnings`

Edges use `from`, `to`, `relationship`, and `target_type`, with service-specific
fields such as `state_name`, `route_key`, or `target_id` when useful.
Permission checks include `enabled`, `checked_count`, `summary`, and `checks`.

## Identity

### `aws_auth_status`

Reports whether the server is authenticated and shows the active AWS account,
principal type, role/user name, session name, profile, region, read-only status,
and a concise message when credentials are missing or expired.

### `aws_identity`

Returns the current AWS account, ARN, user ID, configured profile, configured
region, and read-only status.

## IAM

### `get_iam_role_summary`

Summarizes one IAM role by name or ARN. The result includes trust-policy shape,
attached and inline policy counts/names, service principals, and permission
boundary presence without returning full policy documents.

Inputs:

- `role_name` required, accepts a role name or role ARN
- `region` optional

### `explain_iam_simulation_denial`

Runs IAM policy simulation for one principal, action, and resource, then
summarizes deny results with matched statement metadata, missing context keys,
likely policy layer, and permission-boundary/SCP uncertainty. It does not return
raw trust or permission policy documents.

Inputs:

- `principal_arn` required, IAM role or user ARN
- `action` required, such as `s3:GetObject`
- `resource_arn` required
- `region` optional

## KMS

### `list_kms_keys`

Lists KMS keys with safe metadata such as state, usage, manager, origin, and
creation/deletion timestamps. The tool does not decrypt, generate data keys, or
return key policy documents.

Inputs:

- `region` optional
- `max_results` optional

### `get_kms_key_summary`

Summarizes one KMS key by key ID, alias, or ARN. The result includes metadata,
aliases, rotation status, and key policy name count without returning policy
JSON or cryptographic material.

Inputs:

- `key_id` required
- `region` optional

### `check_kms_dependent_path`

Checks whether an IAM role and optional AWS service principal can use a KMS key
for encrypted service paths. It simulates role permissions for decrypt, encrypt,
and data-key generation, summarizes matching service-principal key-policy
actions, and never returns the key policy document.

Inputs:

- `key_id` required
- `role_arn` required
- `service_principal` optional
- `region` optional

### `find_kms_key_lifecycle_blast_radius`

Finds lifecycle blast-radius risk for one KMS key. It reports disabled,
pending-deletion, or pending-import key state and maps supplied dependent
resource ARN hints to affected services. It never decrypts, generates data
keys, or returns key policy documents.

Inputs:

- `key_id` required
- `dependent_resource_arns` optional
- `region` optional

## Lambda

### `list_lambda_functions`

Lists Lambda functions visible to the active AWS credentials.

Inputs:

- `region` optional
- `name_prefix` optional
- `max_results` optional

### `get_lambda_summary`

Returns a concise Lambda configuration summary. Environment variable values are
never returned; only variable keys are included.

Inputs:

- `function_name` required
- `region` optional

### `get_lambda_event_source_mapping_diagnostics`

Summarizes Lambda event source mappings without reading queue messages or stream
records. The result includes source type, state, batch/window settings, last
processing result, failure destination, filter presence, permission hints, and
bounded IAM simulation checks for the Lambda execution role.

Inputs:

- `function_name` required
- `region` optional
- `max_results` optional
- `include_permission_checks` optional, default `true`
- `max_permission_checks` optional

### `get_lambda_alias_version_summary`

Summarizes Lambda aliases and published versions without fetching code package
contents. The result includes weighted alias routing, published version metadata,
provisioned concurrency presence, and Lambda resource policy hints without
returning the full policy document.

Inputs:

- `function_name` required
- `region` optional
- `max_results` optional

### `investigate_lambda_deployment_drift`

Checks Lambda alias/version deployment drift without fetching code. It compares
current update status, runtime, architecture, environment key set, aliases,
weighted routing, published versions, provisioned concurrency, and `$LATEST`
resource-policy exposure. It does not return environment values, code packages,
or raw policy documents.

Inputs:

- `function_name` required
- `region` optional
- `max_results` optional

### `get_lambda_recent_errors`

Returns recent error-like CloudWatch log events for one Lambda function. The
tool derives `/aws/lambda/{function_name}`, clamps time/result limits,
truncates messages, and groups similar failures.

Inputs:

- `function_name` required
- `since_minutes` optional, default `60`
- `region` optional
- `max_events` optional, default `50`

### `investigate_lambda_failure`

Combines Lambda configuration, recent CloudWatch metrics, and recent grouped
error logs into a diagnostic summary with suggested next checks. The diagnostic
also includes best-effort alias and event source mapping summaries.

Inputs:

- `function_name` required
- `since_minutes` optional, default `60`
- `region` optional

### `investigate_lambda_cold_start_init`

Correlates Lambda runtime/package shape, memory, architecture, timeout, VPC
attachment, init duration metrics, and bounded init/error log patterns to
explain cold-start or initialization risks. It does not return payloads,
environment values, or secret values.

Inputs:

- `function_name` required
- `since_minutes` optional, default `60`
- `region` optional

### `investigate_lambda_timeout_root_cause`

Combines timeout configuration, max duration metric, recent timeout/error log
groups, dependency hints, network posture, and event source mapping pressure to
classify likely timeout causes. It does not read payloads or secret values.

Inputs:

- `function_name` required
- `since_minutes` optional, default `60`
- `region` optional

### `audit_async_lambda_failure_path`

Audits where asynchronously invoked Lambda events go when invocation fails. The
tool summarizes async retry settings, maximum event age, on-failure/on-success
destinations, Lambda DLQ fallback, reserved concurrency, recent throttle
metrics, retry topology nodes/edges, and suggested next checks.

Inputs:

- `function_name` required
- `region` optional

### `investigate_lambda_concurrency_bottlenecks`

Correlates reserved concurrency, recent throttle/invocation metrics, and event
source mapping state to flag likely Lambda delivery bottlenecks.

Inputs:

- `function_name` required
- `region` optional

### `explain_lambda_dependencies`

Maps one Lambda into a compact dependency graph. It combines configuration,
execution role metadata, CloudWatch log group expectations, VPC attachment,
dead-letter targets, aliases, event source mappings, permission hints, and
inferred IAM simulation checks. It does not return IAM policy documents or
secret values. Environment dependency hints classify redacted values by shape
such as ARN, SQS queue URL, URL, or literal name, and expose only metadata such
as likely service, region, partition, account ID, and confidence.

Inputs:

- `function_name` required
- `region` optional
- `include_permission_checks` optional, default `true`
- `max_permission_checks` optional

### `explain_lambda_network_access`

Traces inferred internet and private network reachability for one Lambda from
static AWS configuration. For VPC Lambdas, it inspects Lambda VPC config,
subnets, security groups, route tables, network ACLs, and VPC endpoints. For
non-VPC Lambdas, it reports AWS-managed runtime networking. The result uses the
contract in [Lambda network access contract](lambda-network-access.md). When
`target_url` is supplied, the tool classifies that URL as public internet,
private DNS/network, or AWS service endpoint and maps it to the inferred egress
posture. It also reports redacted URL-like environment targets by key only and
summarizes inferred AWS API reachability through VPC endpoints, private DNS,
endpoint policy presence, endpoint security groups, or public egress fallback.
DNS risk output highlights private-DNS URL targets and interface endpoints with
private DNS disabled.

This tool reports network-layer possibility, not proof that function code
actually calls a destination.

Inputs:

- `function_name` required
- `region` optional
- `target_url` optional

### `simulate_lambda_security_group_path`

Simulates whether a Lambda's security groups allow egress to a target CIDR and
port. When a target security group is supplied, the tool also checks whether
that group allows ingress from the Lambda subnet CIDRs on the same port.

Inputs:

- `function_name` required
- `target_cidr` required
- `target_port` required
- `target_security_group_id` optional
- `region` optional

### `check_lambda_permission_path`

Checks whether one Lambda execution role appears allowed to perform one IAM
action on one AWS resource ARN. Uses IAM policy simulation when available. If
simulation is unavailable, the tool returns `decision: unknown` with warnings.

Inputs:

- `function_name` required
- `action` required, for example `dynamodb:PutItem`
- `resource_arn` required
- `region` optional

### `check_lambda_to_sqs_sendability`

Checks whether one Lambda appears able to send messages to one SQS queue. The
tool combines Lambda execution-role IAM simulation, queue policy inspection,
region/account comparison, FIFO hints, and KMS encryption hints. It does not
send messages or read queue messages.

Inputs:

- `function_name` required
- `queue_url` required
- `region` optional

### `prove_lambda_invocation_path`

Checks a suspected Lambda invocation path end to end. The proof covers function
existence, source ARN region/account alignment, event-source mapping evidence,
Lambda resource policy matching, source condition keys, and caller IAM policy
simulation when the caller is an IAM principal. It does not invoke the function
or return full policy documents.

Inputs:

- `function_name` required
- `caller_principal` required, as a service principal or AWS ARN
- `source_arn` optional
- `region` optional

### `analyze_cross_account_lambda_invocation`

Wraps Lambda invocation proof with cross-account findings for caller principal,
source ARN, and Lambda account drift. It highlights proof blockers without
returning policy documents.

Inputs:

- `function_name` required
- `caller_principal` required, as a service principal or AWS ARN
- `source_arn` optional
- `region` optional

## Step Functions

### `list_step_functions`

Lists Step Functions state machines visible to the active AWS credentials.

Inputs:

- `region` optional
- `name_prefix` optional
- `max_results` optional

### `get_step_function_execution_summary`

Returns one Step Functions execution summary. Input and output are redacted,
truncated, and returned as strings rather than raw blobs. Execution ARN account
must match config.

Inputs:

- `execution_arn` required
- `region` optional

### `investigate_step_function_failure`

Diagnoses one execution using execution status, failed history event,
error/cause text, previous event context, the failed ASL state definition,
retry/catch shape, likely downstream target, and suggested next checks.

Inputs:

- `execution_arn` required
- `region` optional

### `audit_step_function_retry_catch_safety`

Audits one state machine's task retry/catch coverage without returning the full
ASL definition. It summarizes per-task retry/catch counts, terminal Fail
states, external integrations missing catches, and high-risk no-retry tasks. It
does not return execution payloads or secret values.

Inputs:

- `state_machine_arn` required
- `region` optional

### `explain_step_function_dependencies`

Maps one state machine into a compact dependency graph. It parses ASL, extracts
Task state targets such as Lambda, SNS, SQS, DynamoDB, ECS, Batch, and nested
Step Functions, summarizes the execution role, returns a lightweight flow
summary, and runs inferred IAM simulation checks where possible. It also returns
task-level permission proof with per-state target, retry/catch counts, checked
actions, and blocked states. The full state machine definition is not returned.

Inputs:

- `state_machine_arn` required
- `region` optional
- `include_permission_checks` optional, default `true`
- `max_permission_checks` optional

## S3

### `list_s3_buckets`

Lists S3 bucket names and creation dates visible to the active AWS credentials.
Object contents are never fetched.

Inputs:

- `max_results` optional

### `list_s3_objects`

Lists object metadata in one S3 bucket. Object contents are never fetched.

Inputs:

- `bucket` required
- `prefix` optional
- `max_keys` optional, default `50`
- `region` optional

### `get_s3_bucket_summary`

Summarizes one S3 bucket using metadata APIs only. Includes bucket location,
versioning, encryption, public access block, lifecycle rule counts, access
logging, and notification configuration counts.

Inputs:

- `bucket` required
- `region` optional

### `check_s3_notification_destination_readiness`

Checks S3 notification destinations for Lambda, SQS, and SNS readiness. It
summarizes destination ARNs, event names, filter rules, and destination policy
trust for `s3.amazonaws.com`. It does not read objects, return object bodies, or
return bucket/resource policy documents verbatim.

Inputs:

- `bucket` required
- `region` optional

## DynamoDB

### `list_dynamodb_tables`

Lists DynamoDB table names visible to the active AWS credentials. No scan,
query, or item read is performed.

Inputs:

- `region` optional
- `name_prefix` optional
- `max_results` optional

### `dynamodb_table_summary`

Summarizes one DynamoDB table using metadata APIs only. No scan, query, or item
read is performed.

Inputs:

- `table_name` required
- `region` optional

### `check_dynamodb_stream_lambda_readiness`

Checks whether a DynamoDB stream appears ready for Lambda consumption. It
summarizes stream status, Lambda event source mapping state, batch/window
settings, bisect and partial batch support, starting position, retry age,
failure destination, and simulated role permissions. It does not read stream
records, DynamoDB items, or raw IAM policy documents.

Inputs:

- `table_name` required
- `region` optional
- `max_results` optional

## ECS

### `list_ecs_clusters`

Lists ECS clusters by ARN and name.

Inputs:

- `region` optional
- `max_results` optional

### `list_ecs_services`

Lists ECS services in one cluster by ARN and name.

Inputs:

- `cluster` required
- `region` optional
- `max_results` optional

### `get_ecs_service_summary`

Summarizes one ECS service and its task definition with desired/running counts,
deployment state, task and execution roles, containers, log groups, and load
balancer wiring. Container environment values and secret values are not returned.

Inputs:

- `cluster` required
- `service` required
- `region` optional

## SQS

### `list_sqs_queues`

Lists SQS queue URLs visible to the active AWS credentials. It does not receive
messages.

Inputs:

- `region` optional
- `name_prefix` optional
- `max_results` optional

### `get_sqs_queue_summary`

Summarizes one SQS queue using metadata APIs only. Includes queue ARN, timing
attributes, approximate message counts, DLQ/redrive configuration, encryption
shape, and queue policy statement count. It does not receive messages or return
message bodies.

Inputs:

- `queue_url` required
- `region` optional

### `explain_sqs_queue_dependencies`

Maps one SQS queue into the shared dependency graph shape. It summarizes
redrive/DLQ relationships, EventBridge rules that target the queue, Lambda event
source mappings that poll it, and likely producer/consumer permission needs. It
does not receive messages or return message bodies.

Inputs:

- `queue_url` required
- `region` optional
- `include_permission_checks` optional, default `true`
- `max_permission_checks` optional

### `check_sqs_to_lambda_delivery`

Checks whether an SQS queue appears ready to deliver messages to Lambda event
source mappings. The result includes mapping state, Lambda timeout vs queue
visibility timeout, batch partial-failure response, redrive policy, scaling
configuration, failure destination hints, and suggested next checks. It does
not receive messages.

Inputs:

- `queue_url` required
- `region` optional
- `max_results` optional

### `investigate_sqs_backlog_stall`

Correlates SQS backlog signals with Lambda event source mappings and recent
Lambda throttles. The result includes approximate queue depth and oldest-message
age, mapping state, visibility-timeout fit, DLQ/redrive and partial-batch
signals, the first likely bottleneck, and suggested next checks. It does not
receive messages or return message bodies.

Inputs:

- `queue_url` required
- `region` optional
- `max_results` optional

## SNS

### `list_sns_topics`

Lists SNS topics visible to the active AWS credentials. It does not publish
messages.

Inputs:

- `region` optional
- `name_prefix` optional
- `max_results` optional

### `get_sns_topic_summary`

Summarizes one SNS topic using metadata APIs only. Includes display name,
encryption shape, delivery-policy presence, topic policy statement count, and
bounded subscription summaries. HTTP endpoints only return scheme, host, and
whether a path exists; email and unknown endpoint types are redacted.

Inputs:

- `topic_arn` required
- `region` optional
- `max_subscriptions` optional

### `explain_sns_topic_dependencies`

Maps one SNS topic into the shared dependency graph shape. It summarizes
subscriptions, downstream Lambda/SQS/HTTP targets, subscription DLQs where
visible, and likely delivery permission needs. It checks Lambda resource
policies and SQS queue policies where those metadata APIs are readable. It does
not publish messages.

Inputs:

- `topic_arn` required
- `region` optional
- `include_permission_checks` optional, default `true`
- `max_permission_checks` optional

### `audit_sns_fanout_delivery_readiness`

Audits SNS fanout delivery readiness for one topic. It summarizes subscriptions,
protocol mix, subscription DLQs, encrypted-topic KMS hints, pending
confirmations, and downstream Lambda/SQS policy trust. It does not publish
messages or return raw topic policies.

Inputs:

- `topic_arn` required
- `region` optional
- `max_results` optional

## CloudWatch Alarms

### `list_cloudwatch_alarms`

Lists CloudWatch metric and composite alarms with state, action counts, metric
shape, dimensions, and inferred linked resource hints for supported namespaces.

Inputs:

- `region` optional
- `name_prefix` optional
- `max_results` optional

### `get_cloudwatch_alarm_summary`

Summarizes one CloudWatch alarm by name, including likely linked Lambda, API
Gateway, Step Functions, SQS, or EventBridge resources when dimensions identify
them.

Inputs:

- `alarm_name` required
- `region` optional

### `find_cloudwatch_alarm_coverage_gaps`

Checks expected alarm coverage for one Lambda, SQS queue, EventBridge rule, or
API Gateway route. It reports covered and missing metrics, existing alarms with
disabled or missing actions, and suggested metric dimensions. It does not create
or update alarms.

Inputs:

- `resource_type` required, one of `lambda`, `sqs`, `eventbridge_rule`,
  `apigateway_route`
- `resource_name` required
- `region` optional
- `max_results` optional

## CloudWatch Logs

### `list_cloudwatch_log_groups`

Lists CloudWatch log groups visible to the active AWS credentials.

Inputs:

- `region` optional
- `name_prefix` optional
- `max_results` optional

### `cloudwatch_log_search`

Searches one CloudWatch log group with bounded `filter_log_events`. Results are
truncated and returned as concise event summaries.

Inputs:

- `log_group_name` required
- `query` required, CloudWatch Logs filter pattern
- `since_minutes` optional, default `60`
- `max_results` optional, default `50`
- `region` optional

### `cloudwatch_logs_insights_query`

Runs a bounded CloudWatch Logs Insights query against one explicitly provided
log group. The tool clamps the time window and result count, rejects broad
`SOURCE` and `unmask` queries, redacts field values, and returns the current
query status plus any immediately available rows.

Inputs:

- `log_group_name` required
- `query` required, Logs Insights query string
- `since_minutes` optional, default `60`
- `max_results` optional, default `50`
- `region` optional

### `check_cloudwatch_logs_writeability`

Checks whether one IAM role appears able to write to one CloudWatch Logs log
group. The result reports whether the log group exists, retention/KMS context,
and IAM simulation decisions for `logs:CreateLogStream` and
`logs:PutLogEvents`.

Inputs:

- `log_group_name` required
- `role_arn` required, IAM role ARN
- `region` optional

## API Gateway

### `list_api_gateways`

Lists API Gateway REST, HTTP, and WebSocket APIs visible to the active AWS
credentials.

Inputs:

- `region` optional
- `name_prefix` optional
- `max_results` optional

### `get_api_gateway_summary`

Summarizes one API Gateway API without invoking it. REST APIs include resource
and method counts; HTTP/WebSocket APIs include route counts.

Inputs:

- `api_id` required
- `api_type` optional, one of `auto`, `rest`, `http`, or `websocket`
- `region` optional

### `get_api_gateway_authorizer_summary`

Summarizes REST and HTTP/WebSocket API authorizers without returning secrets.
Includes authorizer type, identity sources, Lambda authorizer target metadata,
and route-to-authorizer relationships.

Inputs:

- `api_id` required
- `api_type` optional, one of `auto`, `rest`, `http`, or `websocket`
- `region` optional

### `analyze_api_gateway_authorizer_failures`

Analyzes API Gateway authorizer 401/403 risks without invoking the API. It
checks route authorization config, authorizer type, identity sources, Lambda
authorizer resource policy, TTL/cache setting, and recent authorizer Lambda
errors. It does not return raw Lambda policies or request payloads.

Inputs:

- `api_id` required
- `route_key` optional
- `api_type` optional, one of `auto`, `rest`, `http`, or `websocket`
- `region` optional
- `max_events` optional

### `explain_api_gateway_dependencies`

Maps one API Gateway API into route and integration dependencies without
invoking it. The tool supports REST, HTTP, and WebSocket APIs, extracts route to
integration edges, detects Lambda targets, and summarizes whether each target
Lambda resource policy appears to allow `apigateway.amazonaws.com` to invoke it.
Raw Lambda resource policies are not returned.

Inputs:

- `api_id` required
- `api_type` optional, one of `auto`, `rest`, `http`, or `websocket`
- `region` optional

### `investigate_api_gateway_route`

Diagnoses one API Gateway route without invoking it. The tool finds the route,
summarizes its integration, checks Lambda invoke permission when the target is
Lambda, returns safe Lambda configuration metadata, and groups recent Lambda
error log signals. It also returns callability signals and blockers from
integration availability, Lambda resource policy, Lambda state/update status,
timeout, and recent Lambda error count.

Inputs:

- `api_id` required
- `route_key` optional
- `method` optional
- `path` optional
- `api_type` optional, one of `auto`, `rest`, `http`, or `websocket`
- `region` optional
- `max_events` optional

## EventBridge

### `list_eventbridge_rules`

Lists EventBridge rules visible to the active AWS credentials. When no event bus
is provided, the tool discovers event buses first, then returns rules with
target counts and target service types.

Inputs:

- `region` optional
- `event_bus_name` optional, default discovers visible buses
- `name_prefix` optional
- `max_results` optional

### `get_eventbridge_time_sources`

Summarizes time-driven and replay-driven EventBridge sources without publishing
or replaying events. Includes scheduled rules, Scheduler schedules, archives,
and replays where visible.

Inputs:

- `region` optional
- `event_bus_name` optional
- `max_results` optional

### `explain_eventbridge_rule_dependencies`

Maps one EventBridge rule into event bus, target, DLQ, role, and permission
dependencies. It summarizes event patterns safely, detects target service types,
summarizes retry/DLQ configuration, and checks Lambda/SQS/SNS resource policies
or target `RoleArn` permissions where practical. It never publishes events and
does not return raw policies.

Inputs:

- `rule_name` required
- `event_bus_name` optional, default `default`
- `region` optional
- `include_permission_checks` optional, default `true`
- `max_permission_checks` optional

### `investigate_eventbridge_rule_delivery`

Diagnoses one EventBridge rule using configuration, target permissions,
CloudWatch `AWS/Events` metrics, and SQS DLQ metadata where available. It does
not read DLQ messages. Findings are grouped into configuration, permission, and
metric signals and include target-level retry/DLQ context plus a readiness
summary with explicit blockers, cautions, and DLQ coverage.

Inputs:

- `rule_name` required
- `event_bus_name` optional, default `default`
- `region` optional
- `since_minutes` optional, default `60`

### `audit_eventbridge_target_retry_dlq_safety`

Audits one EventBridge rule's target retry policy and DLQ safety. It summarizes
maximum retry attempts, maximum event age, DLQ queue-policy and KMS hints,
failed-invocation and failed-to-DLQ metrics, and likely silent-drop edges. It
does not publish events, read DLQ messages, return raw policies, or return event
payloads.

Inputs:

- `rule_name` required
- `event_bus_name` optional, default `default`
- `region` optional
- `since_minutes` optional, default `60`

### `explain_event_driven_flow`

Stitches EventBridge, Step Functions, and Lambda dependency tools into one
developer-intent view. Use it when you know a workload name, event source,
detail type, or JSON path from producer code, but do not know the EventBridge
rule name. It returns diagnostic findings, flow paths, downstream hints, safe
resource candidate matches, IAM simulation against the Lambda execution role,
and graph fields.

It never publishes full event payloads, reads S3 object contents, receives SQS
messages, reads DynamoDB items, reads secret or parameter values, calls KMS
decrypt/data-key APIs, or publishes SNS/EventBridge events.

Inputs:

- `name_fragment` optional
- `event_source` optional, for example `aws.s3` or `app.orders`
- `detail_type` optional
- `detail_path` optional, for example `detail.bucket.name` or `object.key`
- `detail_value` optional, matched against the configured event pattern value
- `region` optional
- `max_rules` optional, default `10`

## Cross-Service Search

### `diagnose_region_partition_mismatches`

Checks explicit resource references and configured endpoint overrides for
region or partition drift. The tool parses ARNs and AWS-style URLs, including
SQS queue URLs and service endpoint hosts, then reports mismatches against the
expected region and partition without calling resource APIs.

Plain names such as table names or bucket names are reported as unknown because
they do not encode region or partition by themselves.

Inputs:

- `resource_refs` required, list of ARNs, URLs, endpoint hosts, or names
- `expected_region` optional, defaults to `region` or configured runtime region
- `expected_partition` optional, default `aws`
- `region` optional

### `search_aws_resources`

Best-effort name search across safe discovery tools for Lambda, Step Functions,
S3 buckets, DynamoDB tables, CloudWatch log groups, API Gateway APIs, and
EventBridge rules. This is not a raw AWS API passthrough.

Inputs:

- `query` required
- `services` optional list
- `region` optional
- `max_results` optional

### `search_aws_resources_by_tag`

Searches tagged resources with the Resource Groups Tagging API and groups
matches by service and resource type. The result returns bounded ARN metadata
and tag key/value pairs; if the tagging API is unavailable, the warning is
reported without falling back to unverifiable tag guesses.

Inputs:

- `tag_key` required
- `tag_value` optional
- `region` optional
- `max_results` optional

### `get_cross_service_incident_brief`

Builds a compact incident brief from existing safe tools using a resource name
fragment. The result includes matching resources, matching CloudWatch alarms,
bounded Lambda recent-error/dependency context when applicable, and suggested
next checks.

Inputs:

- `query` required
- `region` optional
- `max_matches` optional

### `build_log_signal_correlation_timeline`

Builds a bounded timeline from matching CloudWatch alarms and Lambda recent
error groups using existing safe diagnostic tools. It returns ordered symptoms,
evidence summaries, and a likely first-failure point without payloads, full log
streams, or secret values.

Inputs:

- `query` required
- `region` optional
- `max_matches` optional

### `plan_end_to_end_transaction_trace`

Builds an ordered investigation plan from a seed resource name. It reuses the
cross-service incident brief, orders likely resources across the request path,
and returns probable breakpoints and next checks.

Inputs:

- `seed_resource` required
- `region` optional
- `max_matches` optional

### `get_risk_scored_dependency_health_summary`

Searches resources by application prefix and assigns a bounded risk score based
on service-specific callability and observability follow-up needs.

Inputs:

- `application_prefix` required
- `region` optional
- `max_matches` optional

### `export_application_dependency_graph`

Exports a redacted dependency graph for resources matching an application
prefix. It uses safe discovery results and existing dependency edges where
available, returning nodes, edges, confidence, and unresolved hints without raw
policies or secret values.

Inputs:

- `application_prefix` required
- `region` optional
- `max_matches` optional

### `run_first_blocked_edge_incident`

Runs existing safe diagnostics from a seed resource and symptom, then stops at
the first blocked or unknown high-confidence edge. It returns checked edges,
blocked or unknown status, and the next safest tool without invoking workloads,
reading payloads, or returning raw policies or secret values.

Inputs:

- `seed_resource` required
- `symptom` required
- `region` optional
- `max_matches` optional
