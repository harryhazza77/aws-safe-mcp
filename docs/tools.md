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

### `explain_lambda_dependencies`

Maps one Lambda into a compact dependency graph. It combines configuration,
execution role metadata, CloudWatch log group expectations, VPC attachment,
dead-letter targets, aliases, event source mappings, permission hints, and
inferred IAM simulation checks. It does not return IAM policy documents or
secret values.

Inputs:

- `function_name` required
- `region` optional
- `include_permission_checks` optional, default `true`
- `max_permission_checks` optional

### `check_lambda_permission_path`

Checks whether one Lambda execution role appears allowed to perform one IAM
action on one AWS resource ARN. Uses IAM policy simulation when available. If
simulation is unavailable, the tool returns `decision: unknown` with warnings.

Inputs:

- `function_name` required
- `action` required, for example `dynamodb:PutItem`
- `resource_arn` required
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
error/cause text, and suggested next checks.

Inputs:

- `execution_arn` required
- `region` optional

### `explain_step_function_dependencies`

Maps one state machine into a compact dependency graph. It parses ASL, extracts
Task state targets such as Lambda, SNS, SQS, DynamoDB, ECS, Batch, and nested
Step Functions, summarizes the execution role, returns a lightweight flow
summary, and runs inferred IAM simulation checks where possible. The full state
machine definition is not returned.

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
not read DLQ messages.

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

### `search_aws_resources`

Best-effort name search across safe discovery tools for Lambda, Step Functions,
S3 buckets, DynamoDB tables, CloudWatch log groups, API Gateway APIs, and
EventBridge rules. This is not a raw AWS API passthrough.

Inputs:

- `query` required
- `services` optional list
- `region` optional
- `max_results` optional
