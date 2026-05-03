# Architecture

`aws-safe-mcp` is a local, read-only MCP server for AWS investigation. It is
designed to help AI clients understand AWS systems without giving them an
unbounded AWS SDK shell.

## Core Decisions

### IAM Is The Authorization Boundary

The server uses the caller's existing AWS credentials and lets AWS IAM decide
which resources are visible. The MCP config keeps a mandatory account allowlist
to prevent wrong-account use, but it does not try to duplicate IAM with resource
allowlists.

This keeps setup simple:

- AWS roles and policies remain the source of truth.
- Users do not need to mirror every Lambda, table, bucket, or log group into an
  MCP config file.
- Optional investigation logic can still explain permissions by calling read-only
  IAM simulation APIs where useful.

### No Raw SDK Passthrough

The server intentionally does not expose a tool like:

```text
aws_call(service, operation, params)
```

A raw passthrough would be hard to audit, difficult to make safe, and not much
better than asking the user to run the AWS CLI. Instead, tools are curated,
bounded, and shaped around common developer questions.

### Tools Should Add Judgment

Good tools combine several AWS reads into a concise answer. For example, a
dependency tool can describe a Lambda function, show its execution role, infer
CloudWatch log dependencies, summarize event sources, and run bounded IAM
checks.

The goal is not to copy the AWS SDK. The goal is to give an AI client enough
structured context to answer questions like:

- What is this workload connected to?
- Why might this serverless flow be failing?
- Which permission path looks broken?
- What should I check next?

## Runtime Flow

At startup:

1. CLI flags and config are loaded.
2. Config is validated.
3. The MCP server starts over stdio.
4. AWS authentication is not required at startup.

When an AWS tool is called:

1. The active boto3 session is resolved from profile, region, or environment.
2. STS `GetCallerIdentity` checks the current account and principal.
3. The account ID must match `allowed_account_ids`.
4. The tool runs bounded, read-only AWS SDK calls.
5. Responses are redacted, truncated, summarized, and returned.
6. The call is audit logged to stderr as structured JSON.

This means the server can start when credentials are missing or expired. Users
can authenticate later with `aws login`, `aws sso login`, an assumed-role
profile, or environment credentials, then call `aws_auth_status` or any AWS tool
without restarting the MCP server.

## Main Modules

- `main.py`: CLI parsing and process entrypoint.
- `config.py`: YAML/JSON config loading and validation.
- `auth.py`: boto3 session/runtime handling and STS identity checks.
- `server.py`: FastMCP server construction and tool registration.
- `audit.py`: structured tool call audit logging.
- `redaction.py`: recursive redaction and truncation helpers.
- `errors.py`: safe error formatting.
- `tools/`: service-specific read-only tools.

## Tool Families

The project has three broad kinds of tools:

- Identity and auth tools, such as `aws_auth_status` and `aws_identity`.
- Bounded inventory tools, such as `list_lambda_functions`, `list_s3_buckets`,
  and `list_step_functions`.
- Higher-level investigation tools, such as `investigate_lambda_failure`,
  `explain_lambda_dependencies`, `explain_step_function_dependencies`, and
  `explain_api_gateway_dependencies`, and `explain_eventbridge_rule_dependencies`.

The higher-level tools are where the server should grow most. Prefer fewer,
richer operations over many one-to-one SDK wrappers.

## Dependency Graph Contract

The `explain_*_dependencies` tools share a common output shape:

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

Edges use:

- `from`
- `to`
- `relationship`
- `target_type`

Service-specific fields can be added when useful, such as `state_name` for Step
Functions, `route_key` for API Gateway, or `target_id` for EventBridge.

Permission checks use a consistent shape:

- `enabled`
- `checked_count`
- `summary`
- `checks`

If a permission check cannot run because IAM permissions are unavailable, the
tool should still return dependency context and include a warning instead of
failing the whole investigation.

## Safety Rules For New Tools

New tools should follow these rules:

- Use read-only AWS APIs only.
- Do not fetch secret values.
- Do not fetch S3 object bodies.
- Do not scan, query, or read DynamoDB items in v1.
- Do not return full Lambda environment values.
- Bound pagination, time windows, and result counts.
- Truncate long strings.
- Return concise summaries rather than full AWS JSON blobs.
- Keep missing permissions non-fatal when a partial answer is still useful.
- Include tests for redaction, limits, pagination, and error behavior.

## Extension Direction

The best next extensions are not more raw `list` tools. They are deeper
investigation tools that can walk safe parts of the AWS graph:

- Lambda to IAM role to inferred downstream resources.
- Step Functions to task targets to IAM simulation.
- API Gateway routes to integrations to Lambda resource policies.
- EventBridge rules to targets, DLQs, roles, metrics, and resource policies.
- Event-driven flow tools that start from workload names, event sources, detail
  types, or event-pattern paths and stitch EventBridge to downstream services.
- Failure summaries that join CloudWatch logs, metrics, and configuration.

Each extension should help a developer reason about the system without requiring
them to know every AWS API involved.
