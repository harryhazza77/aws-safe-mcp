# AI Client Notes

`aws-safe-mcp` is a stdio MCP server, so it should work with any AI client that
can launch local MCP servers over stdio.

Known useful client families include:

- Claude Desktop
- Claude Code
- Cursor
- Continue
- Cline
- Windsurf
- Open WebUI or other local MCP hosts
- Custom MCP clients built with the Python, TypeScript, or other MCP SDKs

Client-specific setup varies, but the server command is the same shape:

```bash
uvx --from /path/to/aws-sdk-mcp aws-safe-mcp \
  --profile dev \
  --region eu-west-2 \
  --readonly \
  --config ~/.config/aws-safe-mcp/config.yaml
```

While iterating on a checkout, prefer:

```bash
uv --directory /path/to/aws-sdk-mcp run aws-safe-mcp \
  --profile dev \
  --region eu-west-2 \
  --readonly \
  --config ~/.config/aws-safe-mcp/config.yaml
```

## Client Behavior To Expect

- The server can start before AWS credentials are valid.
- `get_aws_auth_status` should be the first tool call in a new client session.
- After `aws login` or `aws sso login`, the next AWS tool call re-checks STS.
- Some clients need a reconnect/reload after server code or dependency changes.
- The server writes audit logs to stderr; clients may show these in their MCP
  server logs.

## Provider-Neutral Live Smoke Prompts

Use a non-production AWS profile and account. Keep result limits small.

```text
Check my AWS auth status. Use AWS MCP only.
```

```text
Search AWS resources for <name-fragment>. Use AWS MCP only.
```

```text
List Lambda functions, Step Functions, API Gateways, EventBridge rules, S3 buckets, DynamoDB tables, and CloudWatch log groups with small result limits. Use AWS MCP only.
```

```text
Explain the dependencies for Lambda <function-name>. Use AWS MCP only.
```

```text
Explain the dependencies for Step Function arn:aws:states:<region>:<account>:stateMachine:<name>. Use AWS MCP only.
```

```text
Explain the dependencies for API Gateway <api-id>. Use AWS MCP only.
```

```text
Explain the dependencies for EventBridge rule <rule-name>. Use AWS MCP only.
```

```text
Investigate delivery for EventBridge rule <rule-name> over the last hour. Use AWS MCP only.
```

```text
Trace the event-driven flow for source aws.s3, detail type Object Created, bucket <bucket-name>, and <suffix> object keys. Use AWS MCP only.
```

## Good Live Smoke Signals

- Auth reports the expected account, principal, profile, region, and
  `readonly: true`.
- Search returns a mixed set of matching resources without warnings.
- Lambda dependency tools show execution role, log group, event sources, and IAM
  checks without environment values.
- Step Functions dependency tools show task targets, representative flow paths,
  and IAM checks.
- API Gateway dependency tools show route-to-integration edges. Lambda
  integrations include Lambda permission checks; non-Lambda HTTP integrations do
  not.
- EventBridge dependency tools show rule pattern summary, targets, roles, DLQs,
  metrics, and permission checks. Event patterns are summarized and redacted.
- Event-driven flow tools can start from workload names, EventBridge source,
  detail type, or event JSON paths and stitch EventBridge to Step Functions and
  Lambda where those targets are visible. They should include a concise
  diagnostic summary, key findings, ordered flow paths, and grouped downstream
  hints with S3 bucket candidates, SQS queue candidates, DynamoDB table
  candidates, SNS topic candidates, EventBridge bus candidates, Secrets Manager
  secret candidates, SSM parameter candidates, KMS alias candidates, and
  Lambda-role IAM simulation where available, as well as graph fields. Secret,
  parameter, and KMS candidates are name-only metadata; values and decrypt
  operations are never requested.

## Valid Non-Failures

- Empty DynamoDB, API Gateway, or EventBridge lists can be valid for an account.
- No EventBridge matches in a recent metric window is not necessarily a failure;
  it may simply mean no upstream events arrived.
- Missing optional IAM permissions should appear as warnings or unknown checks,
  not crash the whole tool.
- Non-Lambda API Gateway integrations should show dependency edges with no
  Lambda permission checks.
