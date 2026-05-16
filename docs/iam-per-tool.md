# IAM Per Tool

Reference mapping each `aws-safe-mcp` tool to the AWS read actions its caller
must hold. The server calls AWS as you — every action below is invoked under
your IAM principal, not under a service role.

## How to use this

The caller's IAM principal must hold the listed `Required` actions on the
relevant resources for the tool to succeed. `Optional` actions enrich the
response with extra checks (typically IAM simulation); when they are missing,
the affected sub-checks downgrade to warnings or `unknown` verdicts rather than
failing the whole tool. This partial-results behaviour is contract — see
[limitations.md](limitations.md) ("Visibility Follows The Active Credentials"
and "IAM And Policy Checks"). If a tool fails outright with `AccessDenied`,
grant the `Required` action; if it returns `unknown`, grant the matching
`Optional` action.

## Conventions

- `Required` — the tool's primary AWS API call. Missing this action causes the
  tool to fail.
- `Optional` — secondary calls that enrich the result. Missing these emit
  warnings; the tool still returns useful output.
- `iam:SimulatePrincipalPolicy` — listed as `Optional` for any tool that runs
  permission simulation. Without it, the simulation verdict is reported as
  `unknown` rather than as a confirmed allow or deny.
- Region/account safety: every tool first calls `sts:GetCallerIdentity` to
  validate the account allowlist. This action is implicitly required by every
  tool below and is not repeated per row.

## Tools by service

### Identity

#### `get_aws_identity`

See [tools.md#identity](tools.md#identity).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `sts:GetCallerIdentity` | `sts:GetCallerIdentity` | Required |

#### `get_aws_auth_status`

See [tools.md#identity](tools.md#identity).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `sts:GetCallerIdentity` | `sts:GetCallerIdentity` | Required |

### IAM

#### `get_iam_role_summary`

See [tools.md#iam](tools.md#iam).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `iam:GetRole` | `iam:GetRole` | Required |
| `iam:ListAttachedRolePolicies` | `iam:ListAttachedRolePolicies` | Required |
| `iam:ListRolePolicies` | `iam:ListRolePolicies` | Required |

#### `explain_iam_simulation_denial`

See [tools.md#iam](tools.md#iam).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `iam:SimulatePrincipalPolicy` | `iam:SimulatePrincipalPolicy` | Required |

### Lambda

#### `list_lambda_functions`

See [tools.md#lambda](tools.md#lambda).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `lambda:ListFunctions` | `lambda:ListFunctions` | Required |

#### `get_lambda_summary`

See [tools.md#lambda](tools.md#lambda).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `lambda:GetFunctionConfiguration` | `lambda:GetFunctionConfiguration` | Required |

#### `get_lambda_event_source_mapping_diagnostics`

See [tools.md#lambda](tools.md#lambda).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `lambda:ListEventSourceMappings` | `lambda:ListEventSourceMappings` | Required |
| `lambda:GetFunctionConfiguration` | `lambda:GetFunctionConfiguration` | Required |
| `iam:GetRole` | `iam:GetRole` | Optional |
| `iam:ListAttachedRolePolicies` | `iam:ListAttachedRolePolicies` | Optional |
| `iam:ListRolePolicies` | `iam:ListRolePolicies` | Optional |
| `iam:SimulatePrincipalPolicy` | `iam:SimulatePrincipalPolicy` | Optional |

#### `get_lambda_alias_version_summary`

See [tools.md#lambda](tools.md#lambda).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `lambda:ListAliases` | `lambda:ListAliases` | Required |
| `lambda:ListVersionsByFunction` | `lambda:ListVersionsByFunction` | Required |
| `lambda:GetProvisionedConcurrencyConfig` | `lambda:GetProvisionedConcurrencyConfig` | Optional |
| `lambda:GetPolicy` | `lambda:GetPolicy` | Optional |

#### `get_lambda_recent_errors`

See [tools.md#lambda](tools.md#lambda).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `logs:FilterLogEvents` | `logs:FilterLogEvents` | Required |

#### `investigate_lambda_failure`

See [tools.md#lambda](tools.md#lambda).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `lambda:GetFunctionConfiguration` | `lambda:GetFunctionConfiguration` | Required |
| `cloudwatch:GetMetricData` | `cloudwatch:GetMetricData` | Required |
| `logs:FilterLogEvents` | `logs:FilterLogEvents` | Required |
| `lambda:ListAliases` | `lambda:ListAliases` | Optional |
| `lambda:ListEventSourceMappings` | `lambda:ListEventSourceMappings` | Optional |

#### `explain_lambda_dependencies`

See [tools.md#lambda](tools.md#lambda).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `lambda:GetFunctionConfiguration` | `lambda:GetFunctionConfiguration` | Required |
| `iam:GetRole` | `iam:GetRole` | Required |
| `iam:ListAttachedRolePolicies` | `iam:ListAttachedRolePolicies` | Required |
| `iam:ListRolePolicies` | `iam:ListRolePolicies` | Required |
| `lambda:ListEventSourceMappings` | `lambda:ListEventSourceMappings` | Optional |
| `lambda:GetPolicy` | `lambda:GetPolicy` | Optional |
| `iam:SimulatePrincipalPolicy` | `iam:SimulatePrincipalPolicy` | Optional |

#### `explain_lambda_network_access`

See [tools.md#lambda](tools.md#lambda) and
[lambda-network-access.md](lambda-network-access.md).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `lambda:GetFunctionConfiguration` | `lambda:GetFunctionConfiguration` | Required |
| `ec2:DescribeSubnets` | `ec2:DescribeSubnets` | Required |
| `ec2:DescribeSecurityGroups` | `ec2:DescribeSecurityGroups` | Required |
| `ec2:DescribeRouteTables` | `ec2:DescribeRouteTables` | Required |
| `ec2:DescribeNetworkAcls` | `ec2:DescribeNetworkAcls` | Required |
| `ec2:DescribeVpcEndpoints` | `ec2:DescribeVpcEndpoints` | Required |

#### `check_lambda_permission_path`

See [tools.md#lambda](tools.md#lambda).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `lambda:GetFunctionConfiguration` | `lambda:GetFunctionConfiguration` | Required |
| `iam:SimulatePrincipalPolicy` | `iam:SimulatePrincipalPolicy` | Optional |

#### `prove_lambda_invocation_path`

See [tools.md#lambda](tools.md#lambda).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `lambda:GetFunctionConfiguration` | `lambda:GetFunctionConfiguration` | Required |
| `lambda:GetPolicy` | `lambda:GetPolicy` | Required |
| `lambda:ListEventSourceMappings` | `lambda:ListEventSourceMappings` | Optional |
| `iam:SimulatePrincipalPolicy` | `iam:SimulatePrincipalPolicy` | Optional |

### SQS

#### `list_sqs_queues`

See [tools.md#sqs](tools.md#sqs).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `sqs:ListQueues` | `sqs:ListQueues` | Required |

#### `get_sqs_queue_summary`

See [tools.md#sqs](tools.md#sqs).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `sqs:GetQueueAttributes` | `sqs:GetQueueAttributes` | Required |

#### `explain_sqs_queue_dependencies`

See [tools.md#sqs](tools.md#sqs).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `sqs:GetQueueAttributes` | `sqs:GetQueueAttributes` | Required |
| `events:ListEventBuses` | `events:ListEventBuses` | Optional |
| `events:ListRules` | `events:ListRules` | Optional |
| `events:ListTargetsByRule` | `events:ListTargetsByRule` | Optional |
| `lambda:ListEventSourceMappings` | `lambda:ListEventSourceMappings` | Optional |
| `iam:SimulatePrincipalPolicy` | `iam:SimulatePrincipalPolicy` | Optional |

#### `check_sqs_to_lambda_delivery`

See [tools.md#sqs](tools.md#sqs).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `sqs:GetQueueAttributes` | `sqs:GetQueueAttributes` | Required |
| `lambda:ListEventSourceMappings` | `lambda:ListEventSourceMappings` | Required |
| `lambda:GetFunctionConfiguration` | `lambda:GetFunctionConfiguration` | Optional |

### SNS

#### `list_sns_topics`

See [tools.md#sns](tools.md#sns).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `sns:ListTopics` | `sns:ListTopics` | Required |

#### `get_sns_topic_summary`

See [tools.md#sns](tools.md#sns).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `sns:GetTopicAttributes` | `sns:GetTopicAttributes` | Required |
| `sns:ListSubscriptionsByTopic` | `sns:ListSubscriptionsByTopic` | Optional |
| `sns:GetSubscriptionAttributes` | `sns:GetSubscriptionAttributes` | Optional |

### DynamoDB

#### `list_dynamodb_tables`

See [tools.md#dynamodb](tools.md#dynamodb).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `dynamodb:ListTables` | `dynamodb:ListTables` | Required |

#### `get_dynamodb_table_summary`

See [tools.md#dynamodb](tools.md#dynamodb).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `dynamodb:DescribeTable` | `dynamodb:DescribeTable` | Required |

#### `check_dynamodb_stream_lambda_readiness`

See [tools.md#dynamodb](tools.md#dynamodb).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `dynamodb:DescribeTable` | `dynamodb:DescribeTable` | Required |
| `lambda:ListEventSourceMappings` | `lambda:ListEventSourceMappings` | Required |
| `lambda:GetFunctionConfiguration` | `lambda:GetFunctionConfiguration` | Optional |
| `iam:SimulatePrincipalPolicy` | `iam:SimulatePrincipalPolicy` | Optional |

### S3

#### `list_s3_buckets`

See [tools.md#s3](tools.md#s3).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `s3:ListAllMyBuckets` | `s3:ListAllMyBuckets` | Required |

#### `get_s3_bucket_summary`

See [tools.md#s3](tools.md#s3).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `s3:GetBucketLocation` | `s3:GetBucketLocation` | Required |
| `s3:GetBucketVersioning` | `s3:GetBucketVersioning` | Optional |
| `s3:GetEncryptionConfiguration` | `s3:GetEncryptionConfiguration` | Optional |
| `s3:GetBucketPublicAccessBlock` | `s3:GetBucketPublicAccessBlock` | Optional |
| `s3:GetLifecycleConfiguration` | `s3:GetLifecycleConfiguration` | Optional |
| `s3:GetBucketLogging` | `s3:GetBucketLogging` | Optional |
| `s3:GetBucketNotification` | `s3:GetBucketNotification` | Optional |

### KMS

#### `list_kms_keys`

See [tools.md#kms](tools.md#kms).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `kms:ListKeys` | `kms:ListKeys` | Required |
| `kms:DescribeKey` | `kms:DescribeKey` | Optional |

#### `get_kms_key_summary`

See [tools.md#kms](tools.md#kms).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `kms:DescribeKey` | `kms:DescribeKey` | Required |
| `kms:GetKeyRotationStatus` | `kms:GetKeyRotationStatus` | Optional |
| `kms:ListAliases` | `kms:ListAliases` | Optional |
| `kms:ListKeyPolicies` | `kms:ListKeyPolicies` | Optional |

#### `check_kms_dependent_path`

See [tools.md#kms](tools.md#kms).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `kms:DescribeKey` | `kms:DescribeKey` | Required |
| `kms:GetKeyPolicy` | `kms:GetKeyPolicy` | Optional |
| `iam:SimulatePrincipalPolicy` | `iam:SimulatePrincipalPolicy` | Optional |

#### `find_kms_key_lifecycle_blast_radius`

See [tools.md#kms](tools.md#kms).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `kms:DescribeKey` | `kms:DescribeKey` | Required |
| `kms:ListAliases` | `kms:ListAliases` | Optional |

### EventBridge

#### `list_eventbridge_rules`

See [tools.md#eventbridge](tools.md#eventbridge).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `events:ListEventBuses` | `events:ListEventBuses` | Required |
| `events:ListRules` | `events:ListRules` | Required |
| `events:ListTargetsByRule` | `events:ListTargetsByRule` | Optional |

#### `explain_eventbridge_rule_dependencies`

See [tools.md#eventbridge](tools.md#eventbridge).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `events:DescribeRule` | `events:DescribeRule` | Required |
| `events:ListTargetsByRule` | `events:ListTargetsByRule` | Required |
| `lambda:GetPolicy` | `lambda:GetPolicy` | Optional |
| `sns:GetTopicAttributes` | `sns:GetTopicAttributes` | Optional |
| `sqs:GetQueueAttributes` | `sqs:GetQueueAttributes` | Optional |
| `iam:SimulatePrincipalPolicy` | `iam:SimulatePrincipalPolicy` | Optional |

#### `investigate_eventbridge_rule_delivery`

See [tools.md#eventbridge](tools.md#eventbridge).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `events:DescribeRule` | `events:DescribeRule` | Required |
| `events:ListTargetsByRule` | `events:ListTargetsByRule` | Required |
| `cloudwatch:GetMetricData` | `cloudwatch:GetMetricData` | Required |
| `sqs:GetQueueAttributes` | `sqs:GetQueueAttributes` | Optional |
| `lambda:GetPolicy` | `lambda:GetPolicy` | Optional |
| `iam:SimulatePrincipalPolicy` | `iam:SimulatePrincipalPolicy` | Optional |

### Step Functions

#### `list_step_functions`

See [tools.md#step-functions](tools.md#step-functions).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `states:ListStateMachines` | `states:ListStateMachines` | Required |

#### `get_step_function_execution_summary`

See [tools.md#step-functions](tools.md#step-functions).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `states:DescribeExecution` | `states:DescribeExecution` | Required |

#### `investigate_step_function_failure`

See [tools.md#step-functions](tools.md#step-functions).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `states:DescribeExecution` | `states:DescribeExecution` | Required |
| `states:GetExecutionHistory` | `states:GetExecutionHistory` | Required |
| `states:DescribeStateMachine` | `states:DescribeStateMachine` | Required |

### API Gateway

#### `list_api_gateways`

See [tools.md#api-gateway](tools.md#api-gateway).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `apigateway:GET` on `/restapis` | `apigateway:GET` | Required |
| `apigateway:GET` on `/apis` (HTTP/WebSocket) | `apigateway:GET` | Required |

#### `get_api_gateway_summary`

See [tools.md#api-gateway](tools.md#api-gateway).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `apigateway:GET` (REST `get_rest_api`, `get_resources`) | `apigateway:GET` | Required |
| `apigateway:GET` (HTTP/WebSocket `get_api`, `get_routes`) | `apigateway:GET` | Required |

### CloudWatch

#### `list_cloudwatch_alarms`

See [tools.md#cloudwatch-alarms](tools.md#cloudwatch-alarms).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `cloudwatch:DescribeAlarms` | `cloudwatch:DescribeAlarms` | Required |

#### `search_cloudwatch_logs`

See [tools.md#cloudwatch-logs](tools.md#cloudwatch-logs).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `logs:FilterLogEvents` | `logs:FilterLogEvents` | Required |

#### `query_cloudwatch_logs_insights`

See [tools.md#cloudwatch-logs](tools.md#cloudwatch-logs).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `logs:StartQuery` | `logs:StartQuery` | Required |
| `logs:GetQueryResults` | `logs:GetQueryResults` | Required |

#### `check_cloudwatch_logs_writeability`

See [tools.md#cloudwatch-logs](tools.md#cloudwatch-logs).

| AWS API call | IAM action | Required / Optional |
| --- | --- | --- |
| `logs:DescribeLogGroups` | `logs:DescribeLogGroups` | Required |
| `iam:SimulatePrincipalPolicy` | `iam:SimulatePrincipalPolicy` | Optional |

## Composite IAM policy

The following managed policy grants the union of `Required` read actions across
the high-traffic tools above. It uses `Resource: "*"` for brevity. In
production, scope each statement to specific resource ARNs (Lambda function
ARNs, queue ARNs, table ARNs, log group ARNs, key ARNs, and so on) and consider
`aws:ResourceTag` / `aws:RequestedRegion` conditions to limit blast radius.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Identity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Lambda",
      "Effect": "Allow",
      "Action": [
        "lambda:ListFunctions",
        "lambda:GetFunctionConfiguration",
        "lambda:ListEventSourceMappings",
        "lambda:ListAliases",
        "lambda:ListVersionsByFunction",
        "lambda:GetPolicy",
        "lambda:GetProvisionedConcurrencyConfig",
        "lambda:GetFunctionConcurrency",
        "lambda:GetFunctionEventInvokeConfig"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMReadAndSimulate",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:SimulatePrincipalPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2NetworkRead",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRouteTables",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeVpcEndpoints"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Messaging",
      "Effect": "Allow",
      "Action": [
        "sqs:ListQueues",
        "sqs:GetQueueAttributes",
        "sns:ListTopics",
        "sns:GetTopicAttributes",
        "sns:ListSubscriptionsByTopic",
        "sns:GetSubscriptionAttributes"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DataServices",
      "Effect": "Allow",
      "Action": [
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetLifecycleConfiguration",
        "s3:GetBucketLogging",
        "s3:GetBucketNotification"
      ],
      "Resource": "*"
    },
    {
      "Sid": "KMS",
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListKeyPolicies",
        "kms:GetKeyPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EventsAndStepFunctions",
      "Effect": "Allow",
      "Action": [
        "events:ListEventBuses",
        "events:ListRules",
        "events:DescribeRule",
        "events:ListTargetsByRule",
        "events:ListArchives",
        "events:ListReplays",
        "scheduler:ListSchedules",
        "states:ListStateMachines",
        "states:DescribeStateMachine",
        "states:DescribeExecution",
        "states:GetExecutionHistory"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ApiGateway",
      "Effect": "Allow",
      "Action": [
        "apigateway:GET"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Observability",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:DescribeAlarms",
        "cloudwatch:GetMetricData",
        "logs:DescribeLogGroups",
        "logs:FilterLogEvents",
        "logs:StartQuery",
        "logs:GetQueryResults"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TagSearch",
      "Effect": "Allow",
      "Action": [
        "tag:GetResources"
      ],
      "Resource": "*"
    }
  ]
}
```

## Caveats

This list is best-effort and is derived from the current code under
`src/aws_safe_mcp/tools/`. New tools may add actions that lag this document.
If a tool fails with `AccessDenied`, the fastest path is to check CloudTrail
for the exact denied `eventSource` and `eventName`, then grant that action.
Composite higher-level tools (such as the `investigate_*` and `audit_*`
families) call multiple underlying APIs; missing any `Optional` action degrades
their output to warnings rather than crashing.
