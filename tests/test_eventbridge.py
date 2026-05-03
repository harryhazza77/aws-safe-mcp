from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

import aws_safe_mcp.tools.eventbridge as eventbridge_module
from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.errors import ToolInputError
from aws_safe_mcp.tools.eventbridge import (
    explain_event_driven_flow,
    explain_eventbridge_rule_dependencies,
    investigate_eventbridge_rule_delivery,
    list_eventbridge_rules,
)


class FakeIdentity:
    account = "123456789012"


class FakeEventsClient:
    def __init__(self) -> None:
        self.bus_requests: list[dict[str, Any]] = []
        self.rule_requests: list[dict[str, Any]] = []
        self.target_requests: list[dict[str, Any]] = []

    def list_event_buses(self, **kwargs: Any) -> dict[str, Any]:
        self.bus_requests.append(kwargs)
        if "NextToken" not in kwargs:
            return {
                "NextToken": "bus-page-2",
                "EventBuses": [
                    {
                        "Name": "default",
                        "Arn": "arn:aws:events:eu-west-2:123456789012:event-bus/default",
                    }
                ],
            }
        return {
            "EventBuses": [
                {
                    "Name": "custom",
                    "Arn": "arn:aws:events:eu-west-2:123456789012:event-bus/custom",
                }
            ]
        }

    def list_rules(self, **kwargs: Any) -> dict[str, Any]:
        self.rule_requests.append(kwargs)
        bus = kwargs["EventBusName"]
        if bus == "default":
            return {
                "Rules": [
                    {
                        "Name": "dev-orders",
                        "Arn": "arn:aws:events:eu-west-2:123456789012:rule/dev-orders",
                        "EventBusName": "default",
                        "State": "ENABLED",
                        "EventPattern": json.dumps(
                            {
                                "source": ["app.orders"],
                                "detail-type": ["OrderCreated"],
                                "detail": {
                                    "apiToken": ["secret"],
                                    "object": {"key": [{"suffix": ".csv"}]},
                                },
                            }
                        ),
                    },
                    {
                        "Name": "dev-schedule",
                        "Arn": "arn:aws:events:eu-west-2:123456789012:rule/dev-schedule",
                        "EventBusName": "default",
                        "State": "DISABLED",
                        "ScheduleExpression": "rate(5 minutes)",
                        "ManagedBy": "events.amazonaws.com",
                    },
                ]
            }
        return {
            "Rules": [
                {
                    "Name": "dev-custom",
                    "Arn": "arn:aws:events:eu-west-2:123456789012:rule/custom/dev-custom",
                    "EventBusName": "custom",
                    "State": "ENABLED",
                }
            ]
        }

    def describe_rule(self, **kwargs: Any) -> dict[str, Any]:
        name = kwargs["Name"]
        if name == "missing":
            error = {"Error": {"Code": "ResourceNotFoundException", "Message": "missing"}}
            raise ClientError(error, "DescribeRule")
        return {
            "Name": name,
            "Arn": f"arn:aws:events:eu-west-2:123456789012:rule/{name}",
            "EventBusName": kwargs.get("EventBusName", "default"),
            "State": "ENABLED" if name != "disabled" else "DISABLED",
            "Description": "routes order events",
            "EventPattern": json.dumps(
                {
                    "source": ["app.orders"],
                    "detail-type": ["OrderCreated"],
                    "detail": {
                        "authToken": ["must-not-leak"],
                        "bucket": {"name": ["dev-landing-bucket"]},
                        "object": {"key": [{"suffix": ".csv"}]},
                    },
                }
            ),
        }

    def list_targets_by_rule(self, **kwargs: Any) -> dict[str, Any]:
        self.target_requests.append(kwargs)
        rule = kwargs["Rule"]
        if rule == "dev-orders" and "NextToken" not in kwargs:
            return {
                "NextToken": "target-page-2",
                "Targets": [
                    {
                        "Id": "lambda",
                        "Arn": "arn:aws:lambda:eu-west-2:123456789012:function:dev-handler",
                        "DeadLetterConfig": {
                            "Arn": "arn:aws:sqs:eu-west-2:123456789012:dev-rule-dlq"
                        },
                        "RetryPolicy": {
                            "MaximumRetryAttempts": 2,
                            "MaximumEventAgeInSeconds": 3600,
                        },
                    }
                ],
            }
        if rule == "dev-orders":
            return {
                "Targets": [
                    {
                        "Id": "sfn",
                        "Arn": "arn:aws:states:eu-west-2:123456789012:stateMachine:dev-flow",
                        "RoleArn": "arn:aws:iam::123456789012:role/eventbridge-sfn",
                    },
                    {
                        "Id": "unsupported",
                        "Arn": "arn:aws:logs:eu-west-2:123456789012:log-group:/aws/events/foo",
                    },
                ]
            }
        if rule == "disabled":
            return {"Targets": []}
        return {"Targets": []}


class FakeLambdaClient:
    def __init__(self, allow: bool | None = True) -> None:
        self.allow = allow

    def get_policy(self, FunctionName: str) -> dict[str, Any]:
        if self.allow is None:
            error = {"Error": {"Code": "ResourceNotFoundException", "Message": "no policy"}}
            raise ClientError(error, "GetPolicy")
        principal = "events.amazonaws.com" if self.allow else "apigateway.amazonaws.com"
        return {
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": principal},
                            "Action": "lambda:InvokeFunction",
                            "Resource": FunctionName,
                            "Condition": {
                                "ArnLike": {
                                    "AWS:SourceArn": (
                                        "arn:aws:events:eu-west-2:123456789012:rule/dev-orders"
                                    )
                                }
                            },
                        }
                    ]
                }
            )
        }


class FakeIamClient:
    def __init__(self, decision: str = "allowed") -> None:
        self.decision = decision

    def simulate_principal_policy(self, **_: Any) -> dict[str, Any]:
        if self.decision == "error":
            error = {"Error": {"Code": "AccessDenied", "Message": "denied"}}
            raise ClientError(error, "SimulatePrincipalPolicy")
        return {
            "EvaluationResults": [
                {
                    "EvalDecision": self.decision,
                    "MatchedStatements": [{"SourcePolicyId": "inline"}],
                    "MissingContextValues": [],
                }
            ]
        }


class FakeSqsClient:
    def __init__(self, allow: bool | None = True, messages: str = "3") -> None:
        self.allow = allow
        self.messages = messages
        self.requests: list[dict[str, Any]] = []

    def list_queues(self, **kwargs: Any) -> dict[str, Any]:
        self.requests.append(kwargs)
        return {
            "QueueUrls": [
                "https://sqs.eu-west-2.amazonaws.com/123456789012/dev-orders-queue",
                "https://sqs.eu-west-2.amazonaws.com/123456789012/unrelated-queue",
            ]
        }

    def get_queue_attributes(self, **kwargs: Any) -> dict[str, Any]:
        self.requests.append(kwargs)
        if self.allow is None:
            error = {"Error": {"Code": "AccessDenied", "Message": "denied"}}
            raise ClientError(error, "GetQueueAttributes")
        principal = "events.amazonaws.com" if self.allow else "lambda.amazonaws.com"
        queue_url = str(kwargs.get("QueueUrl") or "")
        queue_name = queue_url.rsplit("/", 1)[-1] or "dev-rule-dlq"
        return {
            "Attributes": {
                "QueueArn": f"arn:aws:sqs:eu-west-2:123456789012:{queue_name}",
                "ApproximateNumberOfMessages": self.messages,
                "ApproximateNumberOfMessagesNotVisible": "1",
                "Policy": json.dumps(
                    {
                        "Statement": {
                            "Effect": "Allow",
                            "Principal": {"Service": principal},
                            "Action": "sqs:SendMessage",
                        }
                    }
                ),
            }
        }


class FakeSnsClient:
    def __init__(self, allow: bool = True) -> None:
        self.allow = allow

    def list_topics(self, **_: Any) -> dict[str, Any]:
        return {
            "Topics": [
                {"TopicArn": "arn:aws:sns:eu-west-2:123456789012:dev-orders-topic"},
                {"TopicArn": "arn:aws:sns:eu-west-2:123456789012:unrelated-topic"},
            ]
        }

    def get_topic_attributes(self, **_: Any) -> dict[str, Any]:
        principal = "events.amazonaws.com" if self.allow else "lambda.amazonaws.com"
        return {
            "Attributes": {
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": principal},
                                "Action": ["sns:Publish"],
                            }
                        ]
                    }
                )
            }
        }


class FakeS3Client:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def list_buckets(self) -> dict[str, Any]:
        if self.fail:
            error = {"Error": {"Code": "AccessDenied", "Message": "denied"}}
            raise ClientError(error, "ListBuckets")
        return {
            "Buckets": [
                {"Name": "dev-landing-bucket"},
                {"Name": "dev-state-bucket"},
                {"Name": "unrelated-bucket"},
            ]
        }


class FakeDynamoDbClient:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def list_tables(self, **kwargs: Any) -> dict[str, Any]:
        self.requests.append(kwargs)
        return {
            "TableNames": [
                "dev-orders-table",
                "dev-state-table",
                "unrelated-table",
            ]
        }


class FakeSecretsManagerClient:
    def list_secrets(self, **_: Any) -> dict[str, Any]:
        return {
            "SecretList": [
                {
                    "Name": "shopify/client",
                    "ARN": "arn:aws:secretsmanager:eu-west-2:123456789012:secret:shopify/client",
                }
            ]
        }


class FakeSsmClient:
    def describe_parameters(self, **_: Any) -> dict[str, Any]:
        return {"Parameters": [{"Name": "/dev/shopify/config"}]}


class FakeKmsClient:
    def list_aliases(self, **_: Any) -> dict[str, Any]:
        return {
            "Aliases": [{"AliasName": "alias/duckdb", "TargetKeyId": "duckdb-key-id"}],
            "Truncated": False,
        }


class FakeCloudWatchClient:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def get_metric_data(self, MetricDataQueries: list[dict[str, Any]], **_: Any) -> dict[str, Any]:
        if self.fail:
            error = {"Error": {"Code": "AccessDenied", "Message": "denied"}}
            raise ClientError(error, "GetMetricData")
        timestamp = datetime(2026, 1, 1, tzinfo=UTC)
        return {
            "MetricDataResults": [
                {
                    "Id": query["Id"],
                    "Label": query["Label"],
                    "Values": [1.0] if query["Label"] in {"FailedInvocations"} else [],
                    "Timestamps": [timestamp] if query["Label"] in {"FailedInvocations"} else [],
                    "StatusCode": "Complete",
                }
                for query in MetricDataQueries
            ]
        }


class FakeRuntime:
    def __init__(
        self,
        *,
        events: FakeEventsClient | None = None,
        lambda_client: FakeLambdaClient | None = None,
        iam: FakeIamClient | None = None,
        sqs: FakeSqsClient | None = None,
        sns: FakeSnsClient | None = None,
        s3: FakeS3Client | None = None,
        dynamodb: FakeDynamoDbClient | None = None,
        secretsmanager: FakeSecretsManagerClient | None = None,
        ssm: FakeSsmClient | None = None,
        kms: FakeKmsClient | None = None,
        cloudwatch: FakeCloudWatchClient | None = None,
    ) -> None:
        self.config = AwsSafeConfig(allowed_account_ids=["123456789012"])
        self.region = "eu-west-2"
        self.identity = FakeIdentity()
        self.events = events or FakeEventsClient()
        self.lambda_client = lambda_client or FakeLambdaClient()
        self.iam = iam or FakeIamClient()
        self.sqs = sqs or FakeSqsClient()
        self.sns = sns or FakeSnsClient()
        self.s3 = s3 or FakeS3Client()
        self.dynamodb = dynamodb or FakeDynamoDbClient()
        self.secretsmanager = secretsmanager or FakeSecretsManagerClient()
        self.ssm = ssm or FakeSsmClient()
        self.kms = kms or FakeKmsClient()
        self.cloudwatch = cloudwatch or FakeCloudWatchClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert region in {"eu-west-2", None}
        if service_name == "events":
            return self.events
        if service_name == "lambda":
            return self.lambda_client
        if service_name == "iam":
            return self.iam
        if service_name == "sqs":
            return self.sqs
        if service_name == "sns":
            return self.sns
        if service_name == "s3":
            return self.s3
        if service_name == "dynamodb":
            return self.dynamodb
        if service_name == "secretsmanager":
            return self.secretsmanager
        if service_name == "ssm":
            return self.ssm
        if service_name == "kms":
            return self.kms
        if service_name == "cloudwatch":
            return self.cloudwatch
        raise AssertionError(service_name)

    def require_identity(self) -> FakeIdentity:
        return self.identity


def test_list_eventbridge_rules_lists_buses_rules_and_target_summaries() -> None:
    runtime = FakeRuntime()

    result = list_eventbridge_rules(runtime, name_prefix="dev", max_results=10)

    assert result["event_bus_count"] == 2
    assert result["count"] == 3
    assert [rule["name"] for rule in result["rules"]] == [
        "dev-orders",
        "dev-schedule",
        "dev-custom",
    ]
    assert result["rules"][0]["target_count"] == 3
    assert result["rules"][0]["target_types"] == ["lambda", "logs", "stepfunctions"]
    assert result["rules"][1]["state"] == "DISABLED"
    assert result["rules"][1]["schedule_expression"] == "rate(5 minutes)"
    assert result["rules"][1]["managed_by"] == "events.amazonaws.com"
    assert runtime.events.bus_requests == [{"Limit": 10}, {"Limit": 9, "NextToken": "bus-page-2"}]


def test_explain_eventbridge_rule_dependencies_returns_graph_and_permission_checks() -> None:
    result = explain_eventbridge_rule_dependencies(FakeRuntime(), "dev-orders")

    assert result["resource_type"] == "eventbridge_rule"
    assert result["summary"]["target_count"] == 3
    assert result["summary"]["dlq_count"] == 1
    assert ".csv" in result["nodes"]["rule"]["event_pattern"]["value"]
    assert "must-not-leak" not in result["nodes"]["rule"]["event_pattern"]["value"]
    assert "[REDACTED]" in result["nodes"]["rule"]["event_pattern"]["value"]
    assert {edge["relationship"] for edge in result["edges"]} >= {
        "matches_on_bus",
        "routes_to",
        "uses_role",
        "sends_failed_events_to",
    }
    assert result["permission_checks"]["summary"] == {
        "allowed": 3,
        "denied": 0,
        "unknown": 1,
        "explicit_denies": 0,
    }
    assert result["nodes"]["dead_letter_queues"][0]["approximate_number_of_messages"] == 3
    assert result["nodes"]["dead_letter_queues"][0]["policy_allows_eventbridge"] is True


def test_explain_eventbridge_rule_dependencies_can_disable_permission_checks() -> None:
    result = explain_eventbridge_rule_dependencies(
        FakeRuntime(),
        "dev-orders",
        include_permission_checks=False,
    )

    assert result["permission_checks"]["enabled"] is False
    assert result["permission_checks"]["checked_count"] == 0


def test_explain_eventbridge_rule_dependencies_reports_role_simulation_denied() -> None:
    result = explain_eventbridge_rule_dependencies(
        FakeRuntime(iam=FakeIamClient(decision="implicitDeny")),
        "dev-orders",
    )

    sfn_check = next(
        check for check in result["permission_checks"]["checks"] if check["target_id"] == "sfn"
    )
    assert sfn_check["decision"] == "implicitDeny"
    assert sfn_check["allowed"] is False
    assert result["permission_checks"]["summary"]["denied"] == 1


def test_explain_eventbridge_rule_dependencies_reports_resource_policy_denied_and_unknown() -> None:
    result = explain_eventbridge_rule_dependencies(
        FakeRuntime(lambda_client=FakeLambdaClient(allow=False), sqs=FakeSqsClient(allow=None)),
        "dev-orders",
    )

    lambda_check = next(
        check
        for check in result["permission_checks"]["checks"]
        if check["target_id"] == "lambda" and check["action"] == "lambda:InvokeFunction"
    )
    assert lambda_check["decision"] == "not_found"
    assert lambda_check["allowed"] is False
    assert result["nodes"]["dead_letter_queues"][0]["available"] is False
    assert result["warnings"]


def test_investigate_eventbridge_rule_delivery_combines_metrics_and_dlq_state() -> None:
    result = investigate_eventbridge_rule_delivery(FakeRuntime(), "dev-orders", since_minutes=120)

    assert result["window_minutes"] == 120
    assert result["metrics"]["available"] is True
    assert result["signals"]["has_failed_invocations"] is True
    assert result["signals"]["dlq_visible_messages"] == 3
    assert "failed delivery" in result["diagnostic_summary"]
    assert any("DLQ" in check for check in result["suggested_next_checks"])


def test_investigate_eventbridge_rule_delivery_keeps_metrics_failures_non_fatal() -> None:
    result = investigate_eventbridge_rule_delivery(
        FakeRuntime(cloudwatch=FakeCloudWatchClient(fail=True)),
        "dev-orders",
    )

    assert result["metrics"]["available"] is False
    assert result["warnings"]


def test_investigate_eventbridge_rule_delivery_handles_disabled_rule_without_targets() -> None:
    result = investigate_eventbridge_rule_delivery(FakeRuntime(), "disabled")

    assert result["signals"]["rule_disabled"] is True
    assert result["signals"]["has_targets"] is False
    assert "disabled" in result["diagnostic_summary"]


def test_explain_event_driven_flow_matches_name_and_follows_targets(monkeypatch: Any) -> None:
    def fake_stepfunctions(*_: Any, **__: Any) -> dict[str, Any]:
        return {
            "name": "dev-flow",
            "arn": "arn:aws:states:eu-west-2:123456789012:stateMachine:dev-flow",
            "summary": {"state_count": 2, "task_state_count": 1, "start_at": "Run"},
            "flow_summary": {"dispatcher_pattern_detected": True},
            "edges": [
                {
                    "from": "sfn",
                    "to": "arn:aws:lambda:eu-west-2:123456789012:function:dev-handler",
                    "relationship": "invokes_task",
                    "target_type": "lambda",
                }
            ],
            "permission_checks": {
                "checked_count": 1,
                "summary": {"allowed": 1, "denied": 0, "unknown": 0, "explicit_denies": 0},
            },
        }

    def fake_lambda(*_: Any, **__: Any) -> dict[str, Any]:
        return {
            "name": "dev-handler",
            "arn": "arn:aws:lambda:eu-west-2:123456789012:function:dev-handler",
            "summary": {"runtime": "python3.12", "environment_variable_keys": ["STATE_BUCKET"]},
            "nodes": {
                "execution_role": {
                    "role_arn": "arn:aws:iam::123456789012:role/dev-handler-role",
                    "role_name": "dev-handler-role",
                }
            },
            "edges": [],
            "unresolved_resource_hints": [
                {
                    "source": "environment_variable_key",
                    "key": "STATE_BUCKET",
                    "likely_service": "s3",
                    "reason": "Environment key STATE_BUCKET suggests a s3 dependency.",
                },
                {
                    "source": "environment_variable_key",
                    "key": "LANDING_BUCKET",
                    "likely_service": "s3",
                    "reason": "Environment key LANDING_BUCKET suggests a s3 dependency.",
                },
                {
                    "source": "environment_variable_key",
                    "key": "ORDER_QUEUE_URL",
                    "likely_service": "sqs",
                    "reason": "Environment key ORDER_QUEUE_URL suggests a sqs dependency.",
                },
                {
                    "source": "environment_variable_key",
                    "key": "ORDER_TABLE_NAME",
                    "likely_service": "dynamodb",
                    "reason": "Environment key ORDER_TABLE_NAME suggests a dynamodb dependency.",
                },
                {
                    "source": "environment_variable_key",
                    "key": "ORDER_TOPIC_ARN",
                    "likely_service": "sns",
                    "reason": "Environment key ORDER_TOPIC_ARN suggests a sns dependency.",
                },
                {
                    "source": "environment_variable_key",
                    "key": "CUSTOM_EVENT_BUS_NAME",
                    "likely_service": "eventbridge",
                    "reason": (
                        "Environment key CUSTOM_EVENT_BUS_NAME suggests an eventbridge dependency."
                    ),
                },
                {
                    "source": "environment_variable_key",
                    "key": "SHOPIFY_CLIENT_SECRET",
                    "likely_service": "secretsmanager",
                    "reason": "Secret-like env key suggests external auth config.",
                },
            ],
            "permission_checks": {
                "checked_count": 1,
                "summary": {"allowed": 1, "denied": 0, "unknown": 0, "explicit_denies": 0},
            },
        }

    monkeypatch.setattr(
        eventbridge_module,
        "explain_step_function_dependencies",
        fake_stepfunctions,
    )
    monkeypatch.setattr(eventbridge_module, "explain_lambda_dependencies", fake_lambda)

    result = explain_event_driven_flow(FakeRuntime(), name_fragment="dev-orders")

    assert result["matched_rule_count"] == 1
    assert result["summary"] == {
        "eventbridge_rule_count": 1,
        "step_function_count": 1,
        "lambda_count": 1,
        "path_count": 1,
    }
    assert result["nodes"]["eventbridge_rules"][0]["name"] == "dev-orders"
    assert result["nodes"]["step_functions"][0]["name"] == "dev-flow"
    assert result["nodes"]["lambdas"][0]["name"] == "dev-handler"
    assert result["permission_checks"]["summary"]["allowed"] == 5
    assert result["diagnostic_summary"] == (
        "Matched 1 EventBridge rule(s) and built 1 event-driven flow path(s); "
        "1 unknown permission check(s)."
    )
    assert result["flow_paths"][0]["path"] == "dev-orders -> dev-flow -> dev-handler"
    assert any("Dispatcher Step Function pattern" in finding for finding in result["key_findings"])
    assert any("downstream hint" in finding for finding in result["key_findings"])
    assert result["downstream_hints"][0]["lambda_name"] == "dev-handler"
    assert result["downstream_hints"][0]["likely_services"] == [
        "dynamodb",
        "eventbridge",
        "s3",
        "secretsmanager",
        "sns",
        "sqs",
    ]
    assert result["downstream_hints"][0]["hint_count"] == 7
    s3_hints = [
        hint for hint in result["downstream_hints"][0]["hints"] if hint["likely_service"] == "s3"
    ]
    assert {hint["status"] for hint in s3_hints} == {"candidate_match"}
    assert {hint["verification"] for hint in s3_hints} == {"candidate_name_match"}
    assert {
        candidate["bucket"] for hint in s3_hints for candidate in hint["s3_candidate_buckets"]
    } >= {"dev-landing-bucket", "dev-state-bucket"}
    assert all(
        candidate["permission_checks"]["summary"]["allowed"] == 3
        for hint in s3_hints
        for candidate in hint["s3_candidate_buckets"]
    )
    s3_check = s3_hints[0]["s3_candidate_buckets"][0]["permission_checks"]["checks"][0]
    assert s3_check["principal"]["role_name"] == "dev-handler-role"
    assert s3_check["action"] == "s3:ListBucket"
    sqs_hints = [
        hint for hint in result["downstream_hints"][0]["hints"] if hint["likely_service"] == "sqs"
    ]
    assert sqs_hints[0]["status"] == "candidate_match"
    assert sqs_hints[0]["verification"] == "candidate_name_match"
    assert sqs_hints[0]["sqs_candidate_queues"][0]["queue_name"] == "dev-orders-queue"
    sqs_check = sqs_hints[0]["sqs_candidate_queues"][0]["permission_checks"]["checks"][0]
    assert sqs_check["action"] == "sqs:SendMessage"
    assert sqs_check["allowed"] is True
    dynamodb_hints = [
        hint
        for hint in result["downstream_hints"][0]["hints"]
        if hint["likely_service"] == "dynamodb"
    ]
    assert dynamodb_hints[0]["status"] == "candidate_match"
    assert dynamodb_hints[0]["verification"] == "candidate_name_match"
    assert dynamodb_hints[0]["dynamodb_candidate_tables"][0]["table_name"] == "dev-orders-table"
    dynamodb_checks = dynamodb_hints[0]["dynamodb_candidate_tables"][0]["permission_checks"][
        "checks"
    ]
    assert {check["action"] for check in dynamodb_checks} == {
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query",
    }
    assert all(check["allowed"] is True for check in dynamodb_checks)
    sns_hints = [
        hint for hint in result["downstream_hints"][0]["hints"] if hint["likely_service"] == "sns"
    ]
    assert sns_hints[0]["status"] == "candidate_match"
    assert sns_hints[0]["sns_candidate_topics"][0]["topic_name"] == "dev-orders-topic"
    sns_check = sns_hints[0]["sns_candidate_topics"][0]["permission_checks"]["checks"][0]
    assert sns_check["action"] == "sns:Publish"
    assert sns_check["allowed"] is True
    eventbridge_hints = [
        hint
        for hint in result["downstream_hints"][0]["hints"]
        if hint["likely_service"] == "eventbridge"
    ]
    assert eventbridge_hints[0]["status"] == "candidate_match"
    assert eventbridge_hints[0]["eventbridge_candidate_buses"][0]["event_bus_name"] == "custom"
    eventbridge_check = eventbridge_hints[0]["eventbridge_candidate_buses"][0]["permission_checks"][
        "checks"
    ][0]
    assert eventbridge_check["action"] == "events:PutEvents"
    assert eventbridge_check["allowed"] is True
    assert "STATE_BUCKET" in result["downstream_hints"][0]["summary"]
    assert "S3 candidates" in result["downstream_hints"][0]["summary"]
    assert "SQS candidates" in result["downstream_hints"][0]["summary"]
    assert "dev-orders-queue (SendMessage allowed)" in result["downstream_hints"][0]["summary"]
    assert "DynamoDB candidates" in result["downstream_hints"][0]["summary"]
    assert "dev-orders-table (4/4 allowed)" in result["downstream_hints"][0]["summary"]
    assert "SNS candidates" in result["downstream_hints"][0]["summary"]
    assert "dev-orders-topic (Publish allowed)" in result["downstream_hints"][0]["summary"]
    assert "EventBridge candidates" in result["downstream_hints"][0]["summary"]
    assert "custom (PutEvents allowed)" in result["downstream_hints"][0]["summary"]
    assert "3/3 allowed" in result["downstream_hints"][0]["summary"]


def test_explain_event_driven_flow_matches_event_pattern_path(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        eventbridge_module,
        "explain_step_function_dependencies",
        lambda *_args, **_kwargs: {
            "name": "dev-flow",
            "arn": "arn:aws:states:eu-west-2:123456789012:stateMachine:dev-flow",
            "summary": {},
            "flow_summary": {},
            "edges": [],
            "permission_checks": {
                "checked_count": 0,
                "summary": {"allowed": 0, "denied": 0, "unknown": 0, "explicit_denies": 0},
            },
        },
    )

    result = explain_event_driven_flow(
        FakeRuntime(),
        event_source="app.orders",
        detail_type="OrderCreated",
        detail_path="object.key",
        detail_value=".csv",
    )

    assert result["matched_rule_count"] == 1
    assert result["flows"][0]["rule"]["name"] == "dev-orders"


def test_explain_event_driven_flow_requires_all_supplied_pattern_criteria() -> None:
    result = explain_event_driven_flow(
        FakeRuntime(),
        event_source="app.orders",
        detail_type="PaymentCreated",
        detail_path="object.key",
        detail_value=".csv",
    )

    assert result["matched_rule_count"] == 0
    assert result["summary"]["path_count"] == 0
    assert result["diagnostic_summary"] == (
        "No EventBridge rules matched the supplied event flow criteria."
    )
    assert result["key_findings"] == [
        "No EventBridge rules matched the supplied event flow criteria."
    ]
    assert result["downstream_hints"] == []


def test_explain_event_driven_flow_requires_search_criteria() -> None:
    try:
        explain_event_driven_flow(FakeRuntime())
    except ToolInputError as exc:
        assert "At least one" in str(exc)
    else:
        raise AssertionError("expected ToolInputError")
