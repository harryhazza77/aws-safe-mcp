from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.tools.downstream import event_driven_downstream_hints


def test_event_driven_downstream_hints_summarizes_all_candidate_families() -> None:
    result = event_driven_downstream_hints(
        FakeRuntime(),
        [_flow([_lambda_node(_all_hints())])],
        [],
    )

    assert len(result) == 1
    hints = result[0]["hints"]
    assert result[0]["likely_services"] == [
        "dynamodb",
        "eventbridge",
        "kms",
        "s3",
        "secretsmanager",
        "sns",
        "sqs",
        "ssm",
    ]
    assert result[0]["hint_count"] == 8
    assert _first_candidate(hints, "s3", "s3_candidate_buckets")["bucket"] == "dev-state-bucket"
    assert (
        _first_candidate(hints, "sqs", "sqs_candidate_queues")["queue_name"] == "dev-orders-queue"
    )
    assert (
        _first_candidate(hints, "dynamodb", "dynamodb_candidate_tables")["table_name"]
        == "dev-orders-table"
    )
    assert (
        _first_candidate(hints, "sns", "sns_candidate_topics")["topic_name"] == "dev-orders-topic"
    )
    assert (
        _first_candidate(hints, "eventbridge", "eventbridge_candidate_buses")["event_bus_name"]
        == "custom"
    )
    assert (
        _first_candidate(hints, "secretsmanager", "secretsmanager_candidate_secrets")["secret_name"]
        == "shopify/client"
    )
    assert (
        _first_candidate(hints, "ssm", "ssm_candidate_parameters")["parameter_name"]
        == "/dev/shopify/config"
    )
    assert _first_candidate(hints, "kms", "kms_candidate_keys")["alias_name"] == "alias/duckdb"
    assert "dev-state-bucket (3/3 allowed)" in result[0]["summary"]
    assert "dev-orders-queue (SendMessage allowed)" in result[0]["summary"]
    assert "dev-orders-table (4/4 allowed)" in result[0]["summary"]
    assert "dev-orders-topic (Publish allowed)" in result[0]["summary"]
    assert "custom (PutEvents allowed)" in result[0]["summary"]
    assert "shopify/client (2/2 allowed)" in result[0]["summary"]
    assert "/dev/shopify/config (GetParameter allowed)" in result[0]["summary"]
    assert "alias/duckdb (2/2 allowed)" in result[0]["summary"]


def test_event_driven_downstream_hints_reports_denied_permissions() -> None:
    result = event_driven_downstream_hints(
        FakeRuntime(iam=FakeDenyIamClient()),
        [_flow([_lambda_node(_all_hints())])],
        [],
    )

    summary = result[0]["summary"]
    assert "dev-state-bucket (3/3 denied)" in summary
    assert "dev-orders-queue (SendMessage denied)" in summary
    assert "dev-orders-table (4/4 denied)" in summary
    assert "dev-orders-topic (Publish denied)" in summary
    assert "custom (PutEvents denied)" in summary
    assert "shopify/client (2/2 denied)" in summary
    assert "/dev/shopify/config (GetParameter denied)" in summary
    assert "alias/duckdb (2/2 denied)" in summary


def test_event_driven_downstream_hints_disables_checks_without_execution_role() -> None:
    result = event_driven_downstream_hints(
        FakeRuntime(),
        [_flow([_lambda_node([_hint("STATE_BUCKET", "s3")], role=False)])],
        [],
    )

    candidate = result[0]["hints"][0]["s3_candidate_buckets"][0]
    assert candidate["permission_checks"]["enabled"] is False
    assert candidate["permission_checks"]["checked_count"] == 0
    assert result[0]["summary"] == (
        "Lambda dev-handler likely depends on s3 from STATE_BUCKET; "
        "hints are inferred from metadata and resource targets are not fully verified."
        " S3 candidates: STATE_BUCKET -> dev-state-bucket."
    )


def test_event_driven_downstream_hints_keeps_partial_results_when_listing_fails() -> None:
    warnings: list[str] = []
    result = event_driven_downstream_hints(
        FakeRuntime(
            s3=FailingS3Client(),
            sqs=FailingSqsClient(),
            dynamodb=FailingDynamoDbClient(),
            sns=FailingSnsClient(),
            events=FailingEventsClient(),
            secretsmanager=FailingSecretsManagerClient(),
            ssm=FailingSsmClient(),
            kms=FailingKmsClient(),
        ),
        [_flow([_lambda_node(_all_hints())])],
        warnings,
    )

    assert result[0]["hint_count"] == 8
    assert {hint["status"] for hint in result[0]["hints"]} == {"unresolved"}
    assert len(warnings) == 8
    assert any("s3.ListBuckets unavailable" in warning for warning in warnings)
    assert any("sqs.ListQueues unavailable" in warning for warning in warnings)
    assert any("dynamodb.ListTables unavailable" in warning for warning in warnings)
    assert any("sns.ListTopics unavailable" in warning for warning in warnings)
    assert any("events.ListEventBuses" in warning for warning in warnings)
    assert any("secretsmanager.ListSecrets unavailable" in warning for warning in warnings)
    assert any("ssm.DescribeParameters unavailable" in warning for warning in warnings)
    assert any("kms.ListAliases unavailable" in warning for warning in warnings)


def test_event_driven_downstream_hints_notes_unresolved_sensitive_hints() -> None:
    result = event_driven_downstream_hints(
        FakeRuntime(
            secretsmanager=EmptySecretsManagerClient(),
            ssm=EmptySsmClient(),
            kms=EmptyKmsClient(),
        ),
        [
            _flow(
                [
                    _lambda_node(
                        [
                            _hint("SHOPIFY_CLIENT_SECRET", "secretsmanager"),
                            _hint("SHOPIFY_CONFIG_PARAMETER", "ssm"),
                            _hint("DUCKDB_KEY", "kms"),
                        ]
                    )
                ]
            )
        ],
        [],
    )

    notes = {
        hint["likely_service"]: hint.get("sensitive_resolution_note") for hint in result[0]["hints"]
    }
    assert result[0]["hint_count"] == 3
    assert {hint["status"] for hint in result[0]["hints"]} == {"unresolved"}
    assert {hint["verification"] for hint in result[0]["hints"]} == {"not_checked"}
    assert "Secrets Manager" in str(notes["secretsmanager"])
    assert "SSM parameter" in str(notes["ssm"])
    assert "KMS alias" in str(notes["kms"])


def _flow(lambdas: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "rule": {"name": "dev-orders", "event_pattern": {"value": "dev-landing-bucket"}},
        "lambdas": lambdas,
    }


def _lambda_node(hints: list[dict[str, str]], *, role: bool = True) -> dict[str, Any]:
    node: dict[str, Any] = {
        "name": "dev-handler",
        "arn": "arn:aws:lambda:eu-west-2:123456789012:function:dev-handler",
        "unresolved_resource_hints": hints,
    }
    if role:
        node["execution_role"] = {
            "role_arn": "arn:aws:iam::123456789012:role/dev-handler-role",
            "role_name": "dev-handler-role",
        }
    return node


def _all_hints() -> list[dict[str, str]]:
    return [
        _hint("STATE_BUCKET", "s3"),
        _hint("ORDER_QUEUE_URL", "sqs"),
        _hint("ORDER_TABLE_NAME", "dynamodb"),
        _hint("ORDER_TOPIC_ARN", "sns"),
        _hint("CUSTOM_EVENT_BUS_NAME", "eventbridge"),
        _hint("SHOPIFY_CLIENT_SECRET", "secretsmanager"),
        _hint("SHOPIFY_CONFIG_PARAMETER", "ssm"),
        _hint("DUCKDB_KEY", "kms"),
    ]


def _hint(identifier: str, service: str) -> dict[str, str]:
    return {
        "source": "environment_variable_key",
        "key": identifier,
        "likely_service": service,
        "reason": f"Environment key {identifier} suggests {service}.",
    }


def _first_candidate(
    hints: list[dict[str, Any]],
    service: str,
    candidate_key: str,
) -> dict[str, Any]:
    hint = next(item for item in hints if item["likely_service"] == service)
    return hint[candidate_key][0]


class FakeIdentity:
    account = "123456789012"


class FakeRuntime:
    def __init__(
        self,
        *,
        events: Any | None = None,
        iam: Any | None = None,
        s3: Any | None = None,
        sqs: Any | None = None,
        dynamodb: Any | None = None,
        sns: Any | None = None,
        secretsmanager: Any | None = None,
        ssm: Any | None = None,
        kms: Any | None = None,
    ) -> None:
        self.config = AwsSafeConfig(allowed_account_ids=["123456789012"])
        self.region = "eu-west-2"
        self.identity = FakeIdentity()
        self.events = events or FakeEventsClient()
        self.iam = iam or FakeAllowIamClient()
        self.s3 = s3 or FakeS3Client()
        self.sqs = sqs or FakeSqsClient()
        self.dynamodb = dynamodb or FakeDynamoDbClient()
        self.sns = sns or FakeSnsClient()
        self.secretsmanager = secretsmanager or FakeSecretsManagerClient()
        self.ssm = ssm or FakeSsmClient()
        self.kms = kms or FakeKmsClient()

    def client(self, service_name: str, region: str | None = None) -> Any:
        assert region in {"eu-west-2", None}
        if service_name == "events":
            return self.events
        if service_name == "iam":
            return self.iam
        if service_name == "s3":
            return self.s3
        if service_name == "sqs":
            return self.sqs
        if service_name == "dynamodb":
            return self.dynamodb
        if service_name == "sns":
            return self.sns
        if service_name == "secretsmanager":
            return self.secretsmanager
        if service_name == "ssm":
            return self.ssm
        if service_name == "kms":
            return self.kms
        raise AssertionError(service_name)

    def require_identity(self) -> FakeIdentity:
        return self.identity


class FakeEventsClient:
    def list_event_buses(self, **_: Any) -> dict[str, Any]:
        return {
            "EventBuses": [
                {
                    "Name": "custom",
                    "Arn": "arn:aws:events:eu-west-2:123456789012:event-bus/custom",
                },
                {
                    "Name": "default",
                    "Arn": "arn:aws:events:eu-west-2:123456789012:event-bus/default",
                },
            ]
        }


class FakeAllowIamClient:
    def simulate_principal_policy(self, **_: Any) -> dict[str, Any]:
        return {
            "EvaluationResults": [
                {
                    "EvalDecision": "allowed",
                    "MatchedStatements": [{"SourcePolicyId": "inline"}],
                    "MissingContextValues": [],
                }
            ]
        }


class FakeDenyIamClient:
    def simulate_principal_policy(self, **_: Any) -> dict[str, Any]:
        return {
            "EvaluationResults": [
                {
                    "EvalDecision": "implicitDeny",
                    "MatchedStatements": [],
                    "MissingContextValues": [],
                }
            ]
        }


class FakeS3Client:
    def list_buckets(self) -> dict[str, Any]:
        return {
            "Buckets": [
                {"Name": "dev-landing-bucket"},
                {"Name": "dev-state-bucket"},
                {"Name": "unrelated-bucket"},
            ]
        }


class FakeSqsClient:
    def list_queues(self, **_: Any) -> dict[str, Any]:
        return {
            "QueueUrls": [
                "https://sqs.eu-west-2.amazonaws.com/123456789012/dev-orders-queue",
                "https://sqs.eu-west-2.amazonaws.com/123456789012/unrelated-queue",
            ]
        }

    def get_queue_attributes(self, **kwargs: Any) -> dict[str, Any]:
        queue_name = str(kwargs["QueueUrl"]).rsplit("/", 1)[-1]
        return {"Attributes": {"QueueArn": f"arn:aws:sqs:eu-west-2:123456789012:{queue_name}"}}


class FakeDynamoDbClient:
    def list_tables(self, **_: Any) -> dict[str, Any]:
        return {"TableNames": ["dev-orders-table", "dev-state-table", "unrelated-table"]}


class FakeSnsClient:
    def list_topics(self, **_: Any) -> dict[str, Any]:
        return {
            "Topics": [
                {"TopicArn": "arn:aws:sns:eu-west-2:123456789012:dev-orders-topic"},
                {"TopicArn": "arn:aws:sns:eu-west-2:123456789012:unrelated-topic"},
            ]
        }


class FakeSecretsManagerClient:
    def list_secrets(self, **_: Any) -> dict[str, Any]:
        return {
            "SecretList": [
                {
                    "Name": "shopify/client",
                    "ARN": "arn:aws:secretsmanager:eu-west-2:123456789012:secret:shopify/client",
                },
                {
                    "Name": "database/password",
                    "ARN": "arn:aws:secretsmanager:eu-west-2:123456789012:secret:database/password",
                },
            ]
        }


class FakeSsmClient:
    def describe_parameters(self, **_: Any) -> dict[str, Any]:
        return {
            "Parameters": [
                {"Name": "/dev/shopify/config"},
                {"Name": "/dev/database/config"},
            ]
        }


class FakeKmsClient:
    def list_aliases(self, **_: Any) -> dict[str, Any]:
        return {
            "Aliases": [
                {"AliasName": "alias/duckdb", "TargetKeyId": "duckdb-key-id"},
                {"AliasName": "alias/database", "TargetKeyId": "database-key-id"},
            ],
            "Truncated": False,
        }


class EmptySecretsManagerClient:
    def list_secrets(self, **_: Any) -> dict[str, Any]:
        return {"SecretList": []}


class EmptySsmClient:
    def describe_parameters(self, **_: Any) -> dict[str, Any]:
        return {"Parameters": []}


class EmptyKmsClient:
    def list_aliases(self, **_: Any) -> dict[str, Any]:
        return {"Aliases": [], "Truncated": False}


class FailingS3Client:
    def list_buckets(self) -> dict[str, Any]:
        raise _client_error("ListBuckets")


class FailingSqsClient:
    def list_queues(self, **_: Any) -> dict[str, Any]:
        raise _client_error("ListQueues")


class FailingDynamoDbClient:
    def list_tables(self, **_: Any) -> dict[str, Any]:
        raise _client_error("ListTables")


class FailingSnsClient:
    def list_topics(self, **_: Any) -> dict[str, Any]:
        raise _client_error("ListTopics")


class FailingEventsClient:
    def list_event_buses(self, **_: Any) -> dict[str, Any]:
        raise _client_error("ListEventBuses")


class FailingSecretsManagerClient:
    def list_secrets(self, **_: Any) -> dict[str, Any]:
        raise _client_error("ListSecrets")


class FailingSsmClient:
    def describe_parameters(self, **_: Any) -> dict[str, Any]:
        raise _client_error("DescribeParameters")


class FailingKmsClient:
    def list_aliases(self, **_: Any) -> dict[str, Any]:
        raise _client_error("ListAliases")


def _client_error(operation: str) -> ClientError:
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, operation)
