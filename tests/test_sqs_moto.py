"""SQS tool integration tests against moto.

Also targets coverage on the heavier helpers: lambda event-source
mapping, EventBridge fan-in, DLQ replay readiness, queue policy
inspection, and SQS→Lambda delivery checks. Each test wires the real
service relationship in moto so the corresponding code path executes
against the AWS shape rather than a hand-rolled fake.
"""

from __future__ import annotations

import io
import json
import zipfile

import boto3

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.tools.sqs import (
    analyze_queue_dlq_replay_readiness,
    check_sqs_to_lambda_delivery,
    explain_sqs_queue_dependencies,
    get_sqs_queue_summary,
    investigate_sqs_backlog_stall,
    list_sqs_queues,
)
from tests.conftest import MOTO_ACCOUNT_ID, MOTO_REGION


def _zip_handler() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("index.py", "def handler(event, context): return {}\n")
    return buffer.getvalue()


def _trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _seed_lambda(name: str) -> str:
    iam = boto3.client("iam", region_name=MOTO_REGION)
    role = iam.create_role(RoleName=f"{name}-role", AssumeRolePolicyDocument=_trust_policy())[
        "Role"
    ]
    response = boto3.client("lambda", region_name=MOTO_REGION).create_function(
        FunctionName=name,
        Runtime="python3.11",
        Role=role["Arn"],
        Handler="index.handler",
        Code={"ZipFile": _zip_handler()},
    )
    return str(response["FunctionArn"])


def _create_queue(name: str, attributes: dict[str, str] | None = None) -> str:
    client = boto3.client("sqs", region_name=MOTO_REGION)
    response = client.create_queue(
        QueueName=name,
        Attributes=attributes or {},
    )
    return str(response["QueueUrl"])


def test_list_sqs_queues_filters_by_prefix(moto_runtime: AwsRuntime) -> None:
    _create_queue("dev-orders")
    _create_queue("dev-payments")
    _create_queue("prod-orders")

    result = list_sqs_queues(moto_runtime, name_prefix="dev-")

    names = sorted(item["queue_name"] for item in result["queues"])
    assert names == ["dev-orders", "dev-payments"]


def test_get_sqs_queue_summary_returns_attributes(moto_runtime: AwsRuntime) -> None:
    queue_url = _create_queue(
        "dev-summary",
        attributes={"VisibilityTimeout": "45", "MessageRetentionPeriod": "600"},
    )

    result = get_sqs_queue_summary(moto_runtime, queue_url)

    assert result["queue_name"] == "dev-summary"
    assert result["queue_url"] == queue_url
    assert result["region"] == MOTO_REGION
    assert result["fifo"] is False
    assert result["visibility_timeout_seconds"] == 45
    assert result["message_retention_seconds"] == 600
    assert result["queue_arn"].endswith(":dev-summary")


def test_get_sqs_queue_summary_handles_fifo_and_dlq(moto_runtime: AwsRuntime) -> None:
    dlq_url = _create_queue("dev-dlq.fifo", attributes={"FifoQueue": "true"})
    sqs = boto3.client("sqs", region_name=MOTO_REGION)
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    redrive = {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "5"}
    primary_url = _create_queue(
        "dev-primary.fifo",
        attributes={"FifoQueue": "true", "RedrivePolicy": json.dumps(redrive)},
    )

    result = get_sqs_queue_summary(moto_runtime, primary_url)

    assert result["fifo"] is True
    assert result["dead_letter"]["configured"] is True
    assert result["dead_letter"]["max_receive_count"] == 5
    assert result["dead_letter"]["dead_letter_target_arn"].endswith(":dev-dlq.fifo")


def test_explain_sqs_queue_dependencies_returns_empty_topology_for_idle_queue(
    moto_runtime: AwsRuntime,
) -> None:
    queue_url = _create_queue("dev-idle")

    result = explain_sqs_queue_dependencies(
        moto_runtime, queue_url, include_permission_checks=False
    )

    assert result["queue_name"] == "dev-idle"
    assert result["region"] == MOTO_REGION
    assert result["nodes"]["lambda_event_source_mappings"] == []
    assert result["nodes"]["eventbridge_rules"] == []
    assert result["nodes"]["dead_letter_queue"] is None
    assert isinstance(result["edges"], list)
    assert f"arn:aws:sqs:{MOTO_REGION}:{MOTO_ACCOUNT_ID}:dev-idle" in result["queue_arn"]


def test_investigate_sqs_backlog_stall_against_empty_queue(
    moto_runtime: AwsRuntime,
) -> None:
    queue_url = _create_queue("dev-stall")

    result = investigate_sqs_backlog_stall(moto_runtime, queue_url)

    assert result["queue_name"] == "dev-stall"
    assert result["region"] == MOTO_REGION
    # Empty queue: no backlog signals fire.
    assert result["summary"]["status"] == "no_stall_signals"


# ---------------------------------------------------------------------------
# Extended coverage: lambda event source mapping fan-in
# ---------------------------------------------------------------------------


def test_explain_sqs_queue_dependencies_with_lambda_consumer(
    moto_runtime: AwsRuntime,
) -> None:
    queue_url = _create_queue("dev-with-consumer")
    sqs = boto3.client("sqs", region_name=MOTO_REGION)
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    _seed_lambda("dev-sqs-consumer")
    boto3.client("lambda", region_name=MOTO_REGION).create_event_source_mapping(
        EventSourceArn=queue_arn,
        FunctionName="dev-sqs-consumer",
        BatchSize=5,
    )

    result = explain_sqs_queue_dependencies(
        moto_runtime, queue_url, include_permission_checks=False
    )

    mappings = result["nodes"]["lambda_event_source_mappings"]
    assert len(mappings) == 1
    assert mappings[0]["function_arn"].endswith("dev-sqs-consumer")
    # An edge to the consumer Lambda is rendered in the dependency graph.
    assert any(
        edge.get("target", "").endswith("dev-sqs-consumer")
        or edge.get("target_arn", "").endswith("dev-sqs-consumer")
        for edge in result["edges"]
    )


def test_check_sqs_to_lambda_delivery_returns_signals(moto_runtime: AwsRuntime) -> None:
    queue_url = _create_queue("dev-delivery")
    sqs = boto3.client("sqs", region_name=MOTO_REGION)
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    _seed_lambda("dev-delivery-consumer")
    boto3.client("lambda", region_name=MOTO_REGION).create_event_source_mapping(
        EventSourceArn=queue_arn,
        FunctionName="dev-delivery-consumer",
        BatchSize=5,
    )

    result = check_sqs_to_lambda_delivery(moto_runtime, queue_url)

    assert result["queue_name"] == "dev-delivery"
    assert result["region"] == MOTO_REGION
    assert len(result["mappings"]) == 1
    diagnostic = result["mappings"][0]
    assert diagnostic["function_name"].endswith("dev-delivery-consumer")
    assert isinstance(result["signals"], dict)
    assert "status" in result["summary"]


# ---------------------------------------------------------------------------
# Extended coverage: DLQ replay readiness
# ---------------------------------------------------------------------------


def test_analyze_queue_dlq_replay_readiness_with_source_queues(
    moto_runtime: AwsRuntime,
) -> None:
    dlq_url = _create_queue("dev-replay-dlq")
    sqs = boto3.client("sqs", region_name=MOTO_REGION)
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    redrive = {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "3"}
    source_url = _create_queue(
        "dev-replay-source",
        attributes={"RedrivePolicy": json.dumps(redrive)},
    )

    result = analyze_queue_dlq_replay_readiness(
        moto_runtime, dlq_url, source_queue_urls=[source_url]
    )

    assert result["dlq_queue_name"] == "dev-replay-dlq"
    assert result["region"] == MOTO_REGION
    assert result["messages_returned"] is False
    assert result["replay_performed"] is False
    assert len(result["source_queues"]) == 1
    assert result["source_queues"][0]["queue_name"] == "dev-replay-source"
    assert "status" in result["summary"]


# ---------------------------------------------------------------------------
# Extended coverage: queue policy + EventBridge fan-in
# ---------------------------------------------------------------------------


def test_explain_sqs_queue_dependencies_with_eventbridge_target(
    moto_runtime: AwsRuntime,
) -> None:
    queue_url = _create_queue("dev-eb-target")
    sqs = boto3.client("sqs", region_name=MOTO_REGION)
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    events = boto3.client("events", region_name=MOTO_REGION)
    events.put_rule(
        Name="dev-rule",
        EventPattern=json.dumps({"source": ["dev.app"]}),
        State="ENABLED",
    )
    events.put_targets(
        Rule="dev-rule",
        Targets=[{"Id": "target-1", "Arn": queue_arn}],
    )

    result = explain_sqs_queue_dependencies(
        moto_runtime, queue_url, include_permission_checks=False
    )

    targets = result["nodes"]["eventbridge_rules"]
    assert len(targets) == 1
    assert targets[0]["rule_name"] == "dev-rule"
    assert targets[0]["target_arn"] == queue_arn


def test_get_sqs_queue_summary_decodes_queue_policy(moto_runtime: AwsRuntime) -> None:
    queue_url = _create_queue("dev-policy-queue")
    sqs = boto3.client("sqs", region_name=MOTO_REGION)
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    result = get_sqs_queue_summary(moto_runtime, queue_url)

    assert result["policy"]["available"] is True
    assert result["policy"]["statement_count"] == 1
    # Raw policy document body is not returned in the summary.
    assert "Allow" not in json.dumps(result["policy"])
    assert "Resource" not in json.dumps(result["policy"])
