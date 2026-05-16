"""Unit tests for SQS private helpers.

These cover the pure-logic branches that moto can't realistically
exercise: policy decision rules, signal classifiers, and value
normalizers. Kept separate from moto-driven integration so the
helpers can iterate fast without spinning up a mock backend.
"""

from __future__ import annotations

from aws_safe_mcp.tools.sqs import (
    _action_matches,
    _dlq_replay_first_edge,
    _dlq_replay_summary,
    _first_sqs_backlog_bottleneck,
    _lambda_name_from_arn,
    _optional_bool,
    _optional_int,
    _permission_summary,
    _principal_matches,
    _queue_name_from_arn,
    _queue_policy_decision,
    _sqs_backlog_stall_summary,
    _sqs_lambda_delivery_summary,
)

# ---------------------------------------------------------------------------
# _queue_policy_decision
# ---------------------------------------------------------------------------


def test_queue_policy_decision_returns_unknown_for_no_policy() -> None:
    assert _queue_policy_decision(None, "events.amazonaws.com", "sqs:SendMessage") == "unknown"


def test_queue_policy_decision_returns_allowed_for_matching_service_principal() -> None:
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
            }
        ]
    }
    assert (
        _queue_policy_decision(policy, "events.amazonaws.com", "sqs:SendMessage") == "allowed"
    )


def test_queue_policy_decision_returns_allowed_for_wildcard_principal() -> None:
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sqs:*",
        }
    }
    assert _queue_policy_decision(policy, "events.amazonaws.com", "sqs:SendMessage") == "allowed"


def test_queue_policy_decision_returns_unknown_when_effect_is_deny() -> None:
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
            }
        ]
    }
    assert _queue_policy_decision(policy, "events.amazonaws.com", "sqs:SendMessage") == "unknown"


def test_queue_policy_decision_skips_non_dict_statements() -> None:
    assert _queue_policy_decision({"Statement": "garbage"}, "x", "y") == "unknown"


# ---------------------------------------------------------------------------
# _principal_matches
# ---------------------------------------------------------------------------


def test_principal_matches_wildcard_string() -> None:
    assert _principal_matches("*", "events.amazonaws.com") is True


def test_principal_matches_service_string() -> None:
    assert _principal_matches({"Service": "lambda.amazonaws.com"}, "lambda.amazonaws.com")


def test_principal_matches_service_list() -> None:
    assert _principal_matches(
        {"Service": ["sns.amazonaws.com", "events.amazonaws.com"]},
        "events.amazonaws.com",
    )


def test_principal_matches_rejects_non_dict_non_wildcard() -> None:
    assert _principal_matches("arn:aws:iam::123:role/x", "lambda.amazonaws.com") is False


def test_principal_matches_returns_false_when_no_service_key() -> None:
    assert _principal_matches({"AWS": "arn:aws:iam::123:role/x"}, "lambda.amazonaws.com") is False


# ---------------------------------------------------------------------------
# _action_matches
# ---------------------------------------------------------------------------


def test_action_matches_exact_string() -> None:
    assert _action_matches("sqs:SendMessage", "sqs:SendMessage") is True


def test_action_matches_service_wildcard_string() -> None:
    assert _action_matches("sqs:*", "sqs:SendMessage") is True


def test_action_matches_universal_wildcard_string() -> None:
    assert _action_matches("*", "sqs:SendMessage") is True


def test_action_matches_list_with_target() -> None:
    assert _action_matches(["sqs:DeleteMessage", "sqs:SendMessage"], "sqs:SendMessage") is True


def test_action_matches_list_with_wildcard() -> None:
    assert _action_matches(["sqs:*"], "sqs:SendMessage") is True


def test_action_matches_returns_false_for_unsupported_type() -> None:
    assert _action_matches({"sqs:SendMessage"}, "sqs:SendMessage") is False


# ---------------------------------------------------------------------------
# _permission_summary
# ---------------------------------------------------------------------------


def test_permission_summary_counts_each_decision_bucket() -> None:
    checks = [
        {"decision": "allowed"},
        {"decision": "allowed"},
        {"decision": "denied"},
        {"decision": "unknown"},
        {"decision": "explicit_deny"},
    ]
    summary = _permission_summary(checks)
    assert summary == {"allowed": 2, "denied": 1, "unknown": 1, "explicit_denies": 1}


# ---------------------------------------------------------------------------
# ARN and value normalizers
# ---------------------------------------------------------------------------


def test_queue_name_from_arn() -> None:
    assert _queue_name_from_arn("arn:aws:sqs:eu-west-2:123:dev-queue") == "dev-queue"


def test_lambda_name_from_arn_returns_none_for_non_string() -> None:
    assert _lambda_name_from_arn(None) is None
    assert _lambda_name_from_arn(123) is None


def test_lambda_name_from_arn_returns_function_name() -> None:
    assert (
        _lambda_name_from_arn(
            "arn:aws:lambda:eu-west-2:123:function:dev-handler"
        )
        == "dev-handler"
    )


def test_optional_int_handles_blank_and_invalid() -> None:
    assert _optional_int(None) is None
    assert _optional_int("not-a-number") is None
    assert _optional_int("42") == 42
    assert _optional_int(7) == 7


def test_optional_bool_handles_variants() -> None:
    assert _optional_bool(None) is None
    assert _optional_bool(True) is True
    assert _optional_bool("true") is True
    assert _optional_bool("FALSE") is False


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------


def test_sqs_lambda_delivery_summary_reports_ready_status() -> None:
    summary = _sqs_lambda_delivery_summary(
        {"risks": [], "mapping_count": 1, "risk_count": 0}
    )
    assert summary["status"] == "ready"


def test_sqs_lambda_delivery_summary_reports_no_mapping() -> None:
    summary = _sqs_lambda_delivery_summary(
        {"risks": [], "mapping_count": 0, "risk_count": 0}
    )
    assert summary["status"] == "no_lambda_mapping"


def test_sqs_lambda_delivery_summary_flags_risks() -> None:
    summary = _sqs_lambda_delivery_summary(
        {"risks": ["queue_redrive_not_configured"], "mapping_count": 1, "risk_count": 1}
    )
    assert summary["status"] == "needs_attention"


def test_sqs_backlog_stall_summary_reports_status() -> None:
    detected = _sqs_backlog_stall_summary(
        {
            "risks": ["lambda_throttles_observed"],
            "risk_count": 1,
        }
    )
    assert detected["status"] == "stall_signals_detected"
    assert detected["first_likely_bottleneck"] == "lambda_throttles_observed"
    empty = _sqs_backlog_stall_summary({"risks": [], "risk_count": 0})
    assert empty["status"] == "no_stall_signals"
    assert empty["first_likely_bottleneck"] is None


def test_first_sqs_backlog_bottleneck_returns_none_for_empty_risks() -> None:
    assert _first_sqs_backlog_bottleneck([]) is None


def test_first_sqs_backlog_bottleneck_prefers_known_risks() -> None:
    assert (
        _first_sqs_backlog_bottleneck(["consumer_throttled", "backlog_present"])
        is not None
    )


def test_dlq_replay_summary_has_status_field() -> None:
    summary = _dlq_replay_summary({"risks": [], "cautions": []})
    assert "status" in summary
    risky = _dlq_replay_summary(
        {"risks": ["dlq_has_active_lambda_consumer"], "cautions": []}
    )
    assert risky["status"] == "not_ready"


def test_dlq_replay_first_edge_returns_known_edge() -> None:
    edge = _dlq_replay_first_edge({"risks": [], "cautions": []})
    assert isinstance(edge, str)
    risky_edge = _dlq_replay_first_edge(
        {"risks": ["dlq_has_active_lambda_consumer"], "cautions": []}
    )
    # First-edge mapping translates the raw risk to a stable edge label.
    assert isinstance(risky_edge, str)
    assert risky_edge != ""
