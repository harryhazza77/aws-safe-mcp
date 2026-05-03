from __future__ import annotations

import json
import logging

import pytest

from aws_safe_mcp.audit import AuditLogger
from aws_safe_mcp.config import RedactionConfig


class ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def test_audit_logger_binds_positional_and_keyword_arguments() -> None:
    logger = logging.getLogger("test_audit_logger_binds")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = ListHandler()
    logger.addHandler(handler)
    audit = AuditLogger(logger=logger, redaction=RedactionConfig())

    @audit.tool("demo")
    def demo(first: str, second: str, token: str) -> str:
        return first + second + token

    assert demo("a", second="b", token="secret") == "absecret"

    started = json.loads(handler.messages[0])
    assert started["arguments"] == {
        "first": "a",
        "second": "b",
        "token": "[REDACTED]",
    }


def test_audit_logger_logs_bound_arguments_on_failure() -> None:
    logger = logging.getLogger("test_audit_logger_failure")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = ListHandler()
    logger.addHandler(handler)
    audit = AuditLogger(logger=logger, redaction=RedactionConfig())

    @audit.tool("demo")
    def demo(resource: str) -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        demo("thing")

    failed = json.loads(handler.messages[1])
    assert failed["event"] == "tool_call_failed"
    assert failed["arguments"] == {"resource": "thing"}
    assert failed["error_type"] == "ValueError"
