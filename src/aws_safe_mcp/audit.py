from __future__ import annotations

import inspect
import json
import logging
import time
from collections.abc import Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from aws_safe_mcp.config import RedactionConfig
from aws_safe_mcp.redaction import redact_data

P = ParamSpec("P")
R = TypeVar("R")


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")


class AuditLogger:
    """Structured audit logger for MCP tool calls.

    Arguments are bound against the wrapped function signature before logging so
    positional and keyword inputs are captured consistently, then redacted.
    """

    def __init__(
        self,
        logger: logging.Logger | None = None,
        redaction: RedactionConfig | None = None,
    ) -> None:
        self._logger = logger or logging.getLogger("aws_safe_mcp.audit")
        self._redaction = redaction or RedactionConfig()

    def tool(self, name: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Decorate a tool function with start, success, and failure audit events."""

        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            @wraps(func)
            def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
                started = time.perf_counter()
                arguments = self._bound_arguments(func, args, kwargs)
                self.log_event("tool_call_started", name, arguments, None, None)
                try:
                    result = func(*args, **kwargs)
                except Exception as exc:
                    duration_ms = int((time.perf_counter() - started) * 1000)
                    self.log_event(
                        "tool_call_failed",
                        name,
                        arguments,
                        duration_ms,
                        exc.__class__.__name__,
                    )
                    raise
                duration_ms = int((time.perf_counter() - started) * 1000)
                self.log_event("tool_call_completed", name, arguments, duration_ms, None)
                return result

            return wrapped

        return decorator

    def _bound_arguments(
        self,
        func: Callable[P, R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            bound = inspect.signature(func).bind_partial(*args, **kwargs)
        except TypeError:
            return {"args": list(args), "kwargs": kwargs}
        bound.apply_defaults()
        return dict(bound.arguments)

    def log_event(
        self,
        event: str,
        tool_name: str,
        arguments: dict[str, Any],
        duration_ms: int | None,
        error_type: str | None,
    ) -> None:
        payload = {
            "event": event,
            "tool": tool_name,
            "arguments": redact_data(arguments, self._redaction),
            "duration_ms": duration_ms,
            "error_type": error_type,
        }
        self._logger.info(json.dumps(payload, sort_keys=True))
