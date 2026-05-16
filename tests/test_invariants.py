"""Project-level invariant tests.

These tests pin guarantees that are easy to break by accident:

1. Every MCP tool registered via ``@mcp.tool()`` is also wrapped by
   ``@audit.tool(...)`` so every public entry point produces an audit
   record. Drift here means a tool can be invoked without leaving an
   audit trail.

2. Tool modules contain no calls to mutating boto3 verbs. ``aws-safe-mcp``
   is a read-only investigation surface; introducing a write call must be
   a deliberate, scope-changing decision rather than a quiet drift.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_PATH = REPO_ROOT / "src" / "aws_safe_mcp" / "server.py"
TOOLS_DIR = REPO_ROOT / "src" / "aws_safe_mcp" / "tools"

# Mutating boto3 verbs that must not appear on any client call in tool
# modules. ``simulate_*`` is intentionally allowed because IAM policy
# simulation is read-only despite the name suffix.
MUTATING_VERB_PREFIXES = (
    "put_",
    "post_",
    "create_",
    "delete_",
    "update_",
    "modify_",
    "send_",
    "publish",
    "invoke",
    "start_execution",
    "stop_execution",
    "redrive",
    "purge_",
    "tag_",
    "untag_",
    "attach_",
    "detach_",
    "associate_",
    "disassociate_",
    "set_",
    "register_",
    "deregister_",
)

# Boto3 calls that look mutating (or share a prefix with a mutating verb)
# but are read-only in practice. Document each exception explicitly.
READ_ONLY_EXCEPTIONS: frozenset[str] = frozenset(
    {
        # CloudWatch Logs Insights: schedules an asynchronous query and
        # returns a query id. No log data is modified.
        "start_query",
        # IAM policy simulation: read-only evaluator of identity/resource
        # policies; returns decisions, never mutates policies.
        "simulate_principal_policy",
        "simulate_custom_policy",
    }
)


def _iter_tool_files() -> list[Path]:
    return sorted(p for p in TOOLS_DIR.glob("*.py") if p.name != "__init__.py")


def _tool_pairs(source: str) -> list[tuple[int, str | None]]:
    """Return ``(mcp_tool_line, audit_tool_name)`` pairs from server.py.

    ``audit_tool_name`` is ``None`` when the ``@mcp.tool()`` decorator is
    not immediately preceded or followed by an ``@audit.tool(...)``
    decorator on the same function definition.
    """
    tree = ast.parse(source)
    pairs: list[tuple[int, str | None]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        decorators = node.decorator_list
        mcp_line: int | None = None
        audit_name: str | None = None
        for dec in decorators:
            if _is_mcp_tool(dec):
                mcp_line = dec.lineno
            elif _is_audit_tool(dec):
                audit_name = _audit_tool_name(dec)
        if mcp_line is not None:
            pairs.append((mcp_line, audit_name))
    return pairs


def _is_mcp_tool(node: ast.expr) -> bool:
    if isinstance(node, ast.Call):
        return _is_mcp_tool(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr == "tool" and _attr_root(node.value) == "mcp"
    return False


def _is_audit_tool(node: ast.expr) -> bool:
    if isinstance(node, ast.Call):
        return _is_audit_tool(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr == "tool" and _attr_root(node.value) == "audit"
    return False


def _audit_tool_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Call) and node.args:
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def _attr_root(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _attr_root(node.value)
    return None


def test_every_mcp_tool_is_audit_wrapped() -> None:
    source = SERVER_PATH.read_text()
    pairs = _tool_pairs(source)
    assert pairs, "expected to find @mcp.tool() decorated functions in server.py"
    missing = [line for line, name in pairs if not name]
    assert not missing, (
        "Every @mcp.tool() in server.py must also be wrapped with "
        f"@audit.tool(...). Unwrapped @mcp.tool() at lines: {missing}"
    )


def test_audit_tool_names_are_unique() -> None:
    source = SERVER_PATH.read_text()
    names = [name for _, name in _tool_pairs(source) if name]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    assert not duplicates, (
        "Each @audit.tool(...) name must be unique across the registry. "
        f"Duplicates: {duplicates}"
    )


@pytest.mark.parametrize("path", _iter_tool_files(), ids=lambda p: p.name)
def test_no_mutating_boto3_calls(path: Path) -> None:
    """Static grep for mutating boto3 verbs in each tool module."""
    source = path.read_text()
    # `client.<verb>(`, `<client>.<verb>(` — pick attribute-style calls.
    pattern = re.compile(r"\.([a-z][a-z0-9_]*)\(")
    violations: list[tuple[str, int]] = []
    for line_num, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for match in pattern.finditer(line):
            verb = match.group(1)
            if verb in READ_ONLY_EXCEPTIONS:
                continue
            if any(verb.startswith(prefix) for prefix in MUTATING_VERB_PREFIXES):
                violations.append((verb, line_num))
    # Filter to only those that look like SDK calls — i.e. preceded by a
    # likely client object name. We use a permissive filter; false
    # positives are caught by READ_ONLY_EXCEPTIONS as they arise.
    sdk_violations = [
        (verb, line_num)
        for verb, line_num in violations
        if _looks_like_sdk_call(source.splitlines()[line_num - 1], verb)
    ]
    assert not sdk_violations, (
        f"{path.name} contains apparent mutating SDK calls: {sdk_violations}. "
        "aws-safe-mcp is a read-only investigation surface. If this call is "
        "genuinely read-only, add the verb to READ_ONLY_EXCEPTIONS with a "
        "comment explaining why."
    )


def _looks_like_sdk_call(line: str, verb: str) -> bool:
    """Heuristic: the verb is invoked on a name suggestive of a boto3 client."""
    pattern = re.compile(
        r"(?:^|[\s(])(?:[a-z_][a-z0-9_]*)\." + re.escape(verb) + r"\("
    )
    if not pattern.search(line):
        return False
    # Skip self-method calls and internal helpers (snake_case dotted names
    # where the receiver looks like a helper rather than a client). The
    # main signal we want is `<client>.<verb>(...)` where the verb prefix
    # matches MUTATING_VERB_PREFIXES; helper functions like `_send_query`
    # are caught here but those are internal calls, not boto3 calls.
    # Internal helper functions are typically prefixed with `_`, so skip
    # those.
    receiver_match = re.search(
        r"(?:^|[\s(])([a-z_][a-z0-9_]*)\." + re.escape(verb) + r"\(", line
    )
    return not (receiver_match and receiver_match.group(1).startswith("_"))
