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
SRC_ROOT = REPO_ROOT / "src" / "aws_safe_mcp"
SERVER_PATH = SRC_ROOT / "server.py"
TOOLS_DIR = SRC_ROOT / "tools"
AUTH_PATH = SRC_ROOT / "auth.py"
S3_TOOL_PATH = TOOLS_DIR / "s3.py"
DYNAMODB_TOOL_PATH = TOOLS_DIR / "dynamodb.py"

# S3 verbs that read or transfer object payloads / directory content.
# aws-safe-mcp must never pull S3 object bodies through the MCP surface;
# even read-only data-plane verbs leak content into model context.
S3_FORBIDDEN_VERBS: frozenset[str] = frozenset(
    {
        # Returns the object body bytes.
        "get_object",
        # Streams filtered object content (SQL over CSV/JSON/Parquet).
        "select_object_content",
        # Returns a BitTorrent file describing the object payload.
        "get_object_torrent",
        # HEAD can be used as a body-read probe via Range; forbid to keep
        # the surface clean (metadata is covered by get_s3_bucket_summary).
        "head_object",
        # Mutating: initiates a Glacier restore (changes object state).
        "restore_object",
        # Downloads an object body to local disk.
        "download_file",
        # Downloads an object body to a file-like object.
        "download_fileobj",
        # Server-side copy: reads source body and writes a new object.
        "copy_object",
        # Catch-all for upload_file / upload_fileobj / upload_part / etc.
        # Handled separately via prefix match below.
    }
)

# DynamoDB verbs that return item bodies or stream records. aws-safe-mcp
# exposes table metadata and dependency posture only; row data and stream
# payloads must not flow through the MCP surface.
DYNAMODB_FORBIDDEN_VERBS: frozenset[str] = frozenset(
    {
        # Returns every item in the table (or index).
        "scan",
        # Returns matching items for a partition/sort key expression.
        "query",
        # Returns a single item by primary key.
        "get_item",
        # Returns multiple items by primary key across tables.
        "batch_get_item",
        # Returns items inside a read transaction.
        "transact_get_items",
        # DynamoDB Streams: returns stream records (item images).
        "get_records",
        # DynamoDB Streams: opens a shard iterator that yields records.
        "get_shard_iterator",
    }
)

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
        f"Each @audit.tool(...) name must be unique across the registry. Duplicates: {duplicates}"
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
    pattern = re.compile(r"(?:^|[\s(])(?:[a-z_][a-z0-9_]*)\." + re.escape(verb) + r"\(")
    if not pattern.search(line):
        return False
    # Skip self-method calls and internal helpers (snake_case dotted names
    # where the receiver looks like a helper rather than a client). The
    # main signal we want is `<client>.<verb>(...)` where the verb prefix
    # matches MUTATING_VERB_PREFIXES; helper functions like `_send_query`
    # are caught here but those are internal calls, not boto3 calls.
    # Internal helper functions are typically prefixed with `_`, so skip
    # those.
    receiver_match = re.search(r"(?:^|[\s(])([a-z_][a-z0-9_]*)\." + re.escape(verb) + r"\(", line)
    return not (receiver_match and receiver_match.group(1).startswith("_"))


def _iter_source_files() -> list[Path]:
    """Every ``.py`` under ``src/aws_safe_mcp/`` (recursive)."""
    return sorted(
        p
        for p in SRC_ROOT.rglob("*.py")
        if "__pycache__" not in p.parts and p.name != "__init__.py"
    )


def _function_param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """All parameter names defined on a function (pos, kw-only, *args, **kwargs)."""
    args = func.args
    names: set[str] = set()
    for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
        names.add(arg.arg)
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    return names


def _is_boto_client_call(call: ast.Call) -> bool:
    """``boto3.client(...)`` or ``<session>.client(...)`` style calls."""
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr != "client":
        return False
    receiver = func.value
    if isinstance(receiver, ast.Name) and receiver.id == "boto3":
        return True
    # ``session.client(...)`` / ``self._session.client(...)`` etc.
    return isinstance(receiver, (ast.Name, ast.Attribute))


def test_no_raw_aws_call_passthrough() -> None:
    """No generic AWS SDK passthrough tool may exist.

    Two failure modes are rejected statically:

    1. Any function named ``aws_call`` — the canonical name for a
       service/operation passthrough — regardless of where it lives.
    2. Any ``boto3.client(service, ...)`` or ``<session>.client(service,
       ...)`` where ``service`` is a parameter of the enclosing function
       rather than a string literal. Caller-controlled service names turn
       the tool into an arbitrary AWS SDK gateway.

    ``src/aws_safe_mcp/auth.py`` is exempt: ``AwsRuntime.client`` is the
    one legitimate place that accepts a service-name argument.
    """
    violations: list[str] = []
    for path in _iter_source_files():
        if path == AUTH_PATH:
            continue
        tree = ast.parse(path.read_text())
        visitor = _PassthroughVisitor(path, violations)
        visitor.visit(tree)

    assert not violations, (
        "Generic AWS SDK passthrough is forbidden. aws-safe-mcp exposes "
        "a fixed catalogue of read-only investigation tools, not an "
        "arbitrary boto3 gateway. Offending sites:\n  " + "\n  ".join(violations)
    )


class _PassthroughVisitor(ast.NodeVisitor):
    """Walk a module and record AWS-passthrough violations into ``sink``."""

    def __init__(self, path: Path, sink: list[str]) -> None:
        self._path = path
        self._sink = sink
        # Parameter scope stack so ``boto3.client(<param>)`` can be detected
        # as caller-controlled.
        self._func_stack: list[set[str]] = []

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if node.name == "aws_call":
            self._sink.append(
                f"{self._path.relative_to(REPO_ROOT)}:{node.lineno}: "
                "function named 'aws_call' is a forbidden generic "
                "AWS SDK passthrough"
            )
        self._func_stack.append(_function_param_names(node))
        try:
            self.generic_visit(node)
        finally:
            self._func_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def visit_Call(self, node: ast.Call) -> None:
        if (
            _is_boto_client_call(node)
            and node.args
            and isinstance(node.args[0], ast.Name)
            and any(node.args[0].id in scope for scope in self._func_stack)
        ):
            self._sink.append(
                f"{self._path.relative_to(REPO_ROOT)}:{node.lineno}: "
                f"boto3/session .client() called with "
                f"parameter '{node.args[0].id}' as service name; "
                "service must be a string literal"
            )
        self.generic_visit(node)


def _verb_call_lines(source: str, verbs: frozenset[str]) -> list[tuple[str, int]]:
    """Return ``(verb, line_no)`` pairs for ``<receiver>.<verb>(`` calls.

    Mirrors the style of ``test_no_mutating_boto3_calls``: attribute-style
    SDK calls only, skipping comments and helper functions whose receiver
    starts with ``_``.
    """
    pattern = re.compile(r"\.([a-z][a-z0-9_]*)\(")
    hits: list[tuple[str, int]] = []
    lines = source.splitlines()
    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for match in pattern.finditer(line):
            verb = match.group(1)
            if verb not in verbs:
                continue
            if _looks_like_sdk_call(line, verb):
                hits.append((verb, line_num))
    return hits


def test_no_s3_object_body_or_directory_listing_with_content() -> None:
    """``s3.py`` must not call any data-plane object verb.

    The S3 tool surface only exposes bucket-level posture (encryption,
    public access, lifecycle, notifications). Pulling object bodies — or
    any verb that streams object content — through the MCP surface would
    leak customer data into model context.
    """
    source = S3_TOOL_PATH.read_text()
    hits = _verb_call_lines(source, S3_FORBIDDEN_VERBS)

    # Additionally reject any ``upload_*`` verb via prefix match.
    pattern = re.compile(r"\.(upload_[a-z0-9_]*)\(")
    for line_num, line in enumerate(source.splitlines(), start=1):
        if line.strip().startswith("#"):
            continue
        for match in pattern.finditer(line):
            verb = match.group(1)
            if _looks_like_sdk_call(line, verb):
                hits.append((verb, line_num))

    assert not hits, (
        f"{S3_TOOL_PATH.name} must not call S3 data-plane verbs. "
        f"Offending calls: {hits}. "
        "aws-safe-mcp exposes bucket posture only; object bodies and "
        "directory content listings with body data are out of scope."
    )


def test_no_dynamodb_item_or_stream_record_reads() -> None:
    """``dynamodb.py`` must not read items or stream records.

    The DynamoDB tool surface exposes table metadata, capacity, stream
    configuration, and dependency posture — never row data. Reads of
    item bodies (scan/query/get_item/...) or stream records would leak
    customer data through the MCP surface.
    """
    source = DYNAMODB_TOOL_PATH.read_text()
    hits = _verb_call_lines(source, DYNAMODB_FORBIDDEN_VERBS)
    assert not hits, (
        f"{DYNAMODB_TOOL_PATH.name} must not call DynamoDB item-read or "
        f"stream-read verbs. Offending calls: {hits}. "
        "Expose metadata and posture only; item bodies and stream "
        "records are out of scope for aws-safe-mcp."
    )
