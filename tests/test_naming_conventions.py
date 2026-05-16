"""Public API naming conventions.

Semantic naming rules ruff cannot express. Style contract for the MCP
tool surface and the underlying tool modules. Pinning these here keeps
the public API consistent as the surface grows — drift surfaces as a
test failure with a clear remediation message.

Scope:
1. Every MCP tool name starts with an approved verb prefix.
2. Tool function names ending in ``_summary`` start with ``get_``.
3. Tool function names starting with ``list_`` end in a plural noun
   (heuristic: ends with ``s``).
4. Each tool module's public function names contain the module's
   subject keyword (e.g. functions in ``lambda_tools.py`` must contain
   ``lambda``).

If a rule fires on a genuinely sound exception, add the function to
``NAMING_EXCEPTIONS`` with a comment explaining why.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_PATH = REPO_ROOT / "src" / "aws_safe_mcp" / "server.py"
TOOLS_DIR = REPO_ROOT / "src" / "aws_safe_mcp" / "tools"

APPROVED_VERB_PREFIXES = (
    "analyze_",
    "audit_",
    "build_",
    "check_",
    "diagnose_",
    "explain_",
    "export_",
    "find_",
    "generate_",
    "get_",
    "investigate_",
    "list_",
    "plan_",
    "prove_",
    "query_",
    "run_",
    "search_",
    "simulate_",
)

# Module subject keywords. The public functions in each module must
# contain the relevant keyword so cross-module imports remain
# self-describing at the call site.
MODULE_SUBJECT_KEYWORDS: dict[str, tuple[str, ...]] = {
    "apigateway.py": ("api_gateway",),
    "cloudwatch.py": ("cloudwatch",),
    "dynamodb.py": ("dynamodb",),
    "ecs.py": ("ecs",),
    "eventbridge.py": ("eventbridge", "event_driven"),
    "iam.py": ("iam",),
    "identity.py": ("aws_identity", "aws_auth"),
    "kms.py": ("kms",),
    "lambda_tools.py": ("lambda",),
    "s3.py": ("s3",),
    "sns.py": ("sns",),
    "sqs.py": ("sqs", "queue"),
    "stepfunctions.py": ("step_function",),
    "resource_search.py": (
        "resource",
        "search_aws",
        "incident",
        "trace",
        "dependency",
        "graph",
        "narrative",
        "drift",
        "timeline",
        "transaction",
        "blocked_edge",
        "policy_condition",
        "region_partition",
    ),
    # Shared helpers, not registered as MCP tools; no subject keyword.
    "common.py": (),
    "downstream.py": (),
    "graph.py": (),
}

# Functions intentionally exempt from one or more naming rules. Each
# entry must include the rule it is exempt from and the reason.
NAMING_EXCEPTIONS: dict[str, str] = {
    # No exceptions today. Add as: "module:func_name": "reason".
}


def _public_functions(path: Path) -> list[ast.FunctionDef]:
    tree = ast.parse(path.read_text())
    return [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
    ]


def _mcp_tool_names(source: str) -> list[str]:
    return re.findall(r'@audit\.tool\("([^"]+)"\)', source)


def test_every_mcp_tool_name_uses_approved_verb_prefix() -> None:
    names = _mcp_tool_names(SERVER_PATH.read_text())
    assert names, "expected to find @audit.tool(...) names in server.py"
    bad = [
        name
        for name in names
        if not any(name.startswith(prefix) for prefix in APPROVED_VERB_PREFIXES)
        and f"server:{name}" not in NAMING_EXCEPTIONS
    ]
    assert not bad, (
        "Every MCP tool name must start with an approved verb prefix "
        f"({', '.join(APPROVED_VERB_PREFIXES)}). Violations: {bad}"
    )


def test_summary_tools_use_get_prefix() -> None:
    names = _mcp_tool_names(SERVER_PATH.read_text())
    bad = [
        name
        for name in names
        if name.endswith("_summary")
        and not name.startswith("get_")
        and f"server:{name}" not in NAMING_EXCEPTIONS
    ]
    assert not bad, f"Tool names ending in '_summary' must start with 'get_'. Violations: {bad}"


def test_list_tools_use_plural_noun() -> None:
    names = _mcp_tool_names(SERVER_PATH.read_text())
    bad = [
        name
        for name in names
        if name.startswith("list_")
        and not name.endswith("s")
        and f"server:{name}" not in NAMING_EXCEPTIONS
    ]
    assert not bad, (
        "Tool names starting with 'list_' must end with a plural noun "
        f"(end in 's'). Violations: {bad}"
    )


@pytest.mark.parametrize(
    "module_name,keywords",
    sorted(MODULE_SUBJECT_KEYWORDS.items()),
)
def test_public_functions_contain_module_subject(
    module_name: str, keywords: tuple[str, ...]
) -> None:
    if not keywords:
        return  # shared helper module, no subject contract
    path = TOOLS_DIR / module_name
    if not path.exists():
        pytest.skip(f"{module_name} missing")
    bad = []
    for func in _public_functions(path):
        if f"{module_name}:{func.name}" in NAMING_EXCEPTIONS:
            continue
        if not any(keyword in func.name for keyword in keywords):
            bad.append(func.name)
    assert not bad, (
        f"Public functions in {module_name} must contain one of "
        f"{keywords} in their name. Violations: {bad}"
    )
