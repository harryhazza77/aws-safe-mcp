"""Freshness check for the Quick Capability Reference matrix in docs/features.md.

Every backtick-quoted tool name that appears in the matrix must correspond to
a real ``@audit.tool("...")`` registration in ``src/aws_safe_mcp/server.py``.

This catches stale matrix entries when a tool is renamed or removed but the
documentation forgot to follow. The inverse direction (server tools missing
from the matrix) is intentionally NOT enforced here, because the matrix is a
curated capability grouping rather than an exhaustive index.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FEATURES_DOC = REPO_ROOT / "docs" / "features.md"
SERVER_FILE = REPO_ROOT / "src" / "aws_safe_mcp" / "server.py"

TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
BACKTICK_RE = re.compile(r"`([^`]+)`")
AUDIT_TOOL_RE = re.compile(r'@audit\.tool\("([^"]+)"\)')

# Section header that anchors the matrix. The matrix is everything between
# this header and the next ``##``/``###`` header.
MATRIX_HEADER = "## Quick Capability Reference"


def _extract_matrix_block(text: str) -> tuple[str, int]:
    """Return the matrix section text and the absolute line number it starts at."""
    lines = text.splitlines()
    start: int | None = None
    end: int | None = None
    for idx, line in enumerate(lines):
        if start is None:
            if line.strip() == MATRIX_HEADER:
                start = idx + 1
            continue
        # Stop at the next same-or-shallower heading. The "How to read this"
        # subsection (###) is part of the matrix block and should be excluded
        # because its backtick identifiers reference docs, not tools.
        if line.startswith("## ") or line.startswith("### "):
            end = idx
            break
    assert start is not None, f"Could not locate '{MATRIX_HEADER}' section in {FEATURES_DOC}"
    if end is None:
        end = len(lines)
    return "\n".join(lines[start:end]), start


def _collect_matrix_tool_names() -> dict[str, list[int]]:
    """Return {tool_name: [line_numbers]} for every tool-shaped backtick identifier."""
    text = FEATURES_DOC.read_text(encoding="utf-8")
    block, block_start_line = _extract_matrix_block(text)
    found: dict[str, list[int]] = {}
    for offset, raw_line in enumerate(block.splitlines()):
        # Only inspect table rows (markdown table lines start with ``|``).
        if not raw_line.lstrip().startswith("|"):
            continue
        for match in BACKTICK_RE.finditer(raw_line):
            candidate = match.group(1).strip()
            if TOOL_NAME_RE.match(candidate):
                # ``block_start_line`` is 0-indexed; convert to 1-indexed file line.
                file_line = block_start_line + offset + 1
                found.setdefault(candidate, []).append(file_line)
    return found


def _collect_registered_tool_names() -> set[str]:
    text = SERVER_FILE.read_text(encoding="utf-8")
    return set(AUDIT_TOOL_RE.findall(text))


def test_capability_matrix_entries_exist_as_registered_tools() -> None:
    matrix_entries = _collect_matrix_tool_names()
    registered = _collect_registered_tool_names()
    assert registered, f"Expected at least one @audit.tool(...) registration in {SERVER_FILE}"

    stale = {name: lines for name, lines in matrix_entries.items() if name not in registered}
    if stale:
        details = "\n".join(
            f"  - `{name}` referenced at {FEATURES_DOC.name} lines "
            f"{', '.join(str(n) for n in lines)}"
            for name, lines in sorted(stale.items())
        )
        raise AssertionError(
            "Quick Capability Reference matrix references tool names that "
            "are not registered via @audit.tool(...) in "
            f"{SERVER_FILE.relative_to(REPO_ROOT)}:\n{details}\n"
            "Update docs/features.md to match the current tool surface, or "
            "re-register the missing tool."
        )


def test_capability_matrix_has_entries() -> None:
    """Sanity check: the matrix block must contain at least a handful of tools."""
    matrix_entries = _collect_matrix_tool_names()
    assert len(matrix_entries) >= 20, (
        f"Expected the Quick Capability Reference matrix to list many tools; "
        f"found only {len(matrix_entries)}. Did the section header move?"
    )
