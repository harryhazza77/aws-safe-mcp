from __future__ import annotations

from typing import Any


def dependency_graph_summary(
    *,
    nodes: dict[str, Any],
    edges: list[dict[str, Any]],
    permission_checks: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    """Return common graph counts shared by all dependency explanation tools."""

    return {
        "node_count": _node_count(nodes),
        "edge_count": len(edges),
        "target_types": sorted(
            {str(edge.get("target_type")) for edge in edges if edge.get("target_type") is not None}
        ),
        "permission_check_count": int(permission_checks.get("checked_count") or 0),
        "warning_count": len(warnings),
    }


def empty_permission_checks() -> dict[str, Any]:
    """Return the standard disabled permission-check block."""

    return {
        "enabled": False,
        "checked_count": 0,
        "checks": [],
        "summary": {
            "allowed": 0,
            "denied": 0,
            "unknown": 0,
            "explicit_denies": 0,
        },
    }


def _node_count(nodes: dict[str, Any]) -> int:
    count = 0
    for value in nodes.values():
        if isinstance(value, list):
            count += len(value)
        elif isinstance(value, dict) or value is not None:
            count += 1
    return count
