# Add A Tool

This is a worked example for adding your first tool to `aws-safe-mcp`. It walks
through adding `get_route53_hosted_zone_summary`, a read-only Route53 hosted
zone summary. Every path and command is literal: copy them, then adapt.

## Before You Start

Read these first. Each takes a few minutes and prevents the most common review
churn.

- `CONTRIBUTING.md` — design principles, pull request checklist, what kinds of
  tools we accept.
- `docs/development.md` — local setup and the exact lint, type, and test
  commands CI runs.
- `docs/architecture.md` — runtime flow, dependency graph contract, and the
  safety rules every new tool must follow.
- `docs/naming-conventions.md` — approved verb prefixes, suffix rules, and the
  module subject keyword each tool name must contain.

## Pick A Template

Do not start from scratch. Copy the closest existing tool and adapt it.

- For an inventory listing, read `src/aws_safe_mcp/tools/s3.py` and copy the
  shape of `list_s3_buckets`. It shows bounded pagination, region note, and
  the `count` / `is_truncated` contract.
- For a single-resource summary, read `src/aws_safe_mcp/tools/iam.py` and copy
  the shape of `get_iam_role_summary`. It shows partial-failure handling with
  `warnings`, paginated sub-calls, and the no-secret-values discipline.

For the worked example below, `get_route53_hosted_zone_summary` is a
single-resource summary, so the IAM role summary is the better template.

## Step 1 — Create The Implementation File

Create `src/aws_safe_mcp/tools/route53.py`. Keep the function signature
canonical: `runtime` first, then required identifiers, then optional `region`
and `max_results`. Clamp pagination through `clamp_limit`. Normalize AWS
errors through `normalize_aws_error`. Never return secret values.

```python
from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.common import clamp_limit, isoformat


def get_route53_hosted_zone_summary(
    runtime: AwsRuntime,
    hosted_zone_id: str,
    region: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    """Summarize one Route53 hosted zone without returning full record data."""
    zone_id = _require_zone_id(hosted_zone_id)
    limit = clamp_limit(
        max_results,
        default=50,
        configured_max=runtime.config.max_results,
        label="max_results",
    )
    # Route53 is a global service; region is informational only.
    client = runtime.client("route53", region=region or runtime.region)
    warnings: list[str] = []

    try:
        response = client.get_hosted_zone(Id=zone_id)
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "route53.GetHostedZone") from exc

    zone = response.get("HostedZone", {}) or {}
    config = zone.get("Config", {}) or {}
    vpcs = response.get("VPCs", []) or []

    record_set_count = 0
    try:
        paginator = client.get_paginator("list_resource_record_sets")
        for page in paginator.paginate(
            HostedZoneId=zone_id,
            PaginationConfig={"PageSize": limit, "MaxItems": str(limit)},
        ):
            record_set_count += len(page.get("ResourceRecordSets", []))
            if record_set_count >= limit:
                break
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "route53.ListResourceRecordSets")))

    return {
        "resource_type": "route53_hosted_zone",
        "hosted_zone_id": zone.get("Id") or zone_id,
        "name": zone.get("Name"),
        "private_zone": bool(config.get("PrivateZone")),
        "comment": config.get("Comment"),
        "record_set_count_sampled": min(record_set_count, limit),
        "is_truncated": record_set_count >= limit,
        "associated_vpcs": [
            {"vpc_id": v.get("VPCId"), "vpc_region": v.get("VPCRegion")}
            for v in vpcs[:limit]
        ],
        "created_at": isoformat(zone.get("CallerReference")),
        "warnings": warnings,
    }


def _require_zone_id(value: str) -> str:
    if not value or not value.strip():
        raise ToolInputError("hosted_zone_id is required")
    return value.strip()
```

Notes:

- Use `runtime.client(service, region=...)` exclusively. It enforces the
  account allowlist. Do not call `boto3.client` directly.
- Keep the return shape concise and predictable. Surveying tools should
  prefer the dependency graph contract from `docs/architecture.md` when they
  walk multiple resources; a single-resource summary like this one can stay
  flat.
- Use `warnings` to record optional sub-call failures so the AI client still
  gets a partial answer.

## Step 2 — Add The Test

Create `tests/test_route53.py`. Prefer a moto-based integration test so the
test exercises the real boto3 client shape (capitalization, pagination
tokens, ARN formats). Hand-rolled fakes are acceptable for pure-logic
helpers but should not be the primary test for a tool that talks to AWS.

Prior art to read:

- `tests/test_lambda_moto.py` — moto-driven happy-path tests using the shared
  `moto_runtime` fixture.
- `tests/test_sqs_moto.py` — second moto example.
- `tests/test_sqs_helpers.py` — hand-rolled fakes for pure-logic helpers.

Skeleton:

```python
"""Route53 tool integration tests against moto."""

from __future__ import annotations

import boto3
from moto import mock_aws

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.tools.route53 import get_route53_hosted_zone_summary
from tests.conftest import MOTO_REGION


def test_get_route53_hosted_zone_summary_returns_real_shape(
    moto_runtime: AwsRuntime,
) -> None:
    client = boto3.client("route53", region_name=MOTO_REGION)
    response = client.create_hosted_zone(
        Name="example.internal.",
        CallerReference="contrib-example",
        HostedZoneConfig={"Comment": "test zone", "PrivateZone": False},
    )
    zone_id = response["HostedZone"]["Id"]

    result = get_route53_hosted_zone_summary(moto_runtime, zone_id)

    assert result["resource_type"] == "route53_hosted_zone"
    assert result["name"] == "example.internal."
    assert result["private_zone"] is False
    assert "warnings" in result
```

Cover at least: a happy path, an input-validation failure for an empty id,
and a redaction or limit assertion when the tool returns user-influenced
strings.

## Step 3 — Register The Tool

Open `src/aws_safe_mcp/server.py` and add a registration function. Follow
the existing `_register_lambda_tools` pattern (around line 339): import the
implementation with an `_tool` alias, declare a thin `@mcp.tool()` wrapper,
and wrap it with `@audit.tool("...")` so every call is audit-logged with
redaction.

Add the import at the top of the file:

```python
from aws_safe_mcp.tools.route53 import (
    get_route53_hosted_zone_summary as get_route53_hosted_zone_summary_tool,
)
```

Add the registration function near the other `_register_*_tools`:

```python
def _register_route53_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("get_route53_hosted_zone_summary")
    def get_route53_hosted_zone_summary(
        hosted_zone_id: str,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Summarize one Route53 hosted zone."""
        return get_route53_hosted_zone_summary_tool(
            runtime,
            hosted_zone_id=hosted_zone_id,
            region=region,
            max_results=max_results,
        )
```

Wire it into `create_server`:

```python
_register_route53_tools(mcp, audit, runtime)
```

The MCP tool name string in `@audit.tool(...)` must match the Python
function name exactly. Uniqueness is enforced by `tests/test_invariants.py`.

## Step 4 — Follow Naming Rules

Read `docs/naming-conventions.md` for the full ruleset. The verbs allowed
as a public tool prefix are:

```
analyze_, audit_, build_, check_, diagnose_, explain_, export_, find_,
generate_, get_, investigate_, list_, plan_, prove_, query_, run_,
search_, simulate_
```

`summarize_` is not on the list. Use `get_*_summary` for single-resource
summaries — hence `get_route53_hosted_zone_summary`, not
`summarize_route53_hosted_zone`. The naming test will fail CI if you pick
the wrong verb.

Module subject keywords are enforced too. Every public function in
`src/aws_safe_mcp/tools/route53.py` must contain a Route53 subject keyword
in its name. When you add the file, also add an entry to
`MODULE_SUBJECT_KEYWORDS` in `tests/test_naming_conventions.py` so the
rule applies:

```python
"route53.py": ("route53", "hosted_zone"),
```

## Step 5 — Update The Docs

Three places need an entry. Keep each entry short and factual.

- `docs/tools.md` — add a new "Route53" section listing the tool name, what
  it returns, and any non-obvious parameters. Match the prose style of the
  IAM and KMS sections.
- `docs/features.md` — add `get_route53_hosted_zone_summary` to the
  capability list so the surface stays discoverable.
- `tests/test_mcp_smoke.py` — add the MCP tool name to the expected surface
  set so the smoke test asserts the tool is registered.

## Step 6 — Verify Locally

All three must be green before you open a PR:

```bash
python -m pytest -q
python -m ruff check .
python -m mypy src
```

The full pre-commit suite from `docs/development.md` adds format checks,
security scans, and coverage. Run that suite at least once before requesting
review.

## Step 7 — Open The PR

Open the pull request and walk down the "Pull Request Checklist" in
`CONTRIBUTING.md`. Confirm each item explicitly in the PR description.
Reviewers will check the same list.

## Safety Reminders

- No mutating boto3 verbs. Only `get_*`, `list_*`, `describe_*`, `search_*`,
  and simulation calls. `tests/test_invariants.py` will fail CI if a write
  verb appears in any tool module.
- Never disclose environment variable values, secret strings, KMS plaintext,
  S3 object bodies, or DynamoDB item data. Keys-only is the rule; the
  redaction helpers and `is_secret_like_key` exist to enforce it.
- The account allowlist is enforced by `AwsRuntime`. Always go through
  `runtime.client(...)`. Never instantiate `boto3.client` or `boto3.Session`
  directly in tool code — that bypass would let a tool query a disallowed
  account.
