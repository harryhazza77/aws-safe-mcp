# Naming Conventions

This document mirrors the rules enforced by `tests/test_naming_conventions.py`.
The test file is authoritative; this page exists so contributors do not have
to read Python to discover the rules.

## Why These Rules

The MCP tool surface is the public API of `aws-safe-mcp`. AI clients see
every tool name, and a drifting surface is hard for them to reason about.
The naming test pins the verb prefix, summary suffix, plural-noun list
rule, and module subject keyword rules. A pull request that violates any
of these will fail CI; the failure message names the offending tool.

## Approved Verb Prefixes

Every MCP tool name must start with one of the following verbs. Listed in
alphabetical order with the situation each is for.

- `analyze_` — classify or score a configuration finding (often without an
  AWS call).
- `audit_` — walk a topology and report safety gaps (DLQs, retries,
  permissions).
- `build_` — assemble a derived artifact from multiple AWS reads, such as
  a correlation timeline.
- `check_` — yes/no readiness check for a specific path or capability.
- `diagnose_` — explain why a configuration looks wrong, with cause hints.
- `explain_` — describe a resource's dependencies, graph edges, and IAM
  expectations.
- `export_` — produce a structured artifact (graph, JSON snapshot) for
  another tool to consume.
- `find_` — discover items matching a predicate across resources.
- `generate_` — produce a narrative, report, or summary text.
- `get_` — fetch a single-resource summary or status.
- `investigate_` — multi-step diagnostic that fuses metadata, logs, and
  metrics.
- `list_` — bounded inventory listing of resources of one type.
- `plan_` — produce a step-by-step trace or plan without executing it.
- `prove_` — assert and demonstrate an invocation or permission path.
- `query_` — run a bounded query against an AWS query API (e.g. Logs
  Insights).
- `run_` — execute a packaged investigation runner.
- `search_` — pattern or substring search across an AWS surface.
- `simulate_` — model a path (e.g. security group reachability) without
  changing state.

If your intent does not fit one of these, the answer is almost always to
rename, not to add a new verb. New verbs require updating
`APPROVED_VERB_PREFIXES` in `tests/test_naming_conventions.py` with
reviewer agreement.

## Suffix Rules

- Single-resource summaries: `get_*_summary`. Tools ending in `_summary`
  must start with `get_`; the test enforces this. Examples:
  `get_iam_role_summary`, `get_lambda_summary`, `get_kms_key_summary`.
- Inventory listings: `list_*` followed by a plural noun. The test
  enforces that the name ends in `s`. Examples: `list_lambda_functions`,
  `list_s3_buckets`, `list_step_functions`.
- Cross-service composites use a noun suffix that signals shape:
  - `*_brief` — short structured incident or status brief.
  - `*_narrative` — human-readable health narrative.
  - `*_graph` — dependency graph artifact.
  - `*_trace` — step-by-step transaction trace.
  - `*_timeline` — time-ordered correlated events.
  - `*_incident` — a runnable incident harness.

These suffixes are conventions documented here; they are not yet
mechanically enforced by the test, but reviewers apply them.

## Module Subject Keyword

Every public function in `src/aws_safe_mcp/tools/<service>.py` must contain
that module's subject keyword in its name, so cross-module imports remain
self-describing at the call site. The mapping is the source of truth in
`MODULE_SUBJECT_KEYWORDS` in `tests/test_naming_conventions.py`:

| Module file          | Required keyword(s)                                                                                                                       |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `apigateway.py`      | `api_gateway`                                                                                                                             |
| `cloudwatch.py`      | `cloudwatch`                                                                                                                              |
| `dynamodb.py`        | `dynamodb`                                                                                                                                |
| `ecs.py`             | `ecs`                                                                                                                                     |
| `eventbridge.py`     | `eventbridge`, `event_driven`                                                                                                             |
| `iam.py`             | `iam`                                                                                                                                     |
| `identity.py`        | `aws_identity`, `aws_auth`                                                                                                                |
| `kms.py`             | `kms`                                                                                                                                     |
| `lambda_tools.py`    | `lambda`                                                                                                                                  |
| `s3.py`              | `s3`                                                                                                                                      |
| `sns.py`             | `sns`                                                                                                                                     |
| `sqs.py`             | `sqs`, `queue`                                                                                                                            |
| `stepfunctions.py`   | `step_function`                                                                                                                           |
| `resource_search.py` | `resource`, `search_aws`, `incident`, `trace`, `dependency`, `graph`, `narrative`, `drift`, `timeline`, `transaction`, `blocked_edge`, `policy_condition`, `region_partition` |

Shared helper modules (`common.py`, `downstream.py`, `graph.py`) have no
subject contract because they are not registered as MCP tools.

When you add a new service module (for example `route53.py`), add an entry
to `MODULE_SUBJECT_KEYWORDS` in the test before merging.

## MCP Tool Name

The string in `@audit.tool("...")` is the public MCP tool name. It must:

- Match the Python function name in `server.py` exactly. Mismatches make
  the tool unfindable by AI clients.
- Be unique across the whole server. Uniqueness is checked by
  `tests/test_invariants.py`.
- Start with an approved verb prefix (enforced by
  `tests/test_naming_conventions.py`).

## Worked Rename Examples

Real renames from the project history (commit `b9b67d6`, "Apply
code-review fixes and standardize public API names"):

- `aws_auth_status` → `get_aws_auth_status`. Bare nouns are not allowed;
  the tool returns a status object, so `get_` fits and `_status` is the
  shape suffix.
- `aws_identity` → `get_aws_identity`. Same reason: bare noun became a
  `get_` summary.
- `dynamodb_table_summary` → `get_dynamodb_table_summary`. The
  `_summary` suffix mandates the `get_` prefix.
- `cloudwatch_log_search` → `search_cloudwatch_logs`. Verb-first surface
  reads better at the call site; the noun is now correctly plural-trailing
  rather than buried in the middle.
- `cloudwatch_logs_insights_query` → `query_cloudwatch_logs_insights`.
  Verb-first again, and `query_` is the approved prefix for bounded
  query-API calls.

## How To Add An Exception

If a rule fires on a genuinely sound exception, add an entry to
`NAMING_EXCEPTIONS` in `tests/test_naming_conventions.py`. The map key is
`"<scope>:<name>"`:

- `"server:tool_name"` for an MCP tool name on the server.
- `"<module>.py:func_name"` for a module-subject violation.

The value is a short reason, e.g.:

```python
NAMING_EXCEPTIONS: dict[str, str] = {
    # "server:legacy_helper": "kept for back-compat with v0.1 clients",
}
```

Expect reviewers to push back on exceptions. Renaming is almost always
cheaper than carrying an exception forever.

## How To Run The Check Locally

```bash
python -m pytest tests/test_naming_conventions.py -v
```

Run this whenever you add, rename, or move a tool. The failure messages
name the offending function and the rule that fired, so fixing them is a
mechanical edit.
