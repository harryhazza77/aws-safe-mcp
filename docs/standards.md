# Project Standards

Canonical source for the safety guarantees, feature rules, and design
constraints every change to `aws-safe-mcp` must respect. Other docs
restate these rules in brief and link here; this file is the
authoritative version.

If a rule conflicts between two docs, this file wins. If a rule needs
to change, change it here first and update tests/CI accordingly, then
update brief restatements elsewhere.

## Safety Rules

These are non-negotiable for every tool, every release.

1. **Read-only AWS APIs only.** No `Put*`, `Create*`, `Update*`,
   `Delete*`, `Modify*`, `Send*`, `Publish*`, `Invoke*`,
   `Start*Execution`, `Stop*`, or other mutating verbs. Enforced by
   [`tests/test_invariants.py`](../tests/test_invariants.py).
2. **No raw AWS SDK passthrough.** No `aws_call(service, op, params)`
   tool. Every MCP tool is curated, named, and bounded.
3. **No S3 object body reads.** Metadata-only.
4. **No DynamoDB item reads, scans, or queries.** Metadata-only.
5. **No secret values, SSM parameter values, or KMS decrypt /
   data-key calls.** Never return plaintext secret material.
6. **No full IAM policy documents in responses.** Summaries only
   (statement count, principals, actions, condition keys).
7. **Bounded pagination, time windows, and result counts.** Use the
   shared `clamp_limit`, `clamp_since_minutes`, and per-API
   `page_size` helpers from
   [`src/aws_safe_mcp/tools/common.py`](../src/aws_safe_mcp/tools/common.py).
8. **Redact and truncate returned strings.** Use
   [`src/aws_safe_mcp/redaction.py`](../src/aws_safe_mcp/redaction.py)
   helpers. Property tests in
   [`tests/test_redaction_properties.py`](../tests/test_redaction_properties.py)
   pin the invariants.
9. **Return partial results with warnings when permissions or
   emulator support are incomplete.** Never raise on a missing
   optional permission; warn and continue.
10. **Mandatory account allowlist.** Every tool call refreshes the
    AWS identity via STS and rejects accounts not in
    `allowed_account_ids`. Enforced by
    [`src/aws_safe_mcp/auth.py`](../src/aws_safe_mcp/auth.py).

## Feature Rules

Every new feature should have:

- Clear user-facing value tied to a real investigation workflow.
- Narrow acceptance criteria.
- Unit tests for behaviour, limits, and errors.
- Moto-based integration tests where the tool's value depends on real
  boto3 shapes; see
  [`tests/test_lambda_moto.py`](../tests/test_lambda_moto.py) for the
  pattern.
- Fixture changes when local emulator proof needs new AWS resources;
  live in the separate `aws-sdk-mcp-tf` repo.
- AWS CLI proof against the emulator when applicable.
- `aws-safe-mcp` proof against the emulator when applicable.
- Move the completed item out of `docs/backlog.md` and into
  `docs/features.md`; add the matching `docs/tools.md` entry.
- One focused commit in the main repo.
- A separate fixture-repo commit when Terraform fixtures change.
- A clean repository state before the next feature starts.

## Naming Rules

Function names and MCP tool names must satisfy
[`tests/test_naming_conventions.py`](../tests/test_naming_conventions.py).
Reference doc: [naming-conventions.md](naming-conventions.md). High
level:

- Approved verb prefixes only (`get_`, `list_`, `search_`, `query_`,
  `check_`, `audit_`, `analyze_`, `explain_`, `investigate_`,
  `find_`, `simulate_`, `prove_`, `plan_`, `build_`, `generate_`,
  `export_`, `diagnose_`, `run_`).
- Tools ending in `_summary` use the `get_` prefix.
- Tools starting with `list_` end in a plural noun.
- Public functions in each tool module contain that module's subject
  keyword (e.g. `lambda_tools.py` functions contain `lambda`).
- `@audit.tool(...)` names are unique across the registry.

## Dependency-Tool Contract

Tools that return dependency information share the contract documented
at the top of [`docs/tools.md`](tools.md). Reuse it when adding new
dependency tools. Key fields: `nodes`, `edges`, `permission_hints`,
`permission_checks`, `warnings`, `graph_summary`.

## Audit + Observability

- Every MCP tool is wrapped with `@audit.tool("...")` in
  [`src/aws_safe_mcp/server.py`](../src/aws_safe_mcp/server.py). The
  invariant test verifies this.
- Audit records are emitted to stderr as structured JSON; redaction is
  applied. See
  [`security/redaction-scope.md`](security/redaction-scope.md) for the
  scope.

## Release Rules

- Follow [`docs/release-checklist.md`](release-checklist.md) end to end.
- Versioning follows [`docs/semver-policy.md`](semver-policy.md).
- Changelog entries follow [`docs/changelog-convention.md`](changelog-convention.md).
- Rollback flow lives in [`docs/rollback.md`](rollback.md).

## Out-of-Scope Threats

`aws-safe-mcp` does NOT defend against:

- Compromise of the laptop running the server.
- A malicious AWS principal who already holds destructive permissions
  in an allowed account.
- A compromised upstream dependency below the SBOM threshold.

For the full threat model see
[`security/threat-model.md`](security/threat-model.md).

## How to Change a Rule

1. Open an issue or decision entry in
   [`docs/decisions.md`](decisions.md) proposing the change and the
   rationale.
2. Update this file first. Update the enforcing test
   (`tests/test_invariants.py`, `tests/test_redaction_properties.py`,
   `tests/test_naming_conventions.py`) in the same PR.
3. Update brief restatements elsewhere
   (`README.md`, `SECURITY.md`, `docs/architecture.md`, `docs/goal.md`)
   to point at this file rather than duplicate the rule.
4. Mention the rule change in `CHANGELOG.md` under `Changed` or
   `Security`.
