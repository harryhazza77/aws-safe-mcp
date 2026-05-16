# Backlog

This backlog collects high-value feature ideas for `aws-safe-mcp`. It is a
planning aid, not a commitment to build every item in order.

## Evaluation Rules

Prefer features that:

- Preserve the read-only, bounded, redacted tool model.
- Help developers investigate failures, permissions, and dependencies.
- Reuse the dependency-tool contract where a graph is useful.
- Can be verified against local fixtures in `../aws-sdk-mcp-tf`.
- Work against Floci when practical, and MiniStack when Floci lacks service
  support.

Avoid features that:

- Add raw AWS SDK passthrough.
- Read S3 object bodies, DynamoDB items, secret values, or decrypted KMS data.
- Return full policy documents or full state machine definitions.
- Expand scope without a clear diagnostic workflow.

## Feature Candidates

### Deep Diagnostic Workflows

Ordered by estimated feature size, smallest first. Each item accounts for the
current public tool surface in `src/aws_safe_mcp/server.py` and
`src/aws_safe_mcp/tools/*`; scopes focus on new diagnostic value beyond existing
single-resource summaries, dependency graphs, and permission checks.

All planned feature candidates have been implemented.

## Suggested Order

Items are ordered by estimated feature size, smallest first. Prefer features
that reuse existing helpers, fixtures, or dependency-graph edges over those
that introduce a new boto3 client surface. Any item that introduces a new AWS
read API is blocked on a safety review (read-only verbs, redaction shape,
bounded outputs) before implementation begins, regardless of where it falls
in the size ordering.

## Documentation Refresh Backlog

The persona-driven documentation review delivered Tier 1 + Tier 2 in
commit `1d5f6db`. Tier 3 (polish edits to existing files) and Tier 4
(consolidation refactors) are deferred. They live here so they are not
lost.

### Tier 3 — Polish edits to existing files

Most items below were folded into the Tier 4 consolidation pass in commit
`a40c595`; remaining bullets are tagged with a candid value/scope/risk
estimate so they can be picked up incrementally.

- DONE in `a40c595`: `README.md` config-file note before the `uvx` block,
  CHANGELOG link in the badges section, new "Feedback and Ideas" section.
- DONE in `a40c595`: `docs/claude-desktop.md` explicit
  `claude_desktop_config.json` paths for macOS, Linux, and Windows.
- DONE in `a40c595`: `docs/cursor.md` explicit Cursor MCP-config file paths
  with a copy-paste snippet.
- DONE in `a40c595`: `docs/ai-clients.md` rephrased `get_aws_auth_status` as
  a safety check; smoke prompts moved to `docs/prompts.md`.
- DONE in `a40c595`: `docs/architecture.md` data-flow mermaid diagram and
  sanitized audit-log JSON example.
- DONE in `a40c595`: `docs/tools.md` one-line `Use when:` SRE use case for
  every tool heading.
- DONE in `a40c595`: `SECURITY.md` "Release Safety Audit" gates table
  linking each safety gate to the enforcing test.
- DONE in `a40c595`: `CONTRIBUTING.md` trimmed duplication with
  `docs/development.md`; links to `docs/contributing/add-a-tool.md` and
  `docs/naming-conventions.md`.
- DONE in `a40c595`: `.github/ISSUE_TEMPLATE/feature.md` new
  feature-proposal template grounded in `docs/standards.md`.
- DONE in `a40c595`: `.github/ISSUE_TEMPLATE/limitation.md` new
  limitation-report template grounded in `docs/limitations.md` and
  `SECURITY.md`.

### Tier 4 — Consolidation refactors

- DONE in `a40c595`: merged duplicated safety rules across `docs/goal.md`,
  `README.md`, `docs/architecture.md`, and `SECURITY.md` into a single
  canonical `docs/standards.md`; duplicates now link to it.
- DONE in `a40c595`: `docs/goal.md` rewritten as a live execution prompt
  that references `docs/vision.md`, `docs/backlog.md`, and
  `docs/standards.md`.
- DONE in `a40c595`: `docs/release.md` split — rationale-only, with the
  runbook content living in `docs/release-checklist.md`.

### Source

These items came from a persona-driven documentation review run in
commit `1d5f6db`. The persona prompts are at `docs/personas/`; replay
them on the docs after Tier 3+4 land to confirm gaps closed.

**Role of this file:** backlog.md is the prioritized candidate queue. For
long-term strategy see [vision.md](vision.md). For the workstream replay
script see [goal.md](goal.md).
