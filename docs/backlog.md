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

Use the feature candidate order above.

## Documentation Refresh Backlog

The persona-driven documentation review delivered Tier 1 + Tier 2 in
commit `1d5f6db`. Tier 3 (polish edits to existing files) and Tier 4
(consolidation refactors) are deferred. They live here so they are not
lost.

### Tier 3 — Polish edits to existing files

- `README.md`: add config-file note before the `uvx` block; CHANGELOG
  link in the badges section; new "Feedback and Ideas" section that
  points to GitHub issues.
- `docs/claude-desktop.md`: add explicit `claude_desktop_config.json`
  path for macOS and Linux.
- `docs/cursor.md`: add explicit Cursor MCP-config file path.
- `docs/ai-clients.md`: rephrase the `get_aws_auth_status` line as a
  safety check rather than a startup requirement; move smoke prompts
  into `docs/prompts.md`.
- `docs/architecture.md`: add a sanitized audit-log JSON example; add a
  data-flow diagram aligned with `docs/security/threat-model.md`.
- `docs/tools.md`: add a one-line SRE use case before each tool's
  description.
- `SECURITY.md`: add a "Release Safety Audit" section linking each
  safety gate (no mutating verbs, audit-wrap coverage, redaction
  properties) to the test that enforces it.
- `CONTRIBUTING.md`: trim duplication with `docs/development.md`; link
  to `docs/contributing/add-a-tool.md` and
  `docs/naming-conventions.md`.
- `.github/ISSUE_TEMPLATE/feature.md`: new template covering user
  intent, affected service, scope estimate, safety-rule check.
- `.github/ISSUE_TEMPLATE/limitation.md`: new template for documenting
  known constraints.

### Tier 4 — Consolidation refactors

- Merge safety rules duplicated across `docs/goal.md`, `README.md`,
  `docs/architecture.md`, and `SECURITY.md` into a single canonical
  `docs/standards.md`; replace duplicates with links.
- Decide the fate of `docs/goal.md`: retire if stale, or rewrite as a
  live execution prompt that references `docs/vision.md` and
  `docs/backlog.md`.
- Split `docs/release.md`: keep only rationale; move runbook content
  into `docs/release-checklist.md` (already created in Tier 1).

### Source

These items came from a persona-driven documentation review run in
commit `1d5f6db`. The persona prompts are at `docs/personas/`; replay
them on the docs after Tier 3+4 land to confirm gaps closed.
