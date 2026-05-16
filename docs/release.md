# Release Rationale

`aws-safe-mcp` treats every release as an audit gate. The package ships
read-only AWS tooling with strong safety promises, so the bar for cutting a
tag is not "tests pass" — it is "every safety gate is provably green and the
artefact carries no secrets, real account IDs, or write-capable surface". This
file explains *why* each gate exists. The exact commands live in
[release-checklist.md](release-checklist.md).

Coding agents should drive the checklist file directly. This file is reference
material when a step is unclear.

## Local Verification

Static, lint, type, security, dependency, and unit-test checks run before any
build because a regression caught locally never reaches PyPI. The mix
(`ruff`, `mypy`, `bandit`, `pip-audit`, `pytest`) covers style, types, source
security, dependency CVEs, and behaviour in one pass so a single command set
proves the tree is releasable.

See [release-checklist.md](release-checklist.md#2-local-verification) for the
exact commands.

## Live MCP Smoke Test

A green test suite proves the code paths execute against mocks. The live smoke
proves the packaged server initialises over stdio against a real non-production
AWS account, that auth and identity resolve correctly, and that read-only tools
return bounded structured content with no secret leakage. It is the only check
that exercises the full transport, auth, and redaction path end-to-end.

See [release-checklist.md](release-checklist.md#6-live-mcp-smoke) for the exact
commands, including the `SMOKE_PROFILE` / `SMOKE_REGION` / `SMOKE_ACCOUNT_ID` /
`SMOKE_CONFIG` placeholders that keep real values out of Git. Agents may read
`.codex.local.md` for local smoke-test settings; that file is gitignored and
must never be quoted with real values.

## Package Contents Inspection

The published wheel and sdist must contain only `src/aws_safe_mcp/...`,
packaging metadata, and project text files. Stray `.env`, `.codex.local.md`,
audit logs, or real account IDs in metadata are silent supply-chain incidents,
so the checklist greps both archives before publish.

See [release-checklist.md](release-checklist.md#5-build) for the exact
commands.

## PyPI Publish

Publish runs through PyPI Trusted Publishing in
`.github/workflows/publish.yml`, gated on the GitHub Release tag matching the
`pyproject.toml` version. Trusted Publishing keeps long-lived PyPI tokens out
of the repository and out of maintainer machines; the workflow is the only
principal that uploads, and it reruns local verification, rebuilds the
artefacts, and inspects contents before pushing.

See [release-checklist.md](release-checklist.md#10-publish) for the exact
commands. Manual `uv publish` is a fallback only when the workflow is
unavailable.

## Post-Publish Smoke

A successful PyPI upload does not prove the installed artefact behaves the same
as the local build. The post-publish smoke runs `uvx aws-safe-mcp@X.Y.Z` to
confirm the published version installs cleanly, reports the correct version,
and answers a read-only tool call against the smoke account.

See [release-checklist.md](release-checklist.md#11-post-publish-smoke) for the
exact commands.

## Rollback

A broken release is yanked, not deleted. See [rollback.md](rollback.md) for the
yank/patch flow, severity table, GitHub-release annotation, CHANGELOG yank
entry, and post-mortem requirements.

## Versioning and CHANGELOG

Version bumps follow [semver-policy.md](semver-policy.md), which defines what
counts as a breaking change to the MCP tool surface (tool rename, field
removal, type change, tightened IAM, config schema breakage) and what counts as
additive. CHANGELOG entries follow
[changelog-convention.md](changelog-convention.md), including the Keep-a-
Changelog sections, the `## [Unreleased]` discipline, and the YANKED entry
format.

## Safety Gates

Safety gates are listed in [standards.md](standards.md) and enforced by the
tests called out in
[release-checklist.md](release-checklist.md#3-safety-gates).
