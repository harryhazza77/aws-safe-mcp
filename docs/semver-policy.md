# Semver Policy

`aws-safe-mcp` follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as `MAJOR.MINOR.PATCH`. This document defines what counts as breaking,
additive, or a fix for an MCP server whose public surface is the set of
registered tools and their structured outputs.

See also: [`release-checklist.md`](release-checklist.md),
[`changelog-convention.md`](changelog-convention.md),
[`rollback.md`](rollback.md).

## 1. Version scheme

- `MAJOR` increments on breaking changes to the MCP tool surface.
- `MINOR` increments on additive changes that are backward compatible.
- `PATCH` increments on bug fixes that do not change the tool surface.

The project is currently pre-1.0 (alpha). The current version is tracked in
[`pyproject.toml`](../pyproject.toml).

## 2. Pre-1.0 stability promise

While the package is on `0.y.z`:

- `MINOR` bumps (`0.y.z` to `0.(y+1).0`) MAY break the MCP tool surface. The
  CHANGELOG must call out every breaking change in a `Changed` or `Removed`
  section per [`changelog-convention.md`](changelog-convention.md).
- `PATCH` bumps (`0.y.z` to `0.y.(z+1)`) MUST NOT break the MCP tool
  surface. They are bug fixes only.
- Security regressions are still treated as `PATCH` when they restore the
  intended surface, even if behaviour observably changes for callers
  depending on the bug.

Pre-1.0 status mirrors the policy described in
[`../SECURITY.md`](../SECURITY.md): public APIs may still change while the
safety model is being hardened.

## 3. Post-1.0 (future)

Once the project ships `1.0.0`:

- `MAJOR` is required for any breaking change to the MCP tool surface (see
  section 4).
- `MINOR` is used for additive changes: a new tool, a new optional argument,
  a new field in a structured output.
- `PATCH` is used for bug fixes only. No surface changes, no behaviour
  reversals, no schema edits.

`1.0.0` will be cut when the safety gates, redaction properties, and tool
surface are considered stable enough that further breaking changes require
a major-version contract with users.

## 4. What counts as a breaking change

Treat the following as breaking. Post-1.0 they require a `MAJOR` bump.
Pre-1.0 they require a `MINOR` bump and a prominent CHANGELOG `Changed` or
`Removed` entry.

- Removing an MCP tool.
- Renaming an MCP tool.
- Removing a field from a tool's structured output.
- Changing the type of an existing field in a tool's structured output.
- Changing the semantics of an existing field (for example, switching a
  count from "items returned" to "items matched").
- Tightening the IAM permissions required to run a tool (callers may
  suddenly hit denials).
- Changing the configuration schema in a way that breaks existing configs
  (renamed keys, removed keys, stricter validation).
- Changing CLI flag names or removing flags.

The following are NOT breaking:

- Adding a new MCP tool.
- Adding a new optional argument with a safe default to an existing tool.
- Adding a new field to a tool's structured output (clients must already
  tolerate unknown fields).
- Adding a new optional configuration key with a safe default.
- Loosening required permissions (the same IAM that worked before still
  works).
- Improving redaction so that fewer secrets leak. Redaction tightening that
  removes formerly-returned non-secret content is breaking.
- Performance improvements with the same observable output.

## 5. Pre-release tags

Pre-release suffixes use PEP 440 form:

- `X.Y.ZaN` for alpha.
- `X.Y.ZbN` for beta.
- `X.Y.ZrcN` for release candidates.

Use a pre-release tag when a release needs broader smoke testing before the
final cut. Pre-release tags are not required for ordinary `0.y.z` alpha
development; the leading `0.` already signals alpha status.

PyPI treats pre-releases as opt-in for `pip install` resolvers, which is the
right default for an MCP server.

## 6. Deprecation policy

When removing or renaming a tool, run at least one full `MINOR` release with
the tool still present and deprecated. The deprecation cycle is:

1. Add a deprecation notice to the tool's docstring naming the replacement
   and the planned removal version.
2. Add a `Deprecated` entry under `## [Unreleased]` in `CHANGELOG.md` per
   [`changelog-convention.md`](changelog-convention.md).
3. Cut a `MINOR` release containing the deprecation. The tool still works.
4. In a later release (no sooner than the next `MINOR` after the deprecation
   shipped), remove the tool. Add a `Removed` entry.

For security regressions, this policy may be shortened. A tool that leaks
secrets is removed in the next release with no deprecation cycle; the
removal is documented as a `Security` entry per the changelog convention.

## 7. Worked examples

### Example A: adding `summarize_route53_hosted_zone`

A pull request adds a new MCP tool `summarize_route53_hosted_zone` that
returns a bounded summary of an existing hosted zone.

- No existing tools change. No fields removed. No schemas tightened.
- This is an additive change.
- Bump `MINOR`: `0.2.0` to `0.3.0`. CHANGELOG entry under `Added`.
- Post-1.0 this would also be `MINOR`.

### Example B: removing `cloudwatch_log_search` after renaming

A pull request removes `cloudwatch_log_search`. The replacement tool
`search_cloudwatch_logs` was added and the old name was deprecated in an
earlier release per section 6.

- Pre-1.0: bump `MINOR`. The CHANGELOG entry is under `Removed` and
  references the deprecation release.
- Post-1.0 (hypothetical): the same change requires a `MAJOR` bump because
  the tool name is part of the public surface.

### Example C: fixing a redaction bug

A pull request fixes a bug where the `redact_environment_values` flag
failed to redact one variant of an environment value key.

- No tools added or removed. No output fields changed.
- The visible behaviour change is that previously-leaked content is now
  redacted. This is a security fix.
- Bump `PATCH`: `0.2.0` to `0.2.1`. CHANGELOG entry under `Security`. No
  deprecation cycle required.
