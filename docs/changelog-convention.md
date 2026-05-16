# Changelog Convention

`aws-safe-mcp` keeps a single `CHANGELOG.md` at the repository root. This
document defines how entries are written, where they go, and how the file
moves through a release.

See also: [`semver-policy.md`](semver-policy.md),
[`release-checklist.md`](release-checklist.md),
[`rollback.md`](rollback.md).

## 1. Format

The changelog follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format. The spec is short; read it before opening your first changelog PR.

The file is human-readable Markdown. It is not generated from commits. Do
not run a tool that overwrites it.

## 2. Sections

Each released version uses these section headings, in this order, only when
they have entries:

- `Added` — new tools, new fields, new optional config keys.
- `Changed` — backward-compatible changes in existing behaviour. For
  pre-1.0, also covers breaking changes per
  [`semver-policy.md`](semver-policy.md).
- `Fixed` — bug fixes.
- `Removed` — tools, fields, or config keys that were removed (after the
  required deprecation cycle).
- `Deprecated` — tools, fields, or config keys scheduled for removal.
- `Security` — security regressions fixed in this release.

Omit sections that have no entries. Do not write empty headings.

## 3. Unreleased section

`CHANGELOG.md` always has a `## [Unreleased]` block at the top. Every PR
that affects user-visible behaviour adds at least one entry under it.

Placement:

```
# Changelog

## [Unreleased]

### Added
- New tool `summarize_route53_hosted_zone` for read-only Route 53 zone summaries.

### Fixed
- Redact environment values whose keys mix case (for example `Api_Key`).

## [0.2.0] - 2026-05-15
...
```

If a PR fits more than one section, add an entry to each.

## 4. Authorship and timing

- The PR contributor adds the changelog entry in the same PR that lands the
  change. No follow-up changelog PRs.
- Reviewers must reject any PR that ships a user-visible change without a
  matching changelog entry. This is enforced by the PR checklist in
  [`../CONTRIBUTING.md`](../CONTRIBUTING.md).
- Internal-only changes (refactors with no observable behaviour change,
  test-only changes, CI changes) do not need an entry. When in doubt, add
  one; cheap to add, expensive to miss.

## 5. Entry style

- One line per entry.
- Imperative voice, past tense for verbs of completed work. The existing
  `CHANGELOG.md` uses past tense ("Added ...", "Updated ..."); keep that
  style for consistency.
- Reference tool names, CLI flags, config keys, and file paths in
  backticks.
- Link to the PR or issue at the end of the line when relevant, for
  example `(#123)`.
- No trailing punctuation other than a final period.
- No emojis.

## 6. Examples

Real entries from the project's history (paraphrased to fit each section)
and representative future entries:

```
### Added
- Read-only AWS MCP server with stdio transport.
- Lazy AWS auth status and identity tools.
- Lambda network access tracing for inferred internet, private network, and VPC endpoint reachability.

### Changed
- Clarified README positioning alongside the official AWS MCP server.
- Updated the lockfile to use `urllib3` 2.7.0.

### Fixed
- Bound `list_lambda_functions` results when the AWS account has more than 1000 functions.

### Security
- Redact `aws_secret_access_key` values that appear inside Lambda environment maps.

### Deprecated
- Tool `cloudwatch_log_search` will be removed in the next minor release. Use `search_cloudwatch_logs`.
```

## 7. Release flow

At release time, follow the gated steps in
[`release-checklist.md`](release-checklist.md#7-bump-version-and-changelog).
The CHANGELOG edits are:

1. Rename the existing `## [Unreleased]` heading to
   `## [X.Y.Z] - YYYY-MM-DD`. The date is the planned release date in UTC.
2. Add a fresh `## [Unreleased]` block on top, with no subsections.

Resulting layout:

```
# Changelog

## [Unreleased]

## [X.Y.Z] - YYYY-MM-DD

### Added
- (entries that accumulated under Unreleased)

## [previous version] - YYYY-MM-DD
...
```

The dated section is what gets pasted into the GitHub Release body during
[`release-checklist.md`](release-checklist.md#9-tag-and-github-release).

## 8. YANKED entries

When a release is yanked per [`rollback.md`](rollback.md):

1. Edit the heading from `## [X.Y.Z] - YYYY-MM-DD` to
   `## [X.Y.Z] - YANKED`.
2. Add a "Yanked due to ..." line immediately under the heading, before any
   subsections, with a link to the follow-up version.

Example:

```
## [0.2.1] - YANKED

Yanked due to redaction regression returning environment values for keys
mixing case. Use [0.2.2](#022---2026-05-20) or later.

### Fixed
- (original entries preserved)
```

Do not delete the original entries. The CHANGELOG is an audit trail; keep
it accurate even when a release is bad.
