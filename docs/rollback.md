# Rollback

A broken `aws-safe-mcp` release must be yanked from PyPI quickly. Yanking
hides the release from new resolvers without breaking pinned installs, which
is the right primitive for a safety-critical MCP server. Do not delete the
tag, do not delete the GitHub Release, and do not attempt to re-upload the
same version.

For the forward path, see [`release-checklist.md`](release-checklist.md).

## 1. When to yank

Yank as soon as one of the following is confirmed on a published version.

| Severity | Trigger                                                                                                                       | Action                                                  |
| -------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Critical | Secret values, environment values, credentials, or private keys returned by any tool. Mutating boto3 verb exposed. Read-only bypass. | Yank immediately. Open a security advisory.             |
| High     | Broken artefact (won't install, won't start). Audit logging disabled. Account allowlist not enforced.                          | Yank immediately. Patch release within 24 hours.        |
| High     | Mutating-verb leak in the SDK call surface (no exposed tool, but the verb is reachable).                                       | Yank immediately. Patch release within 24 hours.        |
| Medium   | Functional regression in an existing tool that returns wrong but non-sensitive results.                                        | Yank if the regression is misleading. Otherwise patch.  |
| Low      | Cosmetic regression, doc-only error.                                                                                           | Do not yank. Patch in the next release.                 |

If you are unsure, treat it as the higher severity. Yanking is reversible;
shipping a bad release is not.

## 2. How to yank

Yank using the PyPI web UI. Yank is not delete.

1. Sign in to PyPI as a project maintainer.
2. Navigate to `https://pypi.org/manage/project/aws-safe-mcp/releases/`.
3. Open the release `X.Y.Z`.
4. Click "Options" then "Yank".
5. Enter a short, public reason. Keep it factual: for example, "Security
   regression: tool returned environment values. Use X.Y.Z+1."
6. Confirm.

The PyPI reference is:
https://docs.pypi.org/project_management/yanking-and-deleting-releases/.

Do not:

- Run `pip delete` (no such command).
- Delete the release from PyPI. Deletion permanently burns the version
  number and breaks pinned installs.
- Re-upload `X.Y.Z` after yanking. PyPI rejects this, and even if it didn't,
  caches and mirrors would still serve the old artefact.
- Delete the Git tag or the GitHub Release.

A CLI fallback exists via the PyPI JSON API for automation; the web UI is
the supported path for humans.

## 3. Patch release flow

The fix ships as a new patch version `X.Y.(Z+1)`. Bumping is per
[`semver-policy.md`](semver-policy.md).

1. Branch from the yanked tag:

   ```bash
   git fetch --tags origin
   git checkout -b hotfix/vX.Y.(Z+1) vX.Y.Z
   ```

2. Apply the fix and write or extend tests so the regression cannot return.
3. Bump `version` in `pyproject.toml` to `X.Y.(Z+1)`.
4. Add a CHANGELOG entry per
   [`changelog-convention.md`](changelog-convention.md). Include a `Fixed`
   line that explicitly names the regression and links the yanked version.
5. Run the full release runbook from
   [`release-checklist.md`](release-checklist.md). Do not skip any gate.
6. Merge the hotfix PR into `main`. If `main` has moved on, also forward-port
   the fix or rebase the hotfix branch onto `main` after merge.

The hotfix release replaces the yanked one. Do not skip any safety gate just
because the change is small.

## 4. GitHub release

Edit the bad release on GitHub. Do not delete it.

1. Open `https://github.com/harryhazza77/aws-safe-mcp/releases/tag/vX.Y.Z`.
2. Click "Edit release".
3. Tick "Set as a pre-release".
4. Prepend a banner to the release notes:

   ```
   YANKED on YYYY-MM-DD. Use vX.Y.(Z+1) or later.
   Reason: <short factual reason>.
   ```

5. Save.

Leave the tag in place. Consumers who pin commits need the tag to resolve.

## 5. CHANGELOG entry

Edit the existing `## [X.Y.Z]` heading in `CHANGELOG.md` to record the yank.
Do not remove the original entries; they document what was shipped.

```
## [X.Y.Z] - YANKED

Yanked due to <short factual reason>. Use [X.Y.(Z+1)](#xyz-plus-1) or later.

### Added
- (original entries preserved)

### Fixed
- (original entries preserved)
```

The follow-up version gets its own normal section per
[`changelog-convention.md`](changelog-convention.md). Cross-link the two
versions so readers travelling either direction can find the other.

## 6. Post-mortem

Required for any Critical or High security regression. Optional but
encouraged for functional regressions.

Write it as `docs/postmortems/YYYY-MM-DD-vX.Y.Z.md` using this template:

```
# Post-mortem: vX.Y.Z

## Timeline
- YYYY-MM-DDTHH:MMZ Release X.Y.Z published.
- YYYY-MM-DDTHH:MMZ Regression first observed.
- YYYY-MM-DDTHH:MMZ Yanked from PyPI.
- YYYY-MM-DDTHH:MMZ Hotfix X.Y.(Z+1) published.

## Impact
Who and what was affected. Number of downloads, accounts touched, data
exposure scope. Avoid real account IDs and resource names.

## Root cause
What changed. Why the existing safety gates did not catch it.

## Mitigation
Immediate action taken (yank, hotfix, advisory).

## Prevention
Concrete change to safety gates, tests, or process so the same class of bug
fails the release runbook next time. Reference the threat model in
[`security/threat-model.md`](security/threat-model.md) and update it if the
attack surface changed.
```

Link the post-mortem from the hotfix CHANGELOG entry.

## 7. Vulnerability disclosure

If the yank was driven by a security regression, follow the reporting flow in
[`../SECURITY.md`](../SECURITY.md). In particular:

- File a GitHub Security Advisory for the affected versions.
- Mark `X.Y.Z` as vulnerable in the advisory.
- Mark `X.Y.(Z+1)` (and later) as patched.
- Request a CVE if the issue meets the criteria in `SECURITY.md`.
- Coordinate public disclosure timing with the advisory; the yank itself is
  already public.

Never include live credentials, real account IDs, customer data, or full
production log dumps in the advisory or post-mortem.
