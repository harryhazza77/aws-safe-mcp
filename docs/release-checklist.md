# Release Checklist

A linear, copy-paste runbook for cutting a safe PyPI release of `aws-safe-mcp`.
Every step has a command, an expected outcome, and a pass/fail signal. Do not
skip steps. If any step fails, stop and unblock before continuing.

This document is the gated runbook. For background, design rationale, and the
non-ordered safety review, see [`release.md`](release.md).

Cross-references:

- Version bump rules: [`semver-policy.md`](semver-policy.md).
- CHANGELOG format: [`changelog-convention.md`](changelog-convention.md).
- Yanking a broken release: [`rollback.md`](rollback.md).

## 1. Pre-flight

```bash
git status --short
git rev-parse --abbrev-ref HEAD
git fetch origin
git rev-list --left-right --count HEAD...origin/main
```

Expected:

- `git status --short` prints nothing.
- Current branch is `main`.
- Left/right counts both report `0`.

Pass signal: empty working tree, on `main`, in sync with `origin/main`.
Fail signal: any modified file, wrong branch, or non-zero divergence. Stop.

## 2. Local verification

Run each command in order. Stop at the first failure.

```bash
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python -m bandit -r src
python -m pip_audit
```

Expected:

- `pytest` exits `0` with no failures.
- `ruff check` prints `All checks passed!`.
- `ruff format --check` exits `0` (no files would be reformatted).
- `mypy` reports `Success: no issues found`.
- `bandit` reports `No issues identified.`.
- `pip_audit` reports `No known vulnerabilities found`.

Pass signal: every command exits `0`.
Fail signal: any non-zero exit. Fix and re-run from step 1.

## 3. Safety gates

These tests enforce the project's hard rules. They must pass independently of
the wider suite so that a release-time regression is obvious.

```bash
python -m pytest tests/test_invariants.py -q
python -m pytest tests/test_naming_conventions.py -q
python -m pytest tests/test_redaction_properties.py -q
```

Expected outcomes:

- `test_invariants.py` confirms no new mutating boto3 verbs were added and that
  every tool is wrapped by the audit decorator.
- `test_naming_conventions.py` confirms tool names follow the project's
  conventions (see [`semver-policy.md`](semver-policy.md) for why renames are
  breaking).
- `test_redaction_properties.py` confirms property-based redaction holds for
  secret-like keys, environment values, and bounded string lengths.

Pass signal: all three exit `0`.
Fail signal: any failure. Do not publish. Open an issue.

## 4. Secret and identifier grep

Hunt credentials, real account IDs, real ARNs, and real profile names. The
prior list lives in [`release.md`](release.md#before-publishing-the-repository);
reproduce it here for the release gate.

```bash
rg -n "(AKIA|ASIA|aws_secret_access_key|aws_access_key_id|BEGIN .*PRIVATE KEY|PRIVATE KEY)" .
rg -n "(account-id|your-account-id|123456789012|profile dev)" README.md docs examples
rg -n "arn:aws:[a-z0-9-]+:[a-z0-9-]+:[0-9]{12}:" README.md docs examples src tests
rg -n "[0-9]{12}" README.md docs examples | rg -v "123456789012"
```

Expected:

- Command 1 returns no real secrets.
- Command 2 only shows generic examples (no real account IDs, no real profile
  names).
- Command 3 only shows ARNs that use the placeholder account `123456789012`.
- Command 4 returns nothing. Every 12-digit number in tracked content is the
  placeholder.

Pass signal: every output matches the rule above.
Fail signal: any unredacted real identifier. Remove it and re-run from step 1.

## 5. Build

```bash
rm -rf dist
python -m build
ls dist
tar -tzf dist/aws_safe_mcp-*.tar.gz | head -n 50
unzip -l dist/aws_safe_mcp-*.whl
```

Then verify no forbidden content shipped:

```bash
tar -tzf dist/aws_safe_mcp-*.tar.gz | rg -n "(\.env|audit.*\.log|\.codex\.local\.md)" || echo "clean"
unzip -p dist/aws_safe_mcp-*.whl '*/METADATA' | rg -n "[0-9]{12}" | rg -v "123456789012" || echo "clean"
```

`uv build` is an acceptable substitute for `python -m build` if `uv` is the
local toolchain.

Expected:

- Exactly one `.tar.gz` and one `.whl` in `dist/`.
- Listings show only `src/aws_safe_mcp/...`, packaging metadata, and the
  project's text files.
- Both forbidden-content checks print `clean`.

Pass signal: artefacts exist, listings look right, both checks print `clean`.
Fail signal: stray files, real account IDs in metadata, or missing artefacts.

## 6. Live MCP smoke

Run the stdio smoke client from
[`release.md`](release.md#live-mcp-end-to-end-smoke) against a non-production
AWS account. Use the documented `SMOKE_PROFILE`, `SMOKE_REGION`,
`SMOKE_ACCOUNT_ID`, `SMOKE_CONFIG` placeholders. Never commit real values.

Expected:

- `get_aws_auth_status` reports `authenticated: true`.
- `get_aws_identity` returns the smoke account.
- `tools: N` is printed and `N` matches the registered tool count.
- All list/search calls complete with bounded results.

Pass signal: every call returns structured content, no secret values appear in
output.
Fail signal: any tool errors, returns raw payloads, or leaks credentials.

Delete the temporary config when finished.

## 7. Bump version and changelog

Pick `X.Y.Z` according to [`semver-policy.md`](semver-policy.md).

Edit `pyproject.toml`:

```toml
[project]
name = "aws-safe-mcp"
version = "X.Y.Z"
```

Edit `CHANGELOG.md` following
[`changelog-convention.md`](changelog-convention.md#release-flow). Rename
`## Unreleased` to `## [X.Y.Z] - YYYY-MM-DD` and open a fresh empty
`## [Unreleased]` block on top.

Then re-run steps 1 to 5 to confirm the bump did not break anything.

Pass signal: version edited in exactly one place, CHANGELOG has a dated
section, full verification still green.

## 8. Open release PR and merge

```bash
git checkout -b release/vX.Y.Z
git add pyproject.toml CHANGELOG.md
git commit -m "Release vX.Y.Z"
git push -u origin release/vX.Y.Z
gh pr create --title "Release vX.Y.Z" --body "Release vX.Y.Z. See CHANGELOG.md."
```

Expected:

- PR title is exactly `Release vX.Y.Z`.
- CI is green on the PR.
- Diff touches only `pyproject.toml` and `CHANGELOG.md`.

Pass signal: CI green, PR diff minimal, approval recorded.
Fail signal: CI red, extra files in the diff. Fix or close.

Merge the PR into `main` once green.

## 9. Tag and GitHub Release

```bash
git checkout main
git pull --ff-only origin main
git tag vX.Y.Z
git push origin vX.Y.Z
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <(sed -n "/## \[X.Y.Z\]/,/## \[/p" CHANGELOG.md | sed '$d')
```

Expected:

- Tag `vX.Y.Z` exists locally and on `origin`.
- GitHub Release `vX.Y.Z` exists, body matches the CHANGELOG entry.

Pass signal: `gh release view vX.Y.Z` shows the new release.
Fail signal: tag missing, body empty, or release marked as draft.

## 10. Publish

Trusted Publishing fires from the tag push via
`.github/workflows/publish.yml`. Watch the run:

```bash
gh run watch
```

Expected:

- The `publish` workflow finishes green.
- The PyPI project page lists the new version.

Pass signal: workflow exits success, PyPI shows the new release.
Fail signal: workflow failure, missing wheel on PyPI. Go to
[`rollback.md`](rollback.md).

## 11. Post-publish smoke

```bash
uvx aws-safe-mcp@X.Y.Z --help
uvx aws-safe-mcp@X.Y.Z --version
```

Then run a single read-only tool call from the installed version against the
smoke profile, for example:

```bash
uvx aws-safe-mcp@X.Y.Z \
  --profile "$SMOKE_PROFILE" \
  --region "$SMOKE_REGION" \
  --readonly \
  --config "$SMOKE_CONFIG" \
  --self-check
```

Expected:

- `--help` renders the CLI usage.
- `--version` prints `X.Y.Z`.
- The self-check call returns structured content for the smoke account.

Pass signal: the installed version behaves identically to the local build.
Fail signal: import errors, wrong version string, or tool failures. Go to
[`rollback.md`](rollback.md).

## 12. Pass/fail summary

Tick every box. If any box is unticked, do NOT publish (or yank what is
already published using [`rollback.md`](rollback.md)) and open a tracking
issue.

- [ ] 1. Pre-flight clean.
- [ ] 2. Local verification green.
- [ ] 3. Safety gates green.
- [ ] 4. Secret and identifier grep clean.
- [ ] 5. Build artefacts inspected and clean.
- [ ] 6. Live MCP smoke green.
- [ ] 7. Version and CHANGELOG bumped.
- [ ] 8. Release PR merged green.
- [ ] 9. Tag and GitHub Release created.
- [ ] 10. PyPI publish workflow green.
- [ ] 11. Post-publish smoke green.

If every box is ticked, the release is done. Announce per the project's
communication channels and link the GitHub Release.

## Rollback

If a published release is broken, do not delete the tag. Yank it. Follow
[`rollback.md`](rollback.md).
