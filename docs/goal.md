# Goal

Use this file to run an ambitious `aws-safe-mcp` workstream. The plan lives in
[backlog.md](backlog.md); this file defines how to execute it.

## Working Goal

Execute all focused, high-value `aws-safe-mcp` features from
[backlog.md](backlog.md). Each feature should be useful to real users, tested,
verified against local AWS emulator fixtures where practical, documented, and
committed as a focused change.

## Repositories

- Main code repo: `/Users/hareshpatel/Documents/code/aws-sdk-mcp`
- Terraform fixture repo: `/Users/hareshpatel/Documents/code/aws-sdk-mcp-tf`

## Current Direction

- Use [features.md](features.md) to understand current user-facing capability.
- Use [backlog.md](backlog.md) as the ordered implementation plan.
- Work through backlog items in order by default, unless the user names a
  different item.
- Preserve the one-feature-one-commit rule even when running many features in a
  row.
- Prefer diagnostic workflows over raw list tools.
- Prefer small features that improve safe AWS investigation.

## Execution Prompt

When the user invokes `/goal`, do this:

1. Read `docs/features.md`, `docs/backlog.md`, and `docs/goal.md`.
2. Select the first unfinished backlog item unless the user explicitly picks
   another item.
3. Cross-check existing code and docs to avoid duplicating that feature.
4. Implement the smallest version that satisfies the backlog acceptance notes.
5. Add or update focused unit tests.
6. Update `docs/tools.md` and move the completed capability from
   `docs/backlog.md` into `docs/features.md`.
7. If Terraform fixture changes are needed, update
   `/Users/hareshpatel/Documents/code/aws-sdk-mcp-tf` and commit that repo
   separately.
8. Run local verification:
   - Always run focused tests plus `uv run ruff check src tests`,
     `uv run mypy`, and `uv run pytest`.
   - Run MiniStack/AWS CLI proof only when required commands are already
     approved or can run without extra prompts.
   - If emulator proof would require new permission prompts, stop after unit
     tests and clearly report the exact skipped proof command shapes.
9. Commit the main repo as one focused feature commit.
10. If the user asked to continue the goal, repeat from step 1 for the next
    backlog item.

Do not bundle multiple backlog items into one main-repo commit. After each
feature, leave both repositories clean or clearly report why that was not
possible before starting the next feature.

## Fixture Strategy

- Keep Terraform fixtures out of the Python package repo.
- Use MiniStack on `http://127.0.0.1:4566`
- Verify fixture resources with AWS CLI before relying on them in MCP tests.
- Verify `aws-safe-mcp` against the same emulator with `endpoint_url` in the
  config file.
- For unattended slash-goal runs, pre-approve or run from an environment that
  permits `uv run`, MiniStack `make` targets, and localhost AWS CLI checks.
  Otherwise stop after unit tests and leave live emulator proof as a manual
  verification step.

## Feature Rules

Each feature should have:

- Clear user-facing value.
- Narrow acceptance criteria.
- Unit tests for behavior, limits, and errors.
- Fixture changes when local emulator proof needs new AWS resources.
- AWS CLI proof against the emulator when applicable.
- `aws-safe-mcp` proof against the emulator when applicable.
- Move the completed item out of `docs/backlog.md` and into `docs/features.md`.
- One focused commit in the main repo.
- A separate fixture repo commit when Terraform fixtures change.
- A clean repository state before the next feature starts.

## Safety Rules

- Read-only AWS APIs only.
- No raw AWS SDK passthrough.
- No S3 object body reads.
- No DynamoDB item reads, scans, or queries.
- No secret values, SSM parameter values, or KMS decrypt/data-key calls.
- No full IAM policy documents in responses.
- Bound pagination, time windows, and result counts.
- Redact and truncate returned strings.
- Return partial results with warnings when permissions or emulator support are
  incomplete.

## Planning Mode

Only switch to planning mode when the user explicitly asks to plan, asks for a
proposal, or says not to write code yet. In planning mode, describe user value,
existing overlap, acceptance criteria, tests, fixture changes, emulator choice,
verification command shapes, likely files, and risks.

## Candidate First Batch

1. Step Functions execution diagnostics upgrade.
2. API Gateway route diagnostics.
