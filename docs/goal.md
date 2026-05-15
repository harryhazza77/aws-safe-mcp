# Goal

Use this file to shape an ambitious `aws-safe-mcp` workstream before execution.
Edit it directly, then ask Codex to plan from it.

## Working Goal

Plan and execute a focused set of high-value `aws-safe-mcp` features. Each
feature should be useful to real users, tested, verified against local AWS
emulator fixtures where practical, and committed as a focused change.

## Repositories

- Main code repo: `/Users/hareshpatel/Documents/code/aws-sdk-mcp`
- Terraform fixture repo: `/Users/hareshpatel/Documents/code/aws-sdk-mcp-tf`

## Current Direction

- Use [features.md](features.md) to understand current user-facing capability.
- Use [backlog.md](backlog.md) to choose candidate features.
- Prefer diagnostic workflows over raw list tools.
- Prefer small features that improve safe AWS investigation.

## Fixture Strategy

- Keep Terraform fixtures out of the Python package repo.
- Use MiniStack on `http://127.0.0.1:4566`
- Verify fixture resources with AWS CLI before relying on them in MCP tests.
- Verify `aws-safe-mcp` against the same emulator with `endpoint_url` in the
  config file.

## Feature Rules

Each feature should have:

- Clear user-facing value.
- Narrow acceptance criteria.
- Unit tests for behavior, limits, and errors.
- Fixture changes when local emulator proof needs new AWS resources.
- AWS CLI proof against the emulator when applicable.
- `aws-safe-mcp` proof against the emulator when applicable.
- One focused commit in the main repo.
- A separate fixture repo commit when Terraform fixtures change.

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

## Planning Prompt

Ask Codex:

```text
Read docs/features.md, docs/backlog.md, and docs/goal.md.

Create a proposed implementation plan for the next feature set. Start with
planning only; do not write code until I approve the feature list.

For each proposed feature include:
- user value
- existing implementation overlap
- acceptance criteria
- unit test plan
- Terraform fixture changes
- emulator choice: Floci, MiniStack, or both
- AWS CLI verification command shape
- aws-safe-mcp verification command shape
- likely files to change
- risks or open questions
- when finished, move the item from backlog to features

Prefer the smallest sequence of features that proves the direction.
```

## Open Questions

- How many features should the next batch include?
- Should fixture repo commits be paired one-for-one with main repo feature
  commits?
- Which emulator should be the primary verification target for CI later?

## Candidate First Batch

1. SQS queue dependency explanation.
2. Step Functions execution diagnostics upgrade.
3. API Gateway route diagnostics.
