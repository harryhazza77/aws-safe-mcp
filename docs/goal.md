# Goal

Live execution prompt for the `aws-safe-mcp` workstream. For long-term
direction read [vision.md](vision.md); for the active execution plan read
[backlog.md](backlog.md), which now also carries the documentation-refresh
backlog.

## Execution Prompt

When the user invokes `/goal`, do this:

1. Read [vision.md](vision.md), [backlog.md](backlog.md), and
   [standards.md](standards.md).
2. Pick the next backlog item: the top of [backlog.md](backlog.md) unless the
   user names a specific one.
3. Cross-check [features.md](features.md) and [tools.md](tools.md) to avoid
   duplicating an existing capability.
4. Implement the smallest version that meets the backlog acceptance notes.
5. Add or update focused tests; reuse the moto fixtures wired through
   `tests/conftest.py` where available.
6. Update [tools.md](tools.md) and move the completed item from
   [backlog.md](backlog.md) into [features.md](features.md).
7. Run `python -m pytest -q`, `python -m ruff check .`, and
   `python -m mypy src`.
8. Commit one focused change in the main repo. Commit any Terraform fixture
   changes separately in `/Users/hareshpatel/Documents/code/aws-sdk-mcp-tf`.
9. Repeat from step 2 until the backlog is empty, an item is blocked, or the
   user stops the run.

All safety, feature, and naming rules live in [standards.md](standards.md).
Every step must satisfy them.

## Fixture Strategy

Terraform fixtures live in the separate
`/Users/hareshpatel/Documents/code/aws-sdk-mcp-tf` repo. Verify resources with
the AWS CLI against the localhost emulator (MiniStack on
`http://127.0.0.1:4566`) before relying on them, and point `aws-safe-mcp` at
the same emulator via the `endpoint_url` override in the config file.

## Completion Rule

`/goal` means continue the full workstream; if the run stops before the
backlog is empty, report the exact stopping point, repository state, completed
commits, and the next backlog item.

**Role of this file:** goal.md is the workstream replay script. For long-term
strategy see [vision.md](vision.md). For the prioritized candidate queue see
[backlog.md](backlog.md).
