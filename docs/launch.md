# Launch Notes

Use this checklist when making the repository public or announcing a release.
Keep all examples sanitized: no real profile names, account IDs, ARNs, resource
names, logs, customer names, or credential material.

## GitHub Repository Setup

Recommended description:

```text
Safe, read-only MCP server for AWS investigation by AI coding agents
```

Recommended topics:

```text
mcp
aws
ai-agents
model-context-protocol
lambda
serverless
cloudwatch
eventbridge
step-functions
developer-tools
security
```

Before publishing publicly:

- Confirm CI is green.
- Confirm `README.md` renders well on GitHub.
- Confirm `SECURITY.md`, `CONTRIBUTING.md`, and `LICENSE` are visible.
- Confirm issue templates and pull request template are present.
- Run the release checklist in `docs/release.md`.
- Run the tracked secret/local-detail scans from `docs/release.md`.

## Launch Post

Short positioning:

```text
I built aws-safe-mcp because raw cloud access is too broad for AI agents.
It gives AI clients read-only, bounded AWS investigation tools instead:
dependency graphs, failure summaries, identity checks, and permission hints,
without exposing a generic AWS SDK passthrough.
```

Suggested post outline:

- Problem: AI coding agents need AWS context, but raw SDK access is too much.
- Approach: curated read-only MCP tools with account allowlisting and redaction.
- Demo: trace an S3/EventBridge/Step Functions/Lambda flow from one prompt.
- Safety: no writes, no raw SDK passthrough, no secret/environment values, no S3
  object bodies, no DynamoDB item reads.
- Call to action: try the README quickstart, review the safety model, and open
  issues for useful investigation workflows.

## Demo Snippet

Use placeholder-only examples:

```text
Prompt:
Trace the event-driven flow for source aws.s3, detail type Object Created,
bucket <bucket-name>, and .csv object keys. Use AWS MCP only.

Result:
S3 Object Created event
  -> EventBridge rule
  -> Step Functions state machine
  -> Lambda task
  -> DynamoDB permission check: allowed
```

Never paste live MCP output containing real account IDs, ARNs, profile names,
resource names, log messages, or policy identifiers into launch material.
