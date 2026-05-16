# Vision

The forward-looking position for `aws-safe-mcp`. Read this before adding a
feature, opening a scope debate, or picking up the next backlog item. Rejected
and deferred ideas live in [decisions.md](decisions.md).

## What This Project Is

`aws-safe-mcp` is a local, read-only, AI-agent-facing MCP server for safely
investigating serverless AWS workloads. It runs over stdio against the caller's
own AWS credentials and exposes curated diagnostic tools instead of a raw SDK
shell. Every tool call is gated by a mandatory `allowed_account_ids` allowlist,
restricted to read-only AWS APIs, bounded in pagination/time/result count, and
passed through redaction and truncation before it reaches the client. The
operating model is documented in `README.md` ("Safety Promises"), `SECURITY.md`
("Project Safety Boundaries"), and `docs/architecture.md` ("Core Decisions").

## What This Project Is Not

Explicit non-goals. None of these are deferred features; they are scope
boundaries that gate every new tool.

- Not a general AWS CLI or SDK replacement. There is no `aws_call(service,
  operation, params)` tool and there will not be one in v1.
- Not a cloud-hosted service. The server is a local stdio process invoked by
  the user's MCP client.
- Not a write-capable tool. No Put/Update/Delete/Invoke/Publish/SendMessage or
  any other mutating action is exposed.
- Not an alternative to AWS MCP for broad documentation or general AWS API
  questions. Those use cases belong to AWS MCP (see README "How This Differs
  From AWS MCP").
- Not a permissions-grant tool. IAM is and stays the authorization boundary;
  the server never elevates, assumes additional roles on the user's behalf, or
  ships its own resource allowlist.
- Not a data-plane reader. No S3 object body reads, DynamoDB item/scan/query,
  Secrets Manager values, SSM parameter values, KMS decrypt or data-key calls,
  or full Lambda environment values.

## 12-Month Direction

Where the project should sit roughly a year from now. Each bullet builds on the
existing dependency-graph and investigation-tool contracts in
`docs/architecture.md`; nothing here loosens a safety boundary.

- Deeper failure-correlation narratives. The recent
  `generate_application_health_narrative`, `build_log_signal_correlation_timeline`,
  and `run_first_blocked_edge_incident` tools establish the pattern. Extend it
  so an AI client can answer "what broke first and what is the safe next
  check?" across more service combinations without leaving the bounded
  contract.
- Broader cross-service investigation where read-only diagnostics are
  well-defined. Cognito user-pool authorizer paths, RDS proxy and parameter
  metadata, and OpenSearch domain reachability are plausible candidates if and
  only if their read-only surface fits the dependency-graph contract in
  `docs/architecture.md`. `Open question`: whether each of these clears the
  redaction and bounded-output bar; treat as hypothesis until each is
  designed.
- Better local emulator coverage. MiniStack on `127.0.0.1:4566` is the
  current verified path (see README quickstart and `docs/features.md` "Local
  Emulator Workflows"). Grow the `../aws-sdk-mcp-tf` fixture catalogue so more
  diagnostic tools have reproducible local proof, and flag tools whose proof
  remains untested against an emulator.
- Expanded test fixtures and safety invariants. `tests/test_invariants.py`
  pins the read-only / no-passthrough / no-mutation promises. New tools should
  extend that pin set, not work around it.
- AI-client-agnostic prompt library. `docs/ai-clients.md`, `docs/claude-code.md`,
  `docs/claude-desktop.md`, and `docs/cursor.md` already document setup. The
  next step is a curated, provider-neutral library of investigation prompts so
  the server's diagnostic value is not buried in tool names. `Open question`:
  whether this lives in-repo or graduates to a sibling artifact.

## Scope Boundaries We Will Defend

Non-negotiables. Every proposed feature is measured against these before
acceptance criteria are even discussed.

- Read-only AWS APIs only. Enforced in `docs/goal.md` "Safety Rules" and
  `docs/architecture.md` "Safety Rules For New Tools".
- No raw AWS SDK passthrough. Pinned in README "Safety Promises", `SECURITY.md`
  "Project Safety Boundaries", and `docs/architecture.md` "No Raw SDK
  Passthrough".
- Redaction and truncation by default. Long strings truncated, secret-like
  fragments redacted, full IAM policy/state-machine/ASL documents not returned.
- Mandatory `allowed_account_ids` allowlist. Account mismatch fails closed
  before any AWS resource call runs.
- Bounded pagination, time windows, and result counts. No unbounded list,
  search, or log queries.
- Safety tests pinned in CI. `tests/test_invariants.py` plus the full
  verification suite in README "Development" run on every change.
- Partial results with warnings over guessing. When IAM simulation, an optional
  read, or an emulator capability is missing, tools return partial answers and
  warnings instead of fabricating or failing the whole investigation.

## Trade-Offs We Accept

The price of those boundaries. These are not bugs.

- Dependency graphs are best-effort. They cannot see relationships that live
  only in application code, dynamic configuration, opaque payloads, or policy
  documents the caller cannot read (see `docs/limitations.md` "Best-Effort
  Graphs").
- IAM verdicts can be `unknown`. Permission checks depend on condition keys,
  session policies, boundaries, SCPs, resource policies, tags, and request
  context. The tool returns `unknown` rather than guessing (see
  `docs/limitations.md` "IAM And Policy Checks").
- No message-content or payload inspection. SQS receive, DynamoDB item read,
  S3 GetObject, and full execution input/output are explicitly out of scope.
  This rules out a class of "what was inside the message" investigations.
- Empty lists can be ambiguous. Visibility follows the active credentials, so
  an empty result may mean "nothing exists" or "your role cannot see it".
- Some workflows need both AWS MCP and `aws-safe-mcp`. We accept the
  positioning cost of being deliberately narrower than AWS MCP.
- Audit log noise on stderr. Every tool call is structured-JSON audit logged;
  callers must tolerate that channel.

## Signals That Would Shift Direction

What would justify reopening a scope decision.

- A sister project absorbs the role. If AWS MCP or another upstream server
  adopts an equivalent bounded, read-only, redacted serverless-investigation
  surface with comparable safety tests, the value of a separate project
  shrinks.
- A new AWS read-API category emerges. For example, a CloudTrail-driven or
  Resource Explorer-driven investigation surface that is unambiguously safe
  and read-only could justify a new tool family.
- A security regression in a popular adjacent server. If an adjacent MCP
  server is found leaking secrets, exposing raw SDK passthrough, or bypassing
  account scoping, the bar for the same patterns here gets stricter rather
  than looser.
- A v2 safety model. A future major version may revisit specific boundaries
  (for example, opt-in mutating actions behind explicit per-tool flags). Any
  such shift must go through `docs/decisions.md` and update
  `tests/test_invariants.py` before code lands.

## Decision Link

Candidates that were considered and rejected or deferred are recorded in
[decisions.md](decisions.md) so they are not relitigated. When a planning
discussion ends with "no, because...", capture it there.

**Role of this file:** vision.md states the 12-month strategy. For the
prioritized work queue see [backlog.md](backlog.md). For the live execution
prompt see [goal.md](goal.md).
