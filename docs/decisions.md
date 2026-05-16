# Decisions

A lightweight ADR log for `aws-safe-mcp`.

## Purpose

This file records feature candidates that were considered and rejected or
deferred, with the reasoning preserved so they are not relitigated each
planning cycle. The active, prioritized work list lives in
[backlog.md](backlog.md); the long-term position lives in [vision.md](vision.md);
the non-negotiable safety boundaries are pinned in `README.md`, `SECURITY.md`,
`docs/architecture.md`, `docs/goal.md`, `docs/limitations.md`, and
`tests/test_invariants.py`.

## Format

Each entry is a short ADR.

```
## YYYY-MM — <Title>
**Status:** rejected | deferred | superseded
**Context:**
**Decision:**
**Rationale:**
**Revisit when:**
```

Keep `Rationale` to 2 to 4 sentences. Link to the source-of-truth doc or test
that anchors the decision so future readers can verify the constraint without
re-reading the whole repository.

## Seed Entries

These are the historical record. They are not a planning queue.

## 2026-05 — Raw `aws_call` SDK passthrough tool

**Status:** rejected

**Context:** Repeated request from agent-style use cases: expose a generic
`aws_call(service, operation, params)` so the AI client can reach any AWS
read API without waiting for a curated tool.

**Decision:** Do not ship a raw SDK passthrough in v1, and treat it as a
permanent non-goal rather than a deferred candidate.

**Rationale:** `README.md` "Safety Promises" and `docs/architecture.md` "No Raw
SDK Passthrough" pin this explicitly. A passthrough is hard to audit, makes
redaction and bounded-output guarantees impossible to enforce per-shape, and
collapses the project's positioning relative to AWS MCP described in `README.md`
"How This Differs From AWS MCP". Anything a passthrough would enable should
instead become a curated, bounded diagnostic tool.

**Revisit when:** A v2 safety model is on the table that can prove per-shape
redaction and bounded outputs without per-tool curation, and `SECURITY.md`
"Project Safety Boundaries" is updated to allow it.

## 2026-05 — Mutating actions (Put / Update / Delete / Invoke / Publish / SendMessage) via opt-in flag

**Status:** rejected

**Context:** Suggestion to permit write-capable AWS calls when the user passes
an explicit `--allow-writes` flag or sets a `readonly: false` config value.

**Decision:** Reject for v1. The CLI accepts `--readonly`, but write-capable
tools are not exposed at all regardless of the flag's value.

**Rationale:** `SECURITY.md` "Project Safety Boundaries" lists write-capable
tools first in the not-included set, and `tests/test_invariants.py` pins the
no-write-tools invariant. Allowing a flag to flip that promise breaks the
contract that the audit log, redaction, and account allowlist were designed
around, and makes the project ambiguous with AWS MCP. If a user needs to
mutate AWS, they should use the AWS CLI, AWS console, or AWS MCP directly.

**Revisit when:** A future major version introduces an explicit, per-tool,
test-pinned opt-in model with a separate audit and consent surface, and that
change is recorded as a superseding decision here.

## 2026-05 — Returning raw IAM policy documents

**Status:** rejected

**Context:** Several diagnostic tools (`get_iam_role_summary`,
`explain_iam_simulation_denial`, KMS / Lambda / SNS / SQS / S3 policy
inspection) could be "more useful" if they returned the full policy JSON so the
AI client can reason over conditions directly.

**Decision:** Do not return raw IAM policy documents, KMS key policies, queue
policies, topic policies, bucket policies, Lambda resource policies, or full
state-machine ASL definitions. Return shape, counts, statement summaries,
matched-statement metadata, and `unknown` verdicts instead.

**Rationale:** Policy documents routinely embed account IDs, principal ARNs,
condition values, and resource ARNs that the redaction layer cannot
context-classify safely. `docs/features.md` repeatedly calls out that policy
inspection tools return shape rather than verbatim documents, and
`docs/architecture.md` "Safety Rules For New Tools" forbids returning full
policy JSON. Surfacing the document also defeats the bounded-output goal.

**Revisit when:** A per-statement redaction model exists that can prove no
principal, account, or resource-ARN leak under test, and `docs/limitations.md`
"Logs And Sensitive Data" is updated to reflect it.

## 2026-05 — S3 object body reads and DynamoDB item reads/scans/queries

**Status:** rejected

**Context:** "What was actually in the message?" investigations frequently
want to peek at an S3 object, a DynamoDB item, an SQS message, or a Step
Functions execution payload to confirm a hypothesis.

**Decision:** Reject all data-plane reads. The server returns metadata only:
bucket configuration, notification destination readiness, table schema,
stream-to-Lambda readiness, queue attributes, redacted execution
input/output summaries, and so on. No `GetObject`, no DynamoDB `GetItem` /
`Query` / `Scan`, no SQS `ReceiveMessage`.

**Rationale:** `README.md` "Safety Promises", `SECURITY.md` "Project Safety
Boundaries", and `docs/goal.md` "Safety Rules" all pin this. Application data
is the highest-leak surface in the AWS account and the redaction layer is not
designed to classify arbitrary application payloads. The trade-off is
explicitly accepted in `docs/limitations.md` "Logs And Sensitive Data" and in
[vision.md](vision.md) "Trade-Offs We Accept".

**Revisit when:** Never under the v1 safety model. A v2 may introduce
explicit, scoped data-plane reads behind per-tool opt-in with separate audit
surface, recorded as a superseding decision.

## 2026-05 — Cloud-hosted variant of the server

**Status:** deferred

**Context:** Suggestion to offer a hosted endpoint so users do not have to
install `uvx` locally or manage their own AWS profile wiring.

**Decision:** Defer indefinitely. The published shape stays a local stdio
process invoked by the user's MCP client.

**Rationale:** [vision.md](vision.md) "What This Project Is Not" pins this as a
non-goal. Hosting introduces credential custody, multi-tenant blast radius,
and an authorization boundary that is no longer IAM-by-the-caller, all of
which contradict the threat model in `docs/architecture.md` "IAM Is The
Authorization Boundary". The local stdio shape is what makes the safety
promises in `SECURITY.md` defensible.

**Revisit when:** A credible deployment pattern exists in which the hosted
variant cannot see the caller's AWS credentials at rest and the account
allowlist is enforced by the caller's environment rather than the host. That
change would require a new `SECURITY.md` section and updates to
`tests/test_invariants.py`.

## 2026-05 — General AWS documentation and how-to queries

**Status:** rejected

**Context:** "Ask AWS docs" prompts are a common AI-client workflow; users
sometimes expect this server to answer them because it is "the AWS MCP".

**Decision:** Do not ship documentation, how-to, or AWS-API-reference
retrieval tools. Point users at AWS MCP for that workload.

**Rationale:** `README.md` "How This Differs From AWS MCP" is explicit that
AWS MCP is the right tool for documentation, broad AWS APIs, and general
cloud operations, while `aws-safe-mcp` is "deliberately narrower: a read-only
diagnostic layer for serverless workloads". Adding a documentation surface
would dilute that positioning, increase the dependency surface, and create a
maintenance burden against AWS's own moving docs. The pairing model ("use
both when that helps") is the recommendation in README.

**Revisit when:** AWS MCP loses or removes that surface, or a documentation
need emerges that cannot be answered by the AWS MCP pairing model and is
clearly diagnostic rather than general reference.

## How To Add A New Decision

When a candidate is rejected or deferred during planning, design review, or PR
discussion:

1. Add an entry under "Seed Entries" using the Format block above. Use a
   short, descriptive title and the current `YYYY-MM`.
2. Anchor the `Rationale` to the source-of-truth doc or test that justifies
   the decision (`README.md` "Safety Promises", `SECURITY.md` "Project Safety
   Boundaries", `docs/architecture.md`, `docs/limitations.md`,
   `tests/test_invariants.py`, etc.).
3. Reference the new entry from the issue or PR that closed the candidate, so
   future searches surface the decision alongside the discussion.
4. If the decision supersedes an existing entry, set the prior entry's
   `Status` to `superseded` and link forward to the new one.
5. Do not delete entries. The point of this log is that decisions are durable;
   only `Status` lines change.
