---
name: Feature proposal
about: Propose a new MCP tool or significant capability expansion.
title: '[Feature] '
labels: 'feature'
---

## User intent

<!-- What investigation question should this tool answer? One sentence. -->

## Affected AWS service(s)

<!-- Which boto3 service(s) the tool would call. -->

## Proposed tool name

<!-- Must satisfy the rules in `docs/naming-conventions.md`. -->

## Inputs

<!-- List of arguments and their types. -->

- `arg_name` (type): description

## Outputs

<!-- What the tool returns. If this is a dependency-style tool, reference the
dependency-tool contract documented in `docs/tools.md`. -->

## Safety check

<!-- Confirm against `docs/standards.md`:
- Are all required AWS actions read-only?
- Does the output avoid disclosing secrets, full IAM/resource policies, or
  object contents?
-->

- [ ] Read-only AWS actions only
- [ ] No secret / policy / object disclosure

## Estimated scope

<!-- small / medium / large. How many existing helpers would be reused? -->

## Existing alternatives

<!-- Does any current tool partially cover this? Cite `docs/features.md` and
the Quick Capability Reference matrix. -->

## Acceptance criteria

<!-- At minimum, the tests that would prove this works. -->

- [ ] Unit tests covering ...
- [ ] Integration / mocked-boto test covering ...

---

By submitting this, you confirm the proposal satisfies the rules in [`docs/standards.md`](../../docs/standards.md). For implementation guidance see [`docs/contributing/add-a-tool.md`](../../docs/contributing/add-a-tool.md).
