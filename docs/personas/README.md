# Documentation Personas

This directory holds **replay prompts** representing the audience personas this project's docs address. Each `*.md` file is a self-contained prompt: drop it into a fresh AI session (or have a reviewer adopt the mindset manually) and produce a structured documentation review from that persona's point of view.

## Why

A single author can't easily spot the gaps a first-time PyPI user or a security reviewer would hit. Each persona has different prior knowledge, different goals, and different failure modes. Replaying the docs through each persona surfaces:

- **Gaps** — questions the persona would ask that no doc answers.
- **Improvements** — sections that exist but are at the wrong level or hidden.
- **Refactors** — content scattered across files that one persona would expect in one place.
- **Quotes** — exact lines that confuse, mislead, or violate the persona's expectations.

## How to replay

1. Pick a persona file (e.g. [`ai-assisted-sre.md`](./ai-assisted-sre.md)).
2. Open a fresh AI session with access to this repo, or hand the prompt to a human reviewer.
3. Paste the persona file contents as the system or first user message.
4. The persona will read the docs corpus and return a structured report.
5. Triage the report — fix critical gaps, file issues for the rest, ignore non-applicable feedback.

## Personas in this set

| File | Persona | Primary goal with the docs |
|---|---|---|
| [`ai-assisted-sre.md`](./ai-assisted-sre.md) | AI-Assisted SRE | Diagnose a failing AWS workload through an AI agent |
| [`local-ai-client-user.md`](./local-ai-client-user.md) | Local AI Client User | Install + configure the MCP server in their AI client |
| [`security-reviewer.md`](./security-reviewer.md) | Security Reviewer | Decide if the server is safe to deploy in their org |
| [`open-source-contributor.md`](./open-source-contributor.md) | Open-Source Contributor | Add a tool / fix a bug / extend the project |
| [`pypi-package-user.md`](./pypi-package-user.md) | PyPI Package User | Try it out without prior MCP knowledge |
| [`release-engineer.md`](./release-engineer.md) | Release Engineer | Cut a safe release without leaking secrets or mutating verbs |
| [`feature-planner.md`](./feature-planner.md) | Feature Planner | Decide what to build next and why |

## Docs corpus

Each persona evaluates the same corpus:

**Root:** `README.md`, `AGENTS.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`

**`docs/`:** `ai-clients.md`, `architecture.md`, `backlog.md`, `claude-code.md`, `claude-desktop.md`, `cursor.md`, `development.md`, `features.md`, `goal.md`, `lambda-network-access.md`, `launch.md`, `limitations.md`, `README.md`, `release.md`, `tools.md`

## When to refresh

Re-run a persona replay whenever:

- A new tool, command, or config field is added.
- A persona's prior knowledge shifts (e.g. MCP becomes mainstream, fewer caveats needed).
- A new persona emerges (e.g. enterprise platform team, training-data contributor).

Add new personas as new files here. Keep the index above in sync.
