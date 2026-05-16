# Documentation

`aws-safe-mcp` is a local, read-only MCP server for investigating AWS
serverless workloads from AI coding agents.

## Start here

- [Quickstart](quickstart.md): zero to first successful tool call in under
  five minutes.

## By role

### First-time user

- [Quickstart](quickstart.md): install, configure, and verify.
- [AI client notes](ai-clients.md): provider-neutral smoke prompts.
- [Troubleshooting](troubleshooting.md): common first-run failures.

### On-call SRE

- [Tool catalog](tools.md): every tool, its inputs, and what it returns.
- [Features](features.md): capabilities grouped by investigation workflow.
- [Troubleshooting](troubleshooting.md): fast triage of broken setups.

### Contributor

- [Development guide](development.md): local setup and the verification suite.
- [Add a tool](contributing/add-a-tool.md): the contract a new MCP tool must
  meet.
- [Naming conventions](naming-conventions.md): tool, fixture, and module
  naming rules.

### Security reviewer

- [SECURITY.md](../SECURITY.md): disclosure policy and supported versions.
- [Threat model](security/threat-model.md): in-scope risks and mitigations.
- [Redaction scope](security/redaction-scope.md): what is redacted and why.

### Release engineer

- [Release runbook](release.md): cut, verify, and publish a release.
- [Release checklist](release-checklist.md): the gate before tagging.
- [Rollback](rollback.md): how to recover a bad release.

### Feature planner

- [Goal](goal.md): editable prompt for the next feature workstream.
- [Backlog](backlog.md): candidate features and fixture ideas.
- [Vision](vision.md): direction for the project beyond the current backlog.
- [Decisions](decisions.md): ADR-style log of significant design calls.

## Reference

- [Tool catalog](tools.md)
- [Features](features.md)
- [Architecture](architecture.md)
- [Limitations](limitations.md)
- [Lambda network access contract](lambda-network-access.md)

## Operating

- [AI client notes](ai-clients.md)
- [Claude Code](claude-code.md)
- [Claude Desktop](claude-desktop.md)
- [Cursor](cursor.md)
- [Troubleshooting](troubleshooting.md)

## Contributing and release

- [Development guide](development.md)
- [Add a tool](contributing/add-a-tool.md)
- [Naming conventions](naming-conventions.md)
- [Release runbook](release.md)
- [Release checklist](release-checklist.md)
- [Rollback](rollback.md)

## Security

- [SECURITY.md](../SECURITY.md)
- [Threat model](security/threat-model.md)
- [Redaction scope](security/redaction-scope.md)

## Planning

- [Goal](goal.md)
- [Backlog](backlog.md)
- [Vision](vision.md)
- [Decisions](decisions.md)

## Personas

- [Personas index](personas/README.md): who the project is built for and the
  scenarios each persona uses.
