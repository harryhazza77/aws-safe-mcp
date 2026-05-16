# Threat Model

This document is intended for security reviewers, appsec engineers, and
compliance owners evaluating whether to permit `aws-safe-mcp` on engineer
laptops. Each claim is either backed by code or test evidence (cited inline) or
explicitly marked `asserted-only` where no automated test pins the property
today.

## 1. Scope And Assumptions

### What this server is

`aws-safe-mcp` is a local Model Context Protocol (MCP) server packaged as a
Python distribution. It runs as a stdio child process of an AI client (Claude
Code, Claude Desktop, Cursor, or any provider-neutral MCP client). See
[`README.md`](../../README.md) and [`docs/architecture.md`](../architecture.md).

It is read-only by construction. The server exposes a curated catalog of AWS
investigation tools that call read-only AWS APIs via `boto3` using the caller's
existing AWS credentials (profile, SSO, or environment variables). AWS IAM
remains the resource authorization boundary
([`docs/architecture.md`](../architecture.md), "IAM Is The Authorization
Boundary").

### Trust boundaries crossed

| # | Boundary | Direction | Crossed by |
| - | --- | --- | --- |
| 1 | MCP client (LLM-driven) ↔ MCP server process | stdio | Tool arguments in; structured JSON results out |
| 2 | MCP server ↔ local boto3 session | in-process | Resolved profile/region; signed AWS requests |
| 3 | Laptop ↔ AWS control plane | HTTPS | Read-only AWS API calls (sigv4) |
| 4 | MCP server ↔ stderr | OS pipe | Structured audit JSON to the parent process / terminal |

### Assumptions

- The operator has selected a non-production AWS profile or a role with the
  minimum read-only permissions needed.
- The operator has authored a config file with an explicit
  `allowed_account_ids` list. The server refuses to start without one
  ([`src/aws_safe_mcp/config.py`](../../src/aws_safe_mcp/config.py),
  `allowed_account_ids: list[str] = Field(min_length=1)`).
- The local laptop is not already fully compromised. Endpoint compromise is out
  of scope (see Section 5).
- Network egress to AWS endpoints is permitted by the host network policy.

### What this server is NOT

- Not a cloud-hosted multi-tenant service. There is no shared backend, no
  account federation, and no token-sharing surface.
- Not a generic AWS SDK passthrough. There is no `aws_call(service, operation,
  params)` tool ([`CONTRIBUTING.md`](../../CONTRIBUTING.md), "Do not add a
  generic `aws_call`").
- Not a write surface. `readonly` is enforced as `true` in v1
  ([`src/aws_safe_mcp/config.py`](../../src/aws_safe_mcp/config.py),
  `readonly_must_be_enabled`).
- Not a secret retrieval surface. No tool returns Secrets Manager values, SSM
  parameter values, Lambda environment variable values, S3 object bodies, KMS
  plaintext, or DynamoDB item contents ([`SECURITY.md`](../../SECURITY.md),
  "Project Safety Boundaries").

## 2. Data-Flow Summary

```
+-----------------------+
| MCP client (LLM host) |
+-----------+-----------+
            | stdio (JSON-RPC)         Guardrail: tool schema validation
            v                          + arg redaction at audit time
+-----------+-----------+
| aws-safe-mcp process  |
|  - audit decorator    |
|  - tool function      |
+-----------+-----------+
            | boto3 client             Guardrail: AwsRuntime.client()
            v                          requires STS identity refresh +
                                       allowed_account_ids match
+-----------+-----------+
| boto3 session + STS   |
+-----------+-----------+
            | HTTPS sigv4              Guardrail: BotoConfig with 5s connect,
            v                          20s read, retries=3, custom UA
+-----------+-----------+
| AWS read-only APIs    |
+-----------+-----------+
            | response
            v
+-----------+-----------+
| Tool summariser       |              Guardrail: redact_data / redact_text /
| (per-family shaping)  |              truncate_string + family-specific
+-----------+-----------+              denylists (no policy docs, no env
            |                          values, no payloads)
            +---> stderr audit JSON    Guardrail: redact_data on bound args
            v
+-----------+-----------+
| MCP client (LLM host) |
+-----------------------+
```

Each hop is implemented in the following modules:

- stdio entrypoint and tool registration: `src/aws_safe_mcp/server.py`,
  `src/aws_safe_mcp/main.py`.
- Audit decorator: `src/aws_safe_mcp/audit.py` (`AuditLogger.tool`).
- Runtime, STS check, and account allowlist:
  `src/aws_safe_mcp/auth.py` (`AwsRuntime.client`,
  `_load_and_validate_identity`).
- Redaction: `src/aws_safe_mcp/redaction.py`.
- Tool families: `src/aws_safe_mcp/tools/*.py`.

## 3. STRIDE Table

| Category | Threat scenario | Mitigation in code | Test or evidence | Verdict |
| --- | --- | --- | --- | --- |
| Spoofing | LLM induces the server to call AWS in an account the operator did not authorize | Mandatory `allowed_account_ids` (≥1, 12-digit) validated at config load; STS `GetCallerIdentity` checked before every client; `require_account_allowed` raises `AwsAuthError` on mismatch (`src/aws_safe_mcp/auth.py`, `_load_and_validate_identity`; `src/aws_safe_mcp/config.py`, `require_account_allowed`) | `tests/test_config.py`, `tests/test_identity.py` exercise allowlist enforcement | backed |
| Tampering | LLM induces a mutating AWS write (create/delete/put/invoke/publish/send) | No mutating boto3 verbs in any tool module; `readonly_must_be_enabled` rejects `readonly: false`; no generic `aws_call` tool exists | `tests/test_invariants.py::test_no_mutating_boto3_calls` statically greps every tool module for mutating verb prefixes (`put_`, `create_`, `delete_`, `update_`, `send_`, `publish`, `invoke`, ...) with documented `READ_ONLY_EXCEPTIONS` for `start_query`, `simulate_principal_policy`, `simulate_custom_policy` | backed |
| Repudiation | Tool is invoked without an audit trail | Every `@mcp.tool()` must be decorated with `@audit.tool(...)`; audit decorator emits `tool_call_started`, `tool_call_completed`, or `tool_call_failed` JSON to stderr (`src/aws_safe_mcp/audit.py`) | `tests/test_invariants.py::test_every_mcp_tool_is_audit_wrapped` and `::test_audit_tool_names_are_unique`; `tests/test_audit.py` | backed |
| Repudiation | Audit log is tamper-evident or immutable on disk | Audit records are written to stderr only; no append-only log, no signature, no hash chain | None: stderr is captured by the parent MCP client and rotates with that process | asserted-only |
| Information disclosure | Lambda environment variable values are returned to the LLM | `redact_environment` replaces every value with `[REDACTED]` when `redact_environment_values: true` (default) (`src/aws_safe_mcp/redaction.py`); env-var-keyed dependency hints skip secret-like keys before parsing values (`src/aws_safe_mcp/tools/lambda_tools.py::_lambda_environment_dependency_hints`) | `tests/test_redaction.py::test_redact_environment_hides_all_values_by_default`; `tests/test_redaction_properties.py::test_redact_environment_replaces_every_value_when_env_locked`; `tests/test_redaction_properties.py::test_redact_environment_redacts_secret_keys_even_when_unlocked` | backed |
| Information disclosure | Secret-like keys leak via nested mappings, lists, or unstructured log text | `redact_data` recursively walks `Mapping`/`Sequence` and replaces values under any key matching `SECRET_KEYWORDS`; `redact_text` strips `KEY=value` style pairs from log message text | `tests/test_redaction_properties.py::test_redact_data_preserves_shape_and_redacts_secret_keys`, `::test_redact_text_strips_secret_key_values_from_text`, `::test_redact_text_is_idempotent_on_already_redacted_input` (hypothesis property tests) | backed |
| Information disclosure | Unbounded response leaks a large secret-bearing region of an AWS payload | `truncate_string` enforces `max_string_length` (default 2000, bounded 100–10000) on every string traversed by `redact_data`; pagination caps via `max_results`; time-window caps via `max_since_minutes` | `tests/test_redaction_properties.py::test_truncate_string_never_exceeds_a_bounded_envelope`, `::test_truncate_string_is_idempotent`; per-string truncation only — no overall response byte cap | asserted-only (per-response byte cap) / backed (per-string cap) |
| Denial of service | LLM triggers expensive AWS calls (e.g. paginated logs filter) and stalls the agent | `BotoConfig(connect_timeout=5, read_timeout=20, retries=3)` (`src/aws_safe_mcp/auth.py`); per-tool `max_results`, `max_subscriptions`, `max_events` caps; bounded pagination | Per-tool tests (`tests/test_cloudwatch.py`, `tests/test_sqs.py`, etc.) cover cap behavior | backed |
| Elevation of privilege | LLM uses the server to escalate beyond the caller's IAM permissions | The server inherits the caller's IAM principal verbatim; no `AssumeRole`, no impersonation, no privilege expansion path; missing IAM is non-fatal and reported as `unknown` | `tests/test_iam.py`, `tests/test_identity.py` | backed |
| Elevation of privilege | Error messages or stack traces leak credentials, tokens, or full ARNs that bypass redaction | `src/aws_safe_mcp/errors.py` formats safe error envelopes; audit decorator records only `error_type` (class name), not the exception message | Audit emission verified in `tests/test_audit.py`; the broader claim that no error path leaks a credential is not exhaustively fuzzed | asserted-only |

## 4. Safety Claims Matrix

| # | Claim | Where stated | Code path | Test | Verdict |
| - | --- | --- | --- | --- | --- |
| 1 | No write-capable AWS tool is exposed in v1 | README §Safety Promises; SECURITY §Project Safety Boundaries; CONTRIBUTING §Design Principles | All `tools/*.py` use read-only verbs; `READ_ONLY_EXCEPTIONS` lists the three benign exceptions | `tests/test_invariants.py::test_no_mutating_boto3_calls` | backed |
| 2 | No generic `aws_call` / raw SDK passthrough | README §Safety Promises; CONTRIBUTING §Design Principles; architecture §No Raw SDK Passthrough | No such tool exists in `server.py` | Repository search; no test pins absence | asserted-only |
| 3 | AWS account IDs must be allowlisted | README §Safety Promises; SECURITY §What Counts As Security Sensitive | `AwsSafeConfig.allowed_account_ids` (`min_length=1`); `require_account_allowed`; called from `_load_and_validate_identity` | `tests/test_config.py`, `tests/test_identity.py` | backed |
| 4 | Tool calls are audit logged as structured JSON to stderr | README §Safety Promises | `audit.AuditLogger.tool` decorator emits JSON via `logging.Logger.info`; `configure_logging` sets stream defaults | `tests/test_audit.py`; `tests/test_invariants.py::test_every_mcp_tool_is_audit_wrapped` | backed |
| 5 | Secret-like values are redacted | README §Safety Promises; CONTRIBUTING §Design Principles | `is_secret_like_key`, `redact_value`, `redact_environment`, `redact_data`, `redact_text` | `tests/test_redaction.py`, `tests/test_redaction_properties.py` (hypothesis) | backed |
| 6 | Long strings are truncated | README §Safety Promises | `truncate_string`, configured via `RedactionConfig.max_string_length` | `tests/test_redaction_properties.py::test_truncate_string_*` | backed |
| 7 | No S3 object body reads | SECURITY §Project Safety Boundaries; limitations §Scope | `tools/s3.py` calls only `list_*`, `get_bucket_*`; no `get_object` | No test pins absence | asserted-only |
| 8 | No DynamoDB scan, query, or item reads | SECURITY §Project Safety Boundaries; limitations §Scope | `tools/dynamodb.py` calls only `list_tables`, `describe_table` | `tests/test_invariants.py::test_no_mutating_boto3_calls` rejects `scan_`/`query_` only if prefixed mutating; absence of `scan(`/`query(` is not statically enforced | asserted-only |
| 9 | No full Lambda environment variable values returned | README §Safety Promises; SECURITY §Project Safety Boundaries | `tools/lambda_tools.py` returns `environment_variable_keys` only; `_lambda_environment_dependency_hints` skips secret-like keys via `is_secret_like_key` | `tests/test_lambda_tools.py`, `tests/test_redaction_properties.py::test_redact_environment_replaces_every_value_when_env_locked` | backed |
| 10 | Missing AWS credentials do not crash the server at startup | CONTRIBUTING §Local AWS Testing; architecture §Runtime Flow | `AwsRuntime.refresh_identity` records the auth error instead of raising; `require_identity` re-checks on every client call | `tests/test_identity.py` | backed |
| 11 | Config rejects unknown fields and non-HTTP endpoint URLs | CONTRIBUTING (implicit); config validators | `AwsSafeConfig.model_config = ConfigDict(extra="forbid")`; `endpoint_url_must_be_http`; `service_endpoint_urls_must_be_http` | `tests/test_config.py` | backed |
| 12 | Error envelopes do not leak credentials or full secret values | SECURITY §Safe Disclosure Guidance | `src/aws_safe_mcp/errors.py` formats safe errors; audit decorator records `exc.__class__.__name__` only | `tests/test_errors.py` covers shape; full credential-leakage absence not fuzzed | asserted-only |

## 5. Out-Of-Scope Threats

The following threat classes are explicitly outside the project's defensive
scope. Operators relying on `aws-safe-mcp` must mitigate these elsewhere.

- **Compromise of the operator's laptop.** A local attacker with code execution
  inherits the operator's AWS credentials regardless of this server. Defence
  belongs to endpoint security and AWS credential lifetime controls.
- **Malicious AWS principal in an allowed account.** If the allowlisted AWS
  identity has overly broad IAM permissions, the server faithfully exposes
  whatever that identity can read. Mitigation belongs to AWS IAM policy hygiene
  (least-privilege read-only roles).
- **Malicious MCP client.** The server trusts its stdio peer. A malicious MCP
  client can call any registered tool with any arguments the operator's IAM
  identity permits. Defence belongs to MCP client selection and OS-level
  process isolation.
- **Supply-chain compromise of `boto3`, `pydantic`, `PyYAML`, `FastMCP`, or
  another transitive dependency.** The project runs `pip-audit` in CI but does
  not pin a full SBOM with attestations.
- **Compromise of AWS endpoints, AWS account takeover, or AWS-side data
  exfiltration.** Out of scope by definition; this is an AWS responsibility.
- **AWS resources whose names or ARNs are themselves sensitive.** ARNs contain
  account IDs and may encode environment names. They are not redacted (see
  `docs/security/redaction-scope.md`).
- **Application logs containing sensitive business data that does not match the
  `SECRET_KEYWORDS` heuristic.** CloudWatch Logs tools redact `KEY=value`
  fragments matching the keyword list and truncate long strings; they do not
  attempt content classification.
- **Side channels via timing, audit-log volume, or boto3 retry patterns.**
  Not modelled.

## 6. Reporting

Vulnerabilities should be reported privately. See
[`SECURITY.md`](../../SECURITY.md) for the full reporting policy, the GitHub
Security Advisories URL, the safe-disclosure guidance, and the list of
issue classes that count as security-sensitive (secret leaks, write-capable
operations, missing allowlist enforcement, unredacted audit logs, or unbounded
responses).
