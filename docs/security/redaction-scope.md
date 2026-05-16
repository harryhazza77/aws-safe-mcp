# Redaction Scope

This document describes exactly what `aws-safe-mcp` redacts, what it does not,
and how each guarantee is implemented. Audience: security reviewers and
appsec engineers verifying that this server is safe to expose to an AI client
on an engineer laptop.

All file references are relative to the project root.

## 1. What Is Redacted, Globally

All redaction lives in [`src/aws_safe_mcp/redaction.py`](../../src/aws_safe_mcp/redaction.py).
It is configured by `RedactionConfig` in
[`src/aws_safe_mcp/config.py`](../../src/aws_safe_mcp/config.py).

### The keyword set

```
SECRET_KEYWORDS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "KEY",
    "CREDENTIAL",
    "PRIVATE",
    "AUTH",
)
```

`is_secret_like_key(key)` returns `True` when any keyword appears (case-
insensitively) anywhere in the key name. The match is substring-based, so
`apiToken`, `MY_AWS_SECRET_BAR`, `db_passwd`, and `X_AUTH_HEADER` all match.

### The redaction primitives

| Function | Behavior |
| --- | --- |
| `is_secret_like_key(key)` | Case-insensitive substring match against `SECRET_KEYWORDS`. |
| `redact_value(key, value, config)` | If `redact_secret_like_keys` and the key is secret-like, returns `[REDACTED]`. Otherwise recurses into the value. |
| `redact_environment(env, config)` | If `redact_environment_values` (default `True`), every value becomes `[REDACTED]`. Otherwise only secret-like keys are redacted. |
| `redact_data(value, config)` | Recurses into `Mapping` and `Sequence` structures. Strings are passed through `truncate_string`. Secret-like keys replace the value with `[REDACTED]`. |
| `redact_text(text, config)` | Regex-strips `KEY=value` and `KEY: value` fragments where the key contains any `SECRET_KEYWORDS` token. Then truncates. |
| `truncate_string(value, max_length)` | If longer than `max_length`, returns `value[:max_length] + "...[TRUNCATED] N chars omitted"`. |

### The truncation envelope

`RedactionConfig.max_string_length` defaults to **2000** and is bounded
`100 ≤ N ≤ 10000` (validated by pydantic). Every string traversed by
`redact_data` and every `redact_text` output is clamped to this limit. There is
no overall response byte cap; the cap is per string.

### Defaults

```yaml
redaction:
  redact_environment_values: true   # All env values replaced.
  redact_secret_like_keys: true     # Secret-like keys redacted everywhere.
  max_string_length: 2000
```

These defaults are fail-closed: turning either flag off requires an explicit
config change.

## 2. What Is Redacted, Per Tool Family

The base primitives above apply uniformly. Each tool family then adds
family-specific redaction or omission. The following claims are verified
against the current source.

### Lambda tools (`src/aws_safe_mcp/tools/lambda_tools.py`)

- `get_lambda_summary` returns `environment_variable_keys` only (a sorted list
  of variable names). The corresponding **values are never returned**. Source:
  `_lambda_summary`, lines around 1030–1051.
- `_lambda_environment_dependency_hints` iterates the env variables looking
  for ARN, SQS URL, or HTTP URL shapes, but **first skips any key for which
  `is_secret_like_key(key)` is true** (line 1072). A `MY_TOKEN=...` env
  variable cannot produce a dependency hint even if its value happens to look
  like a URL.
- Recent log/metric tools pass message text through `redact_text` and clamp
  via `runtime.config.redaction.max_string_length` before returning.
- The full Lambda code archive is never fetched.

### IAM tools (`src/aws_safe_mcp/tools/iam.py`)

- `get_iam_role_summary` returns role metadata, attached managed-policy ARNs
  (names only), inline-policy **names only** (not bodies), and a
  `trust_policy` summary containing `service_principals`, `aws_principals`, and
  `federated_principals` extracted from the assume-role policy document. The
  **raw trust-policy JSON is not returned**; the function explicitly maps the
  document down to principal sets (`_trust_policy_summary`).
- `explain_iam_simulation_denial` calls `simulate_principal_policy` and returns
  the decision, the likely policy layer, and missing context keys. The
  response explicitly records `"raw_policy_documents_returned": False`.

### KMS tools (`src/aws_safe_mcp/tools/kms.py`)

- `get_kms_key_summary` returns key metadata, alias list, and a `policy` block
  shaped as `{"available": bool, "policy_name_count": int, "policy_names":
  [...]}`. The **raw key policy document is not returned**.
- `_kms_service_principal_check` reads the default key policy via
  `get_key_policy` only to compute the allowed actions for one named service
  principal; it returns the **action list and a boolean**, never the policy
  document.

### SNS / SQS tools (`src/aws_safe_mcp/tools/sns.py`, `tools/sqs.py`)

- Both families summarise queue/topic policies via `_policy_summary`, which
  returns `{"available": bool, "statement_count": int}` (plus an optional
  parse warning). The **raw policy JSON is not echoed** in the default
  summary; principals and conditions are not echoed by the summariser.
- SNS subscription endpoints flow through `redact_data`, so endpoints that
  happen to live under a secret-like attribute key are redacted. Endpoints
  that are plain email addresses or HTTPS URLs **are returned in cleartext**
  in the `subscriptions` list — they are not classified as secrets by the
  base heuristic. (Treat subscription endpoints as PII-bearing and rely on
  IAM and config-time tag policy rather than the redaction layer.)
- Queue ARNs, names, and `RedrivePolicy` shape (dead-letter target ARN, max
  receive count) are returned in cleartext.

### CloudWatch Logs (`src/aws_safe_mcp/tools/cloudwatch.py`)

- Every log event message is passed through `compact_log_message` then
  `redact_text(message, RedactionConfig(max_string_length=...))`. This strips
  `SECRET=...`, `TOKEN=...`, `PASSWORD=...`, `KEY=...`, `CREDENTIAL=...`,
  `PRIVATE=...`, `AUTH=...` style fragments (and any key containing those
  substrings) before truncating to the configured cap.
- CloudWatch Logs Insights query results similarly pass every field cell
  through `compact_log_message` then `redact_text`.
- Time windows are bounded by `max_since_minutes` (default 1440, max 10080)
  and result counts by `max_results` (default 100, max 1000), preventing
  unbounded log pulls.

### API Gateway (`src/aws_safe_mcp/tools/apigateway.py`)

- Authorizer summaries include `identity_sources` (e.g.
  `method.request.header.Authorization`). These are AWS configuration strings
  that identify *where* the credential is read from, not the credential
  itself. They are **passed through verbatim** to the response. If a custom
  authorizer is configured with an identity source name that happens to
  contain a `SECRET_KEYWORDS` token, the field flows through `redact_data` at
  the top of the response and would be redacted at that point; the per-tool
  shaping does not perform an additional check.
- Integration URIs are returned unmodified for Lambda ARN inference but the
  Lambda function code, environment, and resource-policy document are never
  returned by the authorizer/route tools.

### Step Functions (`src/aws_safe_mcp/tools/stepfunctions.py`)

- `get_step_function_execution_summary` returns the execution `input` and
  `output` fields, but routes them through `_safe_json_field`, which parses
  the JSON, applies `redact_data` (recursive secret-like-key redaction plus
  per-string truncation), and bounds the rendered output by
  `max_string_length`. Plain string values inside the payload are truncated;
  secret-like keys are replaced with `[REDACTED]`.
- State-machine ASL `definition` is parsed for dependency walking (states,
  transitions, retry/catch blocks) but the per-state summary returns
  field-level extracts (`Resource`, `Next`, `Retry`, `Catch`), not the raw
  ASL JSON blob.
- Execution history events are summarised, not echoed in full.

## 3. What Is NOT Redacted

These values are returned in cleartext by design. Reviewers should assume the
LLM client sees them:

- **AWS ARNs.** ARNs encode the account ID, partition, region, and resource
  name. They are not redacted anywhere.
- **AWS resource names** — Lambda function names, queue names, topic names,
  bucket names, DynamoDB table names, log group names, state-machine names,
  API Gateway route keys, EventBridge rule names.
- **The caller's principal ARN** (returned by `get_aws_identity` /
  `get_aws_auth_status`).
- **The active AWS account ID** and **region**.
- **IAM action strings**, attached managed-policy ARNs, and inline-policy
  names (policy *bodies* are not returned; the *names* are).
- **Tool argument values supplied by the LLM**, when those values are not
  themselves secret-like keys. For example, if the LLM passes `function_name=
  "my-fn"`, that string is logged into the audit JSON and echoed in tool
  output.
- **SNS subscription endpoints** when they are plain email addresses or
  HTTPS URLs (these are visible AWS configuration, but treat them as PII).
- **CloudWatch metric values, alarm thresholds, and time series**.
- **Tags** on AWS resources.

## 4. Audit Log Redaction

The audit logger is [`src/aws_safe_mcp/audit.py`](../../src/aws_safe_mcp/audit.py).

### Mechanism

`AuditLogger.tool(name)` wraps every tool function. It emits three event
types — `tool_call_started`, `tool_call_completed`, and `tool_call_failed` —
as JSON lines to the `aws_safe_mcp.audit` logger. `configure_logging` (called
from `main.py`) routes that logger to stderr.

Arguments are captured by binding the call against the wrapped function's
signature (`inspect.signature(func).bind_partial`), applying defaults, then
passing the bound dictionary through `redact_data(arguments, self._redaction)`
before serialisation.

### What is in each audit line

- `event`: one of `tool_call_started`, `tool_call_completed`,
  `tool_call_failed`.
- `tool`: the registered tool name.
- `arguments`: bound arguments, **redacted** via `redact_data`.
- `duration_ms`: integer milliseconds (null for `started`).
- `error_type`: the exception class name (e.g. `AwsAuthError`) for
  `tool_call_failed`, else null. **Exception messages are not logged.**

The **result of the tool call is NOT logged.** Only arguments, timing, and
error class are recorded.

### Sanitized example

```json
{"arguments": {"function_name": "billing-worker", "since_minutes": 60}, "duration_ms": null, "error_type": null, "event": "tool_call_started", "tool": "investigate_lambda_failure"}
{"arguments": {"function_name": "billing-worker", "since_minutes": 60}, "duration_ms": 412, "error_type": null, "event": "tool_call_completed", "tool": "investigate_lambda_failure"}
```

If a caller had passed `api_token="hunter2"`, the audit line would record
`"api_token": "[REDACTED]"` because the key name matches `SECRET_KEYWORDS`.

### Limitations of the audit stream

- stderr only; no on-disk append-only log, no signing, no rotation contract.
- Argument redaction is keyword-based. A non-secret-shaped key carrying a
  secret value (e.g. `note="my password is hunter2"`) would not be redacted
  in the audit line beyond per-string truncation.

## 5. How Redaction Is Tested

Two test files pin the redaction surface:

- [`tests/test_redaction.py`](../../tests/test_redaction.py) — example-based
  unit tests covering `is_secret_like_key`, `redact_data` on nested mappings,
  `redact_environment`, and string truncation.
- [`tests/test_redaction_properties.py`](../../tests/test_redaction_properties.py)
  — hypothesis property-based tests. The pinned invariants are:

  1. `is_secret_like_key` is case-insensitive.
  2. Any string containing any `SECRET_KEYWORDS` token is classified as
     secret-like, regardless of surrounding characters.
  3. Non-secret string values pass through `redact_value` unchanged.
  4. A value under a key matching any `SECRET_KEYWORDS` token is always
     replaced with `[REDACTED]` by `redact_value`, regardless of payload.
  5. With `redact_environment_values=True`, every environment value is
     `[REDACTED]` and the key set is preserved exactly.
  6. With `redact_environment_values=False`, secret-like keys still have
     their values replaced.
  7. `redact_text` strips `KEY=payload` fragments for any payload composed
     of alphanumerics and safe punctuation, leaving the key and separator in
     place.
  8. `redact_text` is idempotent: redacting an already-redacted string
     returns the same string.
  9. `truncate_string` never exceeds `max_length` characters of the original
     plus a constant `[TRUNCATED]` suffix.
 10. `truncate_string` is idempotent for inputs at or below the limit.
 11. `redact_data` preserves the recursive shape (dict keys, list lengths)
     of arbitrary nested structures and redacts every secret-like-keyed
     value at every nesting depth.

The audit decorator is exercised separately by `tests/test_audit.py`, and
the project-level invariant that every MCP tool is audit-wrapped is enforced
by [`tests/test_invariants.py`](../../tests/test_invariants.py)
(`test_every_mcp_tool_is_audit_wrapped`,
`test_audit_tool_names_are_unique`).

## 6. How To Extend Redaction

When adding a new tool or a new field shape, follow this pattern:

1. **Default to passing the response through `redact_data`** before returning
   it. The recursive walker handles nested AWS shapes correctly and applies
   the configured truncation envelope.
2. **Use `is_secret_like_key(key)` as a guard before parsing env-like values.**
   The Lambda dependency-hint helper is the reference pattern:
   `if is_secret_like_key(key): continue` before any attempt to inspect the
   value (`src/aws_safe_mcp/tools/lambda_tools.py`,
   `_lambda_environment_dependency_hints`).
3. **Use `redact_text` for unstructured strings** (log messages, descriptions,
   user-supplied annotations) so embedded `KEY=value` fragments are stripped
   before truncation.
4. **Do not return raw policy documents.** Summarise to principals, action
   sets, statement counts, or named extracts. See `_trust_policy_summary`
   (IAM), `_policy_summary` (SNS/SQS), and `_kms_service_principal_check`
   (KMS) as reference patterns.
5. **To add a new global keyword** (e.g. `BEARER`), extend `SECRET_KEYWORDS`
   in `src/aws_safe_mcp/redaction.py` and add a property test in
   `tests/test_redaction_properties.py`. The hypothesis suite parametrises
   over `SECRET_KEYWORDS` directly, so coverage is automatic for the
   primitive functions.
6. **Bound everything.** Tool inputs that drive pagination, time windows, or
   result counts must enforce a maximum. `RedactionConfig.max_string_length`,
   `AwsSafeConfig.max_since_minutes`, and `AwsSafeConfig.max_results` are
   the canonical bounds.

Any new tool added without these guards must be flagged in code review; the
project's `CONTRIBUTING.md` checklist explicitly requires "Tool outputs are
concise, bounded, and redacted."
