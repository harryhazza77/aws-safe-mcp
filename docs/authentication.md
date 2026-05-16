# Authentication

How `aws-safe-mcp` resolves AWS credentials and what to do when auth breaks.

## How auth works

`aws-safe-mcp` uses boto3 default credential resolution. It does not bundle
its own credential store. On every tool call, the server resolves a boto3
session from the configured `--profile` (or environment if no profile is set),
calls `sts:GetCallerIdentity`, and checks the returned account ID against the
configured `allowed_account_ids`. If the identity check fails, the tool
returns a user-actionable auth error and the server stays running so a
subsequent call can re-validate without restart. See
`src/aws_safe_mcp/auth.py` (`AwsRuntime.refresh_identity` /
`require_identity`) and the runtime flow described in
[architecture.md](architecture.md#runtime-flow).

## AWS CLI profile setup

`aws-safe-mcp` reads from `~/.aws/config` and `~/.aws/credentials` the same way
the AWS CLI does. Two common shapes:

SSO profile in `~/.aws/config`:

```ini
[profile dev]
sso_session = my-sso
sso_account_id = 123456789012
sso_role_name = DeveloperReadOnly
region = eu-west-2
output = json

[sso-session my-sso]
sso_start_url = https://my-org.awsapps.com/start
sso_region = eu-west-2
sso_registration_scopes = sso:account:access
```

Access-key profile in `~/.aws/credentials`:

```ini
[dev]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

For the full guide, see the AWS docs on
[named profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).

## SSO login flow

Log in:

```bash
aws sso login --profile dev
```

When the SSO session expires, the next tool call will fail with an auth error
referencing missing credentials. Re-run the same command — no MCP restart
needed. `aws-safe-mcp` re-validates STS on the next tool call, picks up the
refreshed session, and resumes normally. This is the behaviour documented in
[architecture.md](architecture.md#runtime-flow) ("the server can start when
credentials are missing or expired").

## Environment-variable auth

boto3 honours the standard environment variables; useful for ephemeral test
accounts, CI runners, or short-lived assumed-role credentials:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN` (required for assumed-role / SSO-derived credentials)
- `AWS_REGION` or `AWS_DEFAULT_REGION` (overridden by `--region`)

When these are set and no `--profile` is passed, boto3 uses them directly.

## Instance / container metadata

If the process runs on EC2, ECS, EKS, CodeBuild, or another AWS compute
service with an attached role, boto3 picks up credentials from the instance or
container metadata endpoint automatically. The role's account must appear in
`allowed_account_ids`; otherwise the account allowlist check fails.

## Allowed accounts

The mandatory account allowlist lives in your config file (default path by
convention: `~/.config/aws-safe-mcp/config.yaml`; the actual path is whatever
you pass to `--config`). The field is `allowed_account_ids` and must contain
12-digit account IDs as quoted strings. Example:

```yaml
allowed_account_ids:
  - "123456789012"
  - "234567890123"
readonly: true
```

The config also accepts `readonly`, `redaction`, `max_since_minutes`,
`max_results`, `endpoint_url`, and `service_endpoint_urls`. See
`src/aws_safe_mcp/config.py` for the validated schema. `readonly` must be
`true` in v1; the server refuses to start otherwise.

## Verifying auth

Ask the AI client:

```text
Check my AWS auth status.
```

Expected output shape:

```json
{
  "authenticated": true,
  "account": "123456789012",
  "arn": "arn:aws:sts::123456789012:assumed-role/DeveloperReadOnly/<session>",
  "user_id": "AROAEXAMPLE:<session>",
  "profile": "dev",
  "region": "eu-west-2",
  "readonly": true
}
```

If `authenticated` is `false`, the response includes a concise message such as
"No AWS credentials were found" or "AWS account ... is not allowed by config".

## Reconnecting after re-login

Do not restart the MCP server after running `aws sso login` or rotating
credentials. The next AWS tool call rebuilds the boto3 session and re-validates
STS automatically — this is the documented behaviour of
`AwsRuntime.refresh_identity` in `src/aws_safe_mcp/auth.py`. Just ask the
client to run any tool, for example `Check my AWS auth status.`

## Common failure modes

Full list in [troubleshooting.md](troubleshooting.md). The three most common:

- `authenticated: false` immediately after `aws sso login` — call the tool
  again; the server re-checks STS lazily. If it still fails, run
  `aws sts get-caller-identity --profile <name>` to confirm the SSO browser
  flow actually completed.
- `account <id> is not in the allowed list` — add the 12-digit account ID to
  `allowed_account_ids` in your config. No restart needed.
- `profile <name> not found` — `--profile` does not match any section in
  `~/.aws/config` or `~/.aws/credentials`. Run `aws configure list-profiles`
  to confirm, then `aws configure sso --profile <name>` (or set up a static
  profile) to create it.
