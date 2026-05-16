# Troubleshooting

First-error survival guide. One heading per failure: symptom, why, fix.

## `authenticated: false` after `aws sso login`

**Symptom:** `get_aws_auth_status` returns `{"authenticated": false}` even
though you just ran `aws sso login --profile dev`.

**Why:** The MCP server checks STS lazily on each call. It does not poll, and
it does not need to be restarted when your local credentials refresh.

**Fix:** Call the tool again. Ask the client:

```text
Check my AWS auth status.
```

If it still reports `false`, run `aws sts get-caller-identity --profile dev`
directly. If that also fails, the SSO session has not actually been
established — re-run `aws sso login --profile <name>` and check that the
browser flow completed.

## `account <id> is not in the allowed list`

**Symptom:** A tool call returns an error mentioning that the AWS account is
not allowlisted.

**Why:** Every AWS-touching tool resolves the active account via
`sts:GetCallerIdentity` and refuses to continue unless that account ID appears
in `allowed_account_ids` in your config.

**Fix:** Edit `~/.config/aws-safe-mcp/config.yaml` and add the account ID
exactly as STS returned it (12 digits, quoted as a string):

```yaml
allowed_account_ids:
  - "123456789012"
  - "234567890123"
```

You do not need to restart the server — the config is read on each call.

## `profile <name> not found`

**Symptom:** Startup or tool call fails with a botocore "profile not found"
error.

**Why:** The `--profile` value does not match any section in `~/.aws/config`
or `~/.aws/credentials`.

**Fix:** List your configured profiles:

```bash
aws configure list-profiles
```

If your profile is missing, configure it. For SSO:

```bash
aws configure sso --profile dev
```

For static credentials, see the AWS docs on
[named profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).

## `access denied` on a tool call

**Symptom:** A tool returns an `AccessDeniedException` or similar from AWS.

**Why:** Your IAM principal is missing the read action the tool needs. The
server does not have an escape hatch — it calls AWS as you.

**Fix:** Grant the required read actions to your principal. Common per-tool
mappings live in [iam-per-tool.md](iam-per-tool.md). For the baseline set, see
the Permissions section of the [project README](../README.md).

## Tool returns `unknown` verdict on a permission check

**Symptom:** A permission-checking tool (for example
`check_lambda_permission_path`) returns `verdict: unknown` with a warning
rather than `allowed` or `denied`.

**Why:** `unknown` is not a deny. It means IAM simulation could not run,
typically because your caller principal does not have
`iam:SimulatePrincipalPolicy` on the target role.

**Fix:** Either grant `iam:SimulatePrincipalPolicy` to your investigation
principal, or treat the warning as a known gap and verify the path another
way. The tool will still return any other useful evidence it collected.

## Empty results from a `list_*` tool

**Symptom:** `list_lambda_functions`, `list_s3_buckets`, etc. returns an empty
array even though you expect resources to exist.

**Why:** One of:

1. The MCP server is pointed at a different region than the one the resources
   live in.
2. A `name_prefix` or other filter is too narrow.
3. The principal genuinely cannot see them (IAM scoping).

**Fix:** Check the active region:

```text
What AWS identity am I using right now?
```

Then retry without filters, or with `--region` set on the server command line
to match the resource region.

## MCP client does not see the server

**Symptom:** The client lists no `aws-safe-mcp` tools, or shows the server in
a "failed" state.

**Why:** The client config is missing, malformed, or the client was not
restarted after a config change.

**Fix:** Follow the setup page for your client:

- [Claude Code](claude-code.md): use `/mcp` to inspect status and reconnect.
- [Claude Desktop](claude-desktop.md): restart the app after editing the JSON
  config.
- [Cursor](cursor.md): restart Cursor after adding the stdio entry.

Confirm the `command` and `args` in your client config match the form in those
pages, and that the `--config` path actually exists.

## What command should I run to confirm everything works?

See [quickstart.md](quickstart.md) Step 4. The single prompt
`Check my AWS auth status.` exercises config loading, profile resolution, STS,
and the MCP transport.

## Still stuck?

Open an issue at
[https://github.com/harryhazza77/aws-safe-mcp/issues](https://github.com/harryhazza77/aws-safe-mcp/issues).
Include:

- The exact tool name and prompt you used.
- The redacted output (no account IDs, ARNs, or resource names).
- Your AI client and version.
- Your `aws-safe-mcp` version (`uvx aws-safe-mcp --help` prints it).
