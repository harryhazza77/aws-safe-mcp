# Release Checklist

This project is intended to be safe to run locally with existing AWS
credentials. Release checks should preserve that model: no secrets, no bundled
local config, no write-capable AWS tools, and no raw SDK passthrough.

## For Coding Agents

Before recommending, tagging, publishing, or otherwise preparing a release,
agents should treat this document as the release runbook. Do not rely only on
the test suite or recent green CI.

Agent release workflow:

- Confirm the working tree is clean or that every pending change is intentional.
- Run the repository publishing checks below, including secret and local-detail
  searches.
- Run every command in the required verification suite.
- Run or explicitly defer the live MCP smoke checks in a non-production AWS
  account. Use the "Live MCP End-To-End Smoke" section below when credentials
  are available.
- Inspect package contents before any PyPI publish step.
- Report each command result, any skipped check, and the reason for any skipped
  live AWS check before saying the release is ready.

If any check fails, fix the issue or clearly report the blocker. Do not publish
or advise publishing from a dirty tree, with failed verification, or with
unreviewed local account details in docs or examples.

## Before Publishing The Repository

- Confirm the working tree only contains intended source, docs, tests, and
  packaging changes.
- Search for local account IDs, profile names, usernames, private paths, and
  organization-specific names.
- Search for credentials, private keys, `.env` files, tokens, and secret values.
- Confirm examples use fake account IDs and generic profile names.
- Confirm build artifacts and local caches are ignored.
- Confirm `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and this
  release checklist are present.

Useful local checks:

```bash
git status --short
rg -n "(AKIA|ASIA|aws_secret_access_key|aws_access_key_id|BEGIN .*PRIVATE KEY|PRIVATE KEY)" .
rg -n "(account-id|your-account-id|123456789012|profile dev)" README.md docs examples
```

The second command should return no real secrets. The third command should only
show generic examples.

## Required Verification

Run the full local suite:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run bandit -q -r src
uv run pip-audit
uv run pytest --cov=aws_safe_mcp --cov-report=term-missing
uv run aws-safe-mcp --help
uv build
uvx --from . aws-safe-mcp --help
```

Expected result:

- Ruff formatting check passes.
- Ruff lint passes.
- Mypy passes.
- Bandit reports no source security issues.
- Pip-audit reports no known dependency vulnerabilities.
- Pytest passes and coverage is reported.
- CLI help renders.
- Source distribution and wheel build successfully.
- Local `uvx --from .` execution works.

## Live MCP End-To-End Smoke

Run this check when a non-production AWS profile is available. Keep real profile
names, account IDs, ARNs, resource names, and local config paths out of tracked
docs, examples, commits, and issue comments.

Agents may read `.codex.local.md` for local private smoke-test settings when it
exists. That file is ignored by Git and must never be committed, quoted with
real values, or copied into public release notes.

Use placeholders in notes intended for Git:

- `SMOKE_PROFILE` for the AWS profile.
- `SMOKE_REGION` for the AWS region.
- `SMOKE_ACCOUNT_ID` for the allowlisted AWS account.
- `SMOKE_CONFIG` for a temporary config path outside the repository, such as
  `/private/tmp/aws-safe-mcp-smoke.yaml`.

1. Confirm the AWS CLI can resolve the target identity:

```bash
aws configure list-profiles
aws sts get-caller-identity --profile "$SMOKE_PROFILE" --region "$SMOKE_REGION"
```

2. Create a temporary config outside the repository:

```yaml
allowed_account_ids:
  - "SMOKE_ACCOUNT_ID"

readonly: true

redaction:
  redact_environment_values: true
  redact_secret_like_keys: true
  max_string_length: 2000
```

3. Start the MCP server through stdio and call read-only tools with small limits:

```bash
uv run python - <<'PY'
import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    env = dict(os.environ)
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "aws_safe_mcp.main",
            "--config",
            os.environ["SMOKE_CONFIG"],
            "--profile",
            os.environ["SMOKE_PROFILE"],
            "--region",
            os.environ["SMOKE_REGION"],
            "--readonly",
        ],
        env=env,
    )

    calls = [
        ("get_aws_auth_status", {}),
        ("get_aws_identity", {}),
        ("search_aws_resources", {"query": "test", "max_results": 5}),
        ("list_lambda_functions", {"max_results": 5}),
        ("list_step_functions", {"max_results": 5}),
        ("list_cloudwatch_log_groups", {"max_results": 5}),
        ("list_dynamodb_tables", {"max_results": 5}),
        ("list_api_gateways", {"max_results": 5}),
        ("list_eventbridge_rules", {"max_results": 5}),
    ]

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(f"tools: {len(tools.tools)}")
            for name, arguments in calls:
                result = await session.call_tool(name, arguments)
                print(name, result.structuredContent)


asyncio.run(main())
PY
```

4. Use discovered non-production resources for deeper metadata checks:

- `get_lambda_summary` for one known or discovered Lambda.
- `get_lambda_recent_errors` for that Lambda with `since_minutes: 60` and
  `max_events: 10`.
- `get_dynamodb_table_summary` for one discovered table.
- `get_api_gateway_summary` for one discovered API.
- `explain_eventbridge_rule_dependencies` for one discovered rule with
  permission checks enabled.

Expected result:

- The server initializes over stdio.
- `get_aws_auth_status` reports `authenticated: true`.
- `get_aws_identity` returns the same account as `aws sts get-caller-identity`.
- Tool listing includes the registered AWS tools.
- Read-only list/search calls complete with bounded results or clear
  permission warnings.
- Deeper metadata calls do not expose secret values or raw payload bodies.
- Permission checks return `allowed`, `denied`, or `unknown` with warnings,
  never raw policies or credentials.

After the smoke test, delete the temporary config file. Summaries may mention
counts and check names, but should not include real profile names, account IDs,
ARNs, resource names, or log content in public release notes.

## First GitHub Publish

Before pushing publicly:

- Create the repository.
- Confirm `pyproject.toml` `project.urls` point to the final repository URL.
- Confirm GitHub Actions CI is present at `.github/workflows/ci.yml`.
- Push `main`.
- Confirm the CI workflow passes on GitHub.
- Review the public README rendering.
- Review the GitHub Security policy page.
- Add PyPI version and Python-version badges to `README.md` after the first
  package publish, when the badge target exists.

## PyPI Release

Before publishing to PyPI:

- Decide the release version.
- Update `version` in `pyproject.toml`.
- Update `CHANGELOG.md`.
- Run the required verification checks again.
- Inspect the package contents:

```bash
tar -tzf dist/aws_safe_mcp-*.tar.gz
unzip -l dist/aws_safe_mcp-*.whl
```

- Merge the release-prep PR.
- Tag the exact release commit and create a GitHub Release named `vX.Y.Z`.
- Publish through `.github/workflows/publish.yml` using the `pypi` environment
  and PyPI trusted publishing.

The publish workflow verifies that the GitHub Release tag matches the package
version in `pyproject.toml`, reruns the local verification suite, builds and
inspects the package contents, publishes through PyPI trusted publishing, and
runs a post-publish `uvx` CLI check.

Manual fallback:

```bash
uv publish \
  --token 'pypi-...' \
  dist/aws_safe_mcp-X.Y.Z.tar.gz \
  dist/aws_safe_mcp-X.Y.Z-py3-none-any.whl
```

Only use manual publishing when the trusted publisher workflow is unavailable,
and only upload the artifacts for the intended version.

After publishing:

```bash
uvx aws-safe-mcp --help
```

Then test with a local config:

```bash
uvx aws-safe-mcp \
  --profile dev \
  --region eu-west-2 \
  --readonly \
  --config ~/.config/aws-safe-mcp/config.yaml
```

## Never Publish

- `.env` files.
- AWS credentials or config files.
- Local MCP client configs containing real account IDs or profile names.
- Audit logs.
- CloudWatch log exports.
- S3 object contents.
- Real Lambda environment values.
- Private customer, employer, or account-specific examples.

## Release Safety Review

Before tagging a release, confirm:

- No write-capable AWS tool was added.
- No generic AWS SDK passthrough was added.
- Missing or expired AWS credentials do not prevent server startup.
- AWS account allowlisting is still enforced before resource access.
- Tool responses are bounded, concise, and redacted.
- Tests cover new tools, redaction behavior, and pagination limits.
