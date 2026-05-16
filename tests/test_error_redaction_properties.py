"""Property-based tests pinning ``normalize_aws_error`` redaction.

User-facing error messages are a known exfiltration path: an AWS SDK
exception body can echo back access keys, session tokens, ARNs, or
secret env-var values that the caller never asked to see. These
hypothesis-driven properties fuzz adversarial substrings into the
``ClientError`` body and assert ``normalize_aws_error`` either redacts
or bounds them before the message reaches the MCP client.

If an assertion here fails, the redaction layer in
``aws_safe_mcp.errors._safe_error_message`` is missing a pattern. The
right fix is to harden that helper (or, if a particular pattern is
explicitly out of scope, mark the corresponding test ``xfail`` with a
rationale linking the decision).
"""

from __future__ import annotations

import string

from botocore.exceptions import ClientError
from hypothesis import given, settings
from hypothesis import strategies as st

from aws_safe_mcp.errors import normalize_aws_error


def _client_error(message: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": "ValidationException", "Message": message}},
        "SomeOperation",
    )


# ---------------------------------------------------------------------------
# AKIA-prefixed access keys
# ---------------------------------------------------------------------------


@settings(max_examples=50)
@given(
    st.text(
        alphabet=string.ascii_uppercase + string.digits,
        min_size=16,
        max_size=16,
    )
)
def test_normalize_aws_error_strips_aws_access_key_id_prefix(suffix: str) -> None:
    access_key = f"AKIA{suffix}"
    message = f"request denied for principal {access_key} (see logs)"
    rendered = str(normalize_aws_error(_client_error(message)))

    assert access_key not in rendered, "AWS access key id leaked into normalised error message"


# ---------------------------------------------------------------------------
# Secret-access-key-shaped substrings (40 base64-ish chars)
# ---------------------------------------------------------------------------


@settings(max_examples=50)
@given(
    st.text(
        alphabet=string.ascii_letters + string.digits + "+/",
        min_size=40,
        max_size=40,
    )
)
def test_normalize_aws_error_strips_aws_secret_access_key_shape(secret: str) -> None:
    message = f"upstream rejected request with secret {secret} attached"
    rendered = str(normalize_aws_error(_client_error(message)))

    assert secret not in rendered, (
        "40-char secret-access-key-shaped substring leaked into normalised error message"
    )


# ---------------------------------------------------------------------------
# Session-token-shaped substrings (long base64 blobs)
# ---------------------------------------------------------------------------


@settings(max_examples=50)
@given(
    st.text(
        alphabet=string.ascii_letters + string.digits + "+/=",
        min_size=200,
        max_size=400,
    )
)
def test_normalize_aws_error_strips_session_token_shape(token: str) -> None:
    message = f"sts session_token={token} could not be refreshed"
    rendered = str(normalize_aws_error(_client_error(message)))

    # Either the token must be redacted by keyword match, or the whole
    # message must be truncated below the bounded envelope. A literal
    # 200+ char base64 blob surviving intact is a leak.
    assert token not in rendered, (
        "session-token-shaped substring leaked into normalised error message"
    )


# ---------------------------------------------------------------------------
# Long-message truncation
# ---------------------------------------------------------------------------


@settings(max_examples=25)
@given(
    st.text(
        alphabet=string.ascii_letters + string.digits + " .,:-",
        min_size=600,
        max_size=2000,
    )
)
def test_normalize_aws_error_truncates_long_messages(message: str) -> None:
    rendered = str(normalize_aws_error(_client_error(message)))

    # The prefix ("AWS ValidationException: ") + bounded body + truncation
    # marker must keep the rendered message bounded. The redaction layer
    # caps the message body at 500 chars with a small constant overhead
    # for the truncation tag.
    assert len(rendered) < len(message), (
        f"long error message was not truncated (len={len(rendered)} vs input len={len(message)})"
    )
    assert len(rendered) < 1000, (
        f"rendered error message exceeded bounded envelope (len={len(rendered)})"
    )


# ---------------------------------------------------------------------------
# KEY=value / TOKEN=value / PASSWORD=value style leaks
# ---------------------------------------------------------------------------


@settings(max_examples=50)
@given(
    st.sampled_from(["KEY", "TOKEN", "PASSWORD", "SECRET", "CREDENTIAL"]),
    st.sampled_from(["=", ":", "= ", ": "]),
    st.text(
        alphabet=string.ascii_letters + string.digits + ".-_/",
        min_size=8,
        max_size=64,
    ),
)
def test_normalize_aws_error_strips_secret_keywords(
    keyword: str, separator: str, value: str
) -> None:
    message = f"upstream returned MY_{keyword}{separator}{value} in metadata"
    rendered = str(normalize_aws_error(_client_error(message)))

    assert value not in rendered, (
        f"value after {keyword}{separator!r} leaked into normalised error message: {rendered!r}"
    )
    assert "[REDACTED]" in rendered, (
        f"expected [REDACTED] marker after secret keyword in normalised error message: {rendered!r}"
    )
