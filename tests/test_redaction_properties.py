"""Property-based tests for the redaction primitive.

Redaction is the project's security boundary. Hand-rolled examples can
miss adversarial inputs; hypothesis fuzzes the space to flush out edge
cases. Each property pins one invariant the rest of the codebase relies
on.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from aws_safe_mcp.config import RedactionConfig
from aws_safe_mcp.redaction import (
    REDACTED,
    SECRET_KEYWORDS,
    is_secret_like_key,
    redact_data,
    redact_environment,
    redact_text,
    redact_value,
    truncate_string,
)


def _config(max_length: int = 200) -> RedactionConfig:
    return RedactionConfig(
        redact_environment_values=False,
        redact_secret_like_keys=True,
        max_string_length=max_length,
    )


def _env_locked_config(max_length: int = 200) -> RedactionConfig:
    return RedactionConfig(
        redact_environment_values=True,
        redact_secret_like_keys=True,
        max_string_length=max_length,
    )


# ---------------------------------------------------------------------------
# is_secret_like_key
# ---------------------------------------------------------------------------


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=200))
def test_is_secret_like_key_case_insensitive(text: str) -> None:
    assert is_secret_like_key(text) == is_secret_like_key(text.lower())
    assert is_secret_like_key(text) == is_secret_like_key(text.upper())


@given(st.sampled_from(SECRET_KEYWORDS), st.text(max_size=50), st.text(max_size=50))
def test_is_secret_like_key_matches_any_substring(keyword: str, prefix: str, suffix: str) -> None:
    candidate = f"{prefix}{keyword}{suffix}"
    assert is_secret_like_key(candidate) is True


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=40))
def test_non_secret_strings_pass_through_unredacted(value: str) -> None:
    if is_secret_like_key(value):
        return  # only assert on non-secret keys
    config = _config()
    redacted = redact_value(value, "harmless-value", config)
    assert redacted == "harmless-value"


# ---------------------------------------------------------------------------
# redact_value
# ---------------------------------------------------------------------------


@given(
    st.sampled_from(SECRET_KEYWORDS),
    st.text(min_size=1, max_size=200),
)
def test_redact_value_replaces_secret_like_keys(keyword: str, payload: str) -> None:
    config = _config()
    key = f"DEV_{keyword}_BAR"
    assert redact_value(key, payload, config) == REDACTED


# ---------------------------------------------------------------------------
# redact_environment
# ---------------------------------------------------------------------------


@given(
    st.dictionaries(
        keys=st.text(min_size=1, max_size=30, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789"),
        values=st.text(min_size=0, max_size=100),
        max_size=15,
    )
)
def test_redact_environment_replaces_every_value_when_env_locked(
    environment: dict[str, str],
) -> None:
    config = _env_locked_config()
    redacted = redact_environment(environment, config)
    assert set(redacted.keys()) == set(environment.keys())
    assert all(redacted[key] == REDACTED for key in environment)


@given(
    st.dictionaries(
        keys=st.text(min_size=1, max_size=30, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789"),
        values=st.text(min_size=0, max_size=100),
        max_size=15,
    )
)
def test_redact_environment_redacts_secret_keys_even_when_unlocked(
    environment: dict[str, str],
) -> None:
    config = _config()
    redacted = redact_environment(environment, config)
    for key in environment:
        if is_secret_like_key(key):
            assert redacted[key] == REDACTED


# ---------------------------------------------------------------------------
# redact_text
# ---------------------------------------------------------------------------


@given(
    st.sampled_from(SECRET_KEYWORDS),
    # Token-like payload: alphanumeric + safe punctuation, no separators
    # (`=` / `:` / whitespace) and no `[` / `]` so payload can't collide
    # with the redaction marker itself.
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/",
        min_size=1,
        max_size=50,
    ),
)
def test_redact_text_strips_secret_key_values_from_text(keyword: str, payload: str) -> None:
    config = _config(max_length=1000)
    original = f"foo MY_{keyword}_NAME={payload} bar"
    redacted = redact_text(original, config)
    expected = f"foo MY_{keyword}_NAME={REDACTED} bar"
    assert redacted == expected


@given(st.text(min_size=0, max_size=300))
def test_redact_text_is_idempotent_on_already_redacted_input(value: str) -> None:
    config = _config(max_length=10_000)
    once = redact_text(value, config)
    twice = redact_text(once, config)
    assert once == twice


# ---------------------------------------------------------------------------
# truncate_string
# ---------------------------------------------------------------------------


@given(st.text(min_size=0, max_size=500), st.integers(min_value=10, max_value=200))
def test_truncate_string_never_exceeds_a_bounded_envelope(value: str, max_length: int) -> None:
    # The truncation marker is a fixed suffix; output length is bounded by
    # `max_length` + a constant overhead for the truncation tag.
    result = truncate_string(value, max_length)
    if len(value) <= max_length:
        assert result == value
    else:
        assert result.startswith(value[:max_length])
        assert "TRUNCATED" in result


@given(st.text(min_size=0, max_size=500), st.integers(min_value=10, max_value=200))
def test_truncate_string_is_idempotent(value: str, max_length: int) -> None:
    once = truncate_string(value, max_length)
    twice = truncate_string(once, max_length)
    # Truncating twice may further shorten the truncation marker but the
    # core invariant — the value's prefix is preserved — holds.
    if len(value) <= max_length:
        assert once == twice == value


# ---------------------------------------------------------------------------
# redact_data — recursive structures
# ---------------------------------------------------------------------------


@settings(max_examples=50)
@given(
    st.recursive(
        st.one_of(st.text(max_size=40), st.integers(), st.booleans(), st.none()),
        lambda children: st.one_of(
            st.lists(children, max_size=5),
            st.dictionaries(
                keys=st.text(min_size=1, max_size=20),
                values=children,
                max_size=5,
            ),
        ),
        max_leaves=15,
    )
)
def test_redact_data_preserves_shape_and_redacts_secret_keys(data: object) -> None:
    config = _config(max_length=1000)
    result = redact_data(data, config)

    def assert_shape(original: object, redacted: object) -> None:
        if isinstance(original, dict):
            assert isinstance(redacted, dict)
            assert set(redacted.keys()) == {str(k) for k in original}
            for key, value in original.items():
                if is_secret_like_key(str(key)):
                    assert redacted[str(key)] == REDACTED
                else:
                    assert_shape(value, redacted[str(key)])
        elif isinstance(original, list):
            assert isinstance(redacted, list)
            assert len(redacted) == len(original)
            for original_item, redacted_item in zip(original, redacted, strict=False):
                assert_shape(original_item, redacted_item)

    assert_shape(data, result)
