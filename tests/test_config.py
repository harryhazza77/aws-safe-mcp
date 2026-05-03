from __future__ import annotations

from pathlib import Path

import pytest

from aws_safe_mcp.config import ConfigError, load_config


def write_config(path: Path, extra: str = "") -> Path:
    path.write_text(
        f"""
allowed_account_ids:
  - "123456789012"
readonly: true
{extra}
""",
        encoding="utf-8",
    )
    return path


def test_load_config_accepts_minimal_safe_yaml(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path / "config.yaml"))

    assert config.require_account_allowed("123456789012") == "123456789012"


def test_load_config_fails_closed_when_missing(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(tmp_path / "missing.yaml")


def test_load_config_rejects_write_mode(tmp_path: Path) -> None:
    path = write_config(tmp_path / "config.yaml")
    path.write_text(path.read_text(encoding="utf-8").replace("readonly: true", "readonly: false"))

    with pytest.raises(ConfigError, match="readonly must be true"):
        load_config(path)


def test_load_config_rejects_bad_account_id(tmp_path: Path) -> None:
    path = write_config(tmp_path / "config.yaml")
    path.write_text(path.read_text(encoding="utf-8").replace('"123456789012"', '"abc"'))

    with pytest.raises(ConfigError, match="expected 12 digits"):
        load_config(path)
