from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


class ConfigError(ValueError):
    """Raised when server configuration is missing, invalid, or unsafe."""


class RedactionConfig(BaseModel):
    """Controls recursive response redaction and string truncation."""

    model_config = ConfigDict(extra="forbid")

    redact_environment_values: bool = True
    redact_secret_like_keys: bool = True
    max_string_length: int = Field(default=2000, ge=100, le=10000)


class AwsSafeConfig(BaseModel):
    """Validated fail-closed server configuration.

    AWS IAM controls resource access. The mandatory account allowlist exists to
    stop accidental wrong-account use before any resource-level AWS calls run.
    """

    model_config = ConfigDict(extra="forbid")

    allowed_account_ids: list[str] = Field(min_length=1)
    readonly: bool = True
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    max_since_minutes: int = Field(default=1440, ge=1, le=10080)
    max_results: int = Field(default=100, ge=1, le=1000)

    @field_validator("allowed_account_ids")
    @classmethod
    def account_ids_must_be_12_digits(cls, values: list[str]) -> list[str]:
        for value in values:
            if len(value) != 12 or not value.isdigit():
                raise ValueError(f"Invalid AWS account ID {value!r}; expected 12 digits")
        return values

    @model_validator(mode="after")
    def readonly_must_be_enabled(self) -> AwsSafeConfig:
        if not self.readonly:
            raise ValueError("readonly must be true in v1")
        return self

    def require_account_allowed(self, account_id: str) -> str:
        if account_id not in self.allowed_account_ids:
            raise ConfigError(f"AWS account {account_id!r} is not allowed by config")
        return account_id


def load_config(path: str | Path) -> AwsSafeConfig:
    """Load a YAML or JSON config file and reject unknown or unsafe fields."""

    config_path = Path(path).expanduser()
    if not config_path.exists():
        raise ConfigError(f"Config file does not exist: {config_path}")
    if not config_path.is_file():
        raise ConfigError(f"Config path is not a file: {config_path}")

    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Unable to read config file {config_path}: {exc}") from exc

    try:
        data = _parse_config(raw_text, config_path.suffix.lower())
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"Unable to parse config file {config_path}: {exc}") from exc

    try:
        return AwsSafeConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid config file {config_path}: {exc}") from exc


def _parse_config(raw_text: str, suffix: str) -> dict[str, Any]:
    data = json.loads(raw_text) if suffix == ".json" else yaml.safe_load(raw_text)
    if not isinstance(data, dict):
        raise ConfigError("Config file must contain a YAML or JSON object")
    return data
