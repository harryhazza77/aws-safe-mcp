from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ProfileNotFound

from aws_safe_mcp.main import build_parser, main


class FakeServer:
    def __init__(self) -> None:
        self.transport: str | None = None

    def run(self, transport: str) -> None:
        self.transport = transport


def test_parser_reads_region_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "eu-west-2")
    parser = build_parser()

    args = parser.parse_args(["--config", "config.yaml", "--readonly"])

    assert args.region == "eu-west-2"


def test_main_requires_readonly(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        """
allowed_account_ids:
  - "123456789012"
readonly: true
""",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config), "--region", "eu-west-2"])

    assert exc.value.code == 2


def test_main_requires_config() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--region", "eu-west-2", "--readonly"])

    assert exc.value.code == 2


def test_main_requires_region(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    config = tmp_path / "config.yaml"
    config.write_text(
        """
allowed_account_ids:
  - "123456789012"
readonly: true
""",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config), "--readonly"])

    assert exc.value.code == 2


def test_main_returns_error_for_invalid_config(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        """
allowed_account_ids:
  - "123456789012"
readonly: false
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--config",
            str(config),
            "--region",
            "eu-west-2",
            "--readonly",
        ]
    )

    assert exit_code == 2
    assert "readonly must be true" in capsys.readouterr().err


def test_main_starts_server_when_aws_auth_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aws_safe_mcp.auth as auth
    import aws_safe_mcp.main as main_module

    config = tmp_path / "config.yaml"
    config.write_text(
        """
allowed_account_ids:
  - "123456789012"
readonly: true
""",
        encoding="utf-8",
    )
    server = FakeServer()

    def raise_profile_not_found(*_: Any, **__: Any) -> None:
        raise ProfileNotFound(profile="missing")

    monkeypatch.setattr(auth.boto3, "Session", raise_profile_not_found)
    monkeypatch.setattr(main_module, "create_server", lambda _: server)

    exit_code = main(
        [
            "--config",
            str(config),
            "--profile",
            "missing",
            "--region",
            "eu-west-2",
            "--readonly",
        ]
    )

    assert exit_code == 0
    assert server.transport == "stdio"
