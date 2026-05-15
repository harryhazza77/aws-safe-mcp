from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from aws_safe_mcp.auth import AwsAuthError, AwsIdentity, AwsRuntime
from aws_safe_mcp.config import AwsSafeConfig
from aws_safe_mcp.tools.identity import aws_auth_status, aws_identity


class FakeStsClient:
    def get_caller_identity(self) -> dict[str, str]:
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/dev-role/session",
            "UserId": "AROATEST:session",
        }


class FakeSession:
    def __init__(self, profile_name: str | None = None, region_name: str | None = None) -> None:
        self.profile_name = profile_name
        self.region_name = region_name

    def client(self, service_name: str, **_: Any) -> FakeStsClient:
        assert service_name == "sts"
        return FakeStsClient()


class RecordingClient:
    def __init__(self, service_name: str) -> None:
        self.service_name = service_name

    def get_caller_identity(self) -> dict[str, str]:
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/dev-role/session",
            "UserId": "AROATEST:session",
        }


class RecordingSession:
    client_calls: list[dict[str, Any]] = []

    def __init__(self, profile_name: str | None = None, region_name: str | None = None) -> None:
        self.profile_name = profile_name
        self.region_name = region_name

    def client(self, service_name: str, **kwargs: Any) -> RecordingClient:
        type(self).client_calls.append({"service_name": service_name, **kwargs})
        return RecordingClient(service_name)


class CountingSession:
    calls = 0
    fail_after = 1

    def __init__(self, profile_name: str | None = None, region_name: str | None = None) -> None:
        self.profile_name = profile_name
        self.region_name = region_name

    def client(self, service_name: str, **_: Any) -> Any:
        assert service_name == "sts"
        type(self).calls += 1
        if type(self).calls > type(self).fail_after:
            return NoCredentialsStsClient()
        return FakeStsClient()


class StaticIdentity:
    def __init__(self, arn: str) -> None:
        self.account = "123456789012"
        self.arn = arn
        self.user_id = "USERID"
        self.profile = None
        self.region = "eu-west-2"
        self.readonly = True


class StaticRuntime:
    def __init__(self, arn: str) -> None:
        self.identity = StaticIdentity(arn)
        self.config = AwsSafeConfig(allowed_account_ids=["123456789012"])
        self.profile = None
        self.region = "eu-west-2"
        self.auth_error = None

    def refresh_identity(self) -> StaticIdentity:
        return self.identity

    def require_identity(self) -> StaticIdentity:
        return self.identity


def test_aws_identity_reports_validated_session(monkeypatch: pytest.MonkeyPatch) -> None:
    import aws_safe_mcp.auth as auth

    monkeypatch.setattr(auth.boto3, "Session", FakeSession)
    runtime = AwsRuntime(
        config=AwsSafeConfig(
            allowed_account_ids=["123456789012"],
        ),
        profile="dev",
        region="eu-west-2",
    )

    assert aws_identity(runtime) == {
        "account": "123456789012",
        "arn": "arn:aws:sts::123456789012:assumed-role/dev-role/session",
        "user_id": "AROATEST:session",
        "profile": "dev",
        "region": "eu-west-2",
        "readonly": True,
    }


def test_runtime_uses_configured_global_endpoint_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aws_safe_mcp.auth as auth

    RecordingSession.client_calls = []
    monkeypatch.setattr(auth.boto3, "Session", RecordingSession)
    runtime = AwsRuntime(
        config=AwsSafeConfig(
            allowed_account_ids=["123456789012"],
            endpoint_url="http://127.0.0.1:4566",
        ),
        profile=None,
        region="eu-west-2",
    )

    runtime.client("s3")

    assert [call["service_name"] for call in RecordingSession.client_calls] == ["sts", "sts", "s3"]
    assert [call["endpoint_url"] for call in RecordingSession.client_calls] == [
        "http://127.0.0.1:4566",
        "http://127.0.0.1:4566",
        "http://127.0.0.1:4566",
    ]


def test_runtime_uses_service_endpoint_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aws_safe_mcp.auth as auth

    RecordingSession.client_calls = []
    monkeypatch.setattr(auth.boto3, "Session", RecordingSession)
    runtime = AwsRuntime(
        config=AwsSafeConfig(
            allowed_account_ids=["123456789012"],
            endpoint_url="http://127.0.0.1:4566",
            service_endpoint_urls={"s3": "http://127.0.0.1:4572"},
        ),
        profile=None,
        region="eu-west-2",
    )

    runtime.client("s3")

    assert RecordingSession.client_calls[-1]["service_name"] == "s3"
    assert RecordingSession.client_calls[-1]["endpoint_url"] == "http://127.0.0.1:4572"


def test_aws_auth_status_reports_active_role(monkeypatch: pytest.MonkeyPatch) -> None:
    import aws_safe_mcp.auth as auth

    monkeypatch.setattr(auth.boto3, "Session", FakeSession)
    runtime = AwsRuntime(
        config=AwsSafeConfig(allowed_account_ids=["123456789012"]),
        profile="dev",
        region="eu-west-2",
    )

    assert aws_auth_status(runtime) == {
        "authenticated": True,
        "account": "123456789012",
        "arn": "arn:aws:sts::123456789012:assumed-role/dev-role/session",
        "principal_type": "assumed_role",
        "principal_name": "dev-role",
        "session_name": "session",
        "profile": "dev",
        "region": "eu-west-2",
        "readonly": True,
        "message": None,
    }


@pytest.mark.parametrize(
    ("arn", "principal_type", "principal_name", "session_name"),
    [
        (
            "arn:aws:iam::123456789012:user/dev-user",
            "iam_user",
            "dev-user",
            None,
        ),
        (
            "arn:aws:iam::123456789012:role/platform/dev-role",
            "iam_role",
            "platform/dev-role",
            None,
        ),
        (
            "arn:aws:sts::123456789012:federated-user/alice@example.com",
            "federated_user",
            "alice@example.com",
            None,
        ),
        (
            "not-an-aws-arn/something",
            "unknown",
            "something",
            None,
        ),
    ],
)
def test_aws_auth_status_reports_principal_shapes(
    arn: str,
    principal_type: str,
    principal_name: str,
    session_name: str | None,
) -> None:
    result = aws_auth_status(StaticRuntime(arn))

    assert result["principal_type"] == principal_type
    assert result["principal_name"] == principal_name
    assert result["session_name"] == session_name


class NoCredentialsStsClient:
    def get_caller_identity(self) -> dict[str, str]:
        raise NoCredentialsError()


class ClientErrorStsClient:
    def get_caller_identity(self) -> dict[str, str]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetCallerIdentity",
        )


class WrongAccountStsClient:
    def get_caller_identity(self) -> dict[str, str]:
        return {
            "Account": "999999999999",
            "Arn": "arn:aws:sts::999999999999:assumed-role/dev-role/session",
            "UserId": "AROATEST:session",
        }


class ErrorSession(FakeSession):
    sts_client: Any = NoCredentialsStsClient()

    def client(self, service_name: str, **_: Any) -> Any:
        assert service_name == "sts"
        return self.sts_client


def test_runtime_records_missing_profile_without_failing_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aws_safe_mcp.auth as auth

    def raise_profile_not_found(*_: Any, **__: Any) -> None:
        raise ProfileNotFound(profile="missing")

    monkeypatch.setattr(auth.boto3, "Session", raise_profile_not_found)

    runtime = AwsRuntime(
        config=AwsSafeConfig(allowed_account_ids=["123456789012"]),
        profile="missing",
        region="eu-west-2",
    )

    assert runtime.identity is None
    assert runtime.auth_error is not None
    assert "was not found" in runtime.auth_error
    assert aws_auth_status(runtime)["authenticated"] is False
    with pytest.raises(AwsAuthError, match="aws login --profile missing"):
        runtime.client("s3")
    with pytest.raises(AwsAuthError, match="aws sso login --profile missing"):
        runtime.client("s3")


def test_runtime_records_missing_credentials_without_failing_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aws_safe_mcp.auth as auth

    ErrorSession.sts_client = NoCredentialsStsClient()
    monkeypatch.setattr(auth.boto3, "Session", ErrorSession)

    runtime = AwsRuntime(
        config=AwsSafeConfig(allowed_account_ids=["123456789012"]),
        profile=None,
        region="eu-west-2",
    )

    assert runtime.identity is None
    expected = "No AWS credentials were found for the selected profile/environment"
    assert runtime.auth_error == expected
    status = aws_auth_status(runtime)
    assert status["authenticated"] is False
    assert status["message"] == expected
    with pytest.raises(AwsAuthError, match="No AWS credentials"):
        aws_identity(runtime)


def test_runtime_records_sts_client_error_without_failing_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aws_safe_mcp.auth as auth

    ErrorSession.sts_client = ClientErrorStsClient()
    monkeypatch.setattr(auth.boto3, "Session", ErrorSession)

    runtime = AwsRuntime(
        config=AwsSafeConfig(allowed_account_ids=["123456789012"]),
        profile=None,
        region="eu-west-2",
    )

    assert runtime.identity is None
    assert runtime.auth_error is not None
    assert "Unable to validate AWS identity" in runtime.auth_error
    assert aws_auth_status(runtime)["authenticated"] is False


def test_runtime_records_wrong_account_without_failing_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aws_safe_mcp.auth as auth

    ErrorSession.sts_client = WrongAccountStsClient()
    monkeypatch.setattr(auth.boto3, "Session", ErrorSession)

    runtime = AwsRuntime(
        config=AwsSafeConfig(allowed_account_ids=["123456789012"]),
        profile=None,
        region="eu-west-2",
    )

    assert runtime.identity is None
    assert runtime.auth_error is not None
    assert "not allowed" in runtime.auth_error
    assert aws_auth_status(runtime)["authenticated"] is False


def test_runtime_detects_login_after_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    import aws_safe_mcp.auth as auth

    ErrorSession.sts_client = NoCredentialsStsClient()
    monkeypatch.setattr(auth.boto3, "Session", ErrorSession)
    runtime = AwsRuntime(
        config=AwsSafeConfig(allowed_account_ids=["123456789012"]),
        profile="dev",
        region="eu-west-2",
    )

    assert aws_auth_status(runtime)["authenticated"] is False

    ErrorSession.sts_client = FakeStsClient()

    assert aws_auth_status(runtime)["authenticated"] is True
    assert runtime.require_identity() == AwsIdentity(
        account="123456789012",
        arn="arn:aws:sts::123456789012:assumed-role/dev-role/session",
        user_id="AROATEST:session",
        profile="dev",
        region="eu-west-2",
        readonly=True,
    )


def test_runtime_clears_cached_session_when_refresh_later_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aws_safe_mcp.auth as auth

    CountingSession.calls = 0
    CountingSession.fail_after = 1
    monkeypatch.setattr(auth.boto3, "Session", CountingSession)

    runtime = AwsRuntime(
        config=AwsSafeConfig(allowed_account_ids=["123456789012"]),
        profile="dev",
        region="eu-west-2",
    )

    assert runtime.identity is not None
    assert runtime.refresh_identity() is None
    assert runtime.identity is None
    assert runtime._session is None
    expected = "No AWS credentials were found for the selected profile/environment"
    assert runtime.auth_error == expected
