from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

from aws_safe_mcp.config import AwsSafeConfig, ConfigError


class AwsAuthError(RuntimeError):
    """Raised when AWS authentication or account validation fails."""


@dataclass(frozen=True)
class AwsIdentity:
    """Validated AWS caller identity for the active runtime session."""

    account: str
    arn: str
    user_id: str
    profile: str | None
    region: str
    readonly: bool

    def as_dict(self) -> dict[str, str | bool | None]:
        return {
            "account": self.account,
            "arn": self.arn,
            "user_id": self.user_id,
            "profile": self.profile,
            "region": self.region,
            "readonly": self.readonly,
        }


class AwsRuntime:
    """Owns boto3 session creation and lazy STS validation for tool calls.

    The MCP process should be able to start before the user has authenticated
    with AWS. Runtime therefore records authentication failures during startup
    and re-checks identity whenever a tool asks for a client.
    """

    def __init__(self, config: AwsSafeConfig, profile: str | None, region: str) -> None:
        self.config = config
        self.profile = profile
        self.region = region
        self._boto_config = BotoConfig(
            connect_timeout=5,
            read_timeout=20,
            retries={"max_attempts": 3, "mode": "standard"},
            user_agent_extra="aws-safe-mcp/0.1.0",
        )
        self._session: boto3.Session | None = None
        self.identity: AwsIdentity | None = None
        self.auth_error: str | None = None
        self.refresh_identity()

    def client(self, service_name: str, region: str | None = None) -> Any:
        """Return a boto3 client after refreshing and validating AWS identity."""

        self.require_identity()
        if self._session is None:
            raise AwsAuthError("AWS authentication is not available")
        return self._session.client(
            service_name,
            region_name=region or self.region,
            config=self._boto_config,
            endpoint_url=self.config.endpoint_for_service(service_name),
        )

    def require_identity(self) -> AwsIdentity:
        """Refresh identity and raise a user-actionable auth error if unavailable."""

        identity = self.refresh_identity()
        if identity is not None:
            return identity

        message = self.auth_error or "AWS authentication is not available"
        raise AwsAuthError(
            f"{message}. Authenticate with AWS, for example: aws login --profile "
            f"{self.profile or '<profile>'} or aws sso login --profile "
            f"{self.profile or '<profile>'}"
        )

    def refresh_identity(self) -> AwsIdentity | None:
        """Refresh STS identity without raising, preserving the last auth error."""

        try:
            self._session = self._build_session()
            self.identity = self._load_and_validate_identity(self._session)
            self.auth_error = None
        except AwsAuthError as exc:
            self.identity = None
            self._session = None
            self.auth_error = str(exc)
        return self.identity

    def _build_session(self) -> boto3.Session:
        try:
            if self.profile:
                return boto3.Session(profile_name=self.profile, region_name=self.region)
            return boto3.Session(region_name=self.region)
        except ProfileNotFound as exc:
            raise AwsAuthError(f"AWS profile {self.profile!r} was not found") from exc

    def _load_and_validate_identity(self, session: boto3.Session) -> AwsIdentity:
        try:
            response = session.client(
                "sts",
                region_name=self.region,
                config=self._boto_config,
                endpoint_url=self.config.endpoint_for_service("sts"),
            ).get_caller_identity()
        except NoCredentialsError as exc:
            message = "No AWS credentials were found for the selected profile/environment"
            raise AwsAuthError(message) from exc
        except (BotoCoreError, ClientError) as exc:
            raise AwsAuthError(f"Unable to validate AWS identity with STS: {exc}") from exc

        account = str(response["Account"])
        try:
            self.config.require_account_allowed(account)
        except ConfigError as exc:
            raise AwsAuthError(str(exc)) from exc

        return AwsIdentity(
            account=account,
            arn=str(response["Arn"]),
            user_id=str(response["UserId"]),
            profile=self.profile,
            region=self.region,
            readonly=self.config.readonly,
        )
