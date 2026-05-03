from __future__ import annotations

import re

from aws_safe_mcp.auth import AwsIdentity, AwsRuntime


def aws_identity(runtime: AwsRuntime) -> dict[str, str | bool | None]:
    """Return the validated AWS caller identity for this MCP server session."""
    return runtime.require_identity().as_dict()


def aws_auth_status(runtime: AwsRuntime) -> dict[str, str | bool | None]:
    """Return a compact, human-friendly authentication status."""
    identity = runtime.refresh_identity()
    if identity is None:
        return {
            "authenticated": False,
            "account": None,
            "arn": None,
            "principal_type": None,
            "principal_name": None,
            "session_name": None,
            "profile": runtime.profile,
            "region": runtime.region,
            "readonly": runtime.config.readonly,
            "message": runtime.auth_error,
        }
    return _authenticated_status(identity)


def _authenticated_status(identity: AwsIdentity) -> dict[str, str | bool | None]:
    principal = _principal_from_arn(identity.arn)
    return {
        "authenticated": True,
        "account": identity.account,
        "arn": identity.arn,
        "principal_type": principal["type"],
        "principal_name": principal["name"],
        "session_name": principal["session"],
        "profile": identity.profile,
        "region": identity.region,
        "readonly": identity.readonly,
        "message": None,
    }


def _principal_from_arn(arn: str) -> dict[str, str | None]:
    assumed_role = re.fullmatch(
        r"arn:aws[a-zA-Z-]*:sts::\d{12}:assumed-role/(?P<role>[^/]+)/(?P<session>.+)",
        arn,
    )
    if assumed_role:
        return {
            "type": "assumed_role",
            "name": assumed_role.group("role"),
            "session": assumed_role.group("session"),
        }

    iam_user = re.fullmatch(r"arn:aws[a-zA-Z-]*:iam::\d{12}:user/(?P<user>.+)", arn)
    if iam_user:
        return {"type": "iam_user", "name": iam_user.group("user"), "session": None}

    role = re.fullmatch(r"arn:aws[a-zA-Z-]*:iam::\d{12}:role/(?P<role>.+)", arn)
    if role:
        return {"type": "iam_role", "name": role.group("role"), "session": None}

    federated = re.fullmatch(
        r"arn:aws[a-zA-Z-]*:sts::\d{12}:federated-user/(?P<user>.+)",
        arn,
    )
    if federated:
        return {
            "type": "federated_user",
            "name": federated.group("user"),
            "session": None,
        }

    return {"type": "unknown", "name": arn.rsplit("/", 1)[-1], "session": None}
