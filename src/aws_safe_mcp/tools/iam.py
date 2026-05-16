from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.errors import ToolInputError, normalize_aws_error
from aws_safe_mcp.tools.common import isoformat


def get_iam_role_summary(
    runtime: AwsRuntime,
    role_name: str,
) -> dict[str, Any]:
    """Summarize one IAM role without returning full policy documents.

    Returns role metadata, attached managed policy ARNs (names only),
    inline policy names, trust policy principals/actions, and permissions
    boundary presence. IAM is a global service: no region parameter.
    """
    required_role_name = _require_role_name(role_name)
    client = runtime.client("iam", region=runtime.region)
    warnings: list[str] = []
    role: dict[str, Any] = {}
    attached_policies: list[dict[str, Any]] = []
    inline_policy_names: list[str] = []

    try:
        response = client.get_role(RoleName=required_role_name)
        role = response.get("Role", {})
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "iam.GetRole") from exc

    try:
        paginator = client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(
            RoleName=required_role_name,
            PaginationConfig={"PageSize": 50},
        ):
            for item in page.get("AttachedPolicies", []):
                attached_policies.append(
                    {
                        "policy_name": item.get("PolicyName"),
                        "policy_arn": item.get("PolicyArn"),
                    }
                )
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "iam.ListAttachedRolePolicies")))

    try:
        paginator = client.get_paginator("list_role_policies")
        for page in paginator.paginate(
            RoleName=required_role_name,
            PaginationConfig={"PageSize": 50},
        ):
            inline_policy_names.extend(str(name) for name in page.get("PolicyNames", []))
    except (BotoCoreError, ClientError) as exc:
        warnings.append(str(normalize_aws_error(exc, "iam.ListRolePolicies")))

    boundary = role.get("PermissionsBoundary") or {}
    return {
        "role_name": role.get("RoleName") or required_role_name,
        "role_arn": role.get("Arn"),
        "path": role.get("Path"),
        "created_at": isoformat(role.get("CreateDate")),
        "trust_policy": _trust_policy_summary(role.get("AssumeRolePolicyDocument")),
        "attached_policy_count": len(attached_policies),
        "attached_policies": attached_policies,
        "inline_policy_count": len(inline_policy_names),
        "inline_policy_names": sorted(inline_policy_names),
        "permissions_boundary": {
            "present": bool(boundary),
            "type": boundary.get("PermissionsBoundaryType"),
            "arn": boundary.get("PermissionsBoundaryArn"),
        },
        "warnings": warnings,
    }


def explain_iam_simulation_denial(
    runtime: AwsRuntime,
    principal_arn: str,
    action: str,
    resource_arn: str,
) -> dict[str, Any]:
    """Explain an IAM simulation denial without returning raw policy documents.

    Runs `iam:SimulatePrincipalPolicy` for one (principal, action,
    resource) triple and classifies the decision (allowed / explicitDeny /
    implicitDeny / unknown), the likely policy layer responsible, and any
    missing context keys. Raw policy documents are never returned.
    """
    required_principal = _require_principal_arn(principal_arn)
    required_action = _require_action(action)
    required_resource = _require_resource_arn(resource_arn)
    client = runtime.client("iam", region=runtime.region)
    try:
        response = client.simulate_principal_policy(
            PolicySourceArn=required_principal,
            ActionNames=[required_action],
            ResourceArns=[required_resource],
        )
    except (BotoCoreError, ClientError) as exc:
        raise normalize_aws_error(exc, "iam.SimulatePrincipalPolicy") from exc

    evaluation = _simulation_evaluation(response)
    return {
        "principal_arn": required_principal,
        "action": required_action,
        "resource_arn": required_resource,
        "summary": _denial_summary(evaluation),
        "evaluation": evaluation,
        "likely_policy_layer": _likely_policy_layer(evaluation),
        "uncertainty": {
            "permission_boundary_or_scp": (
                "IAM simulation can expose matched statement metadata and missing context "
                "keys, but SCP and some boundary effects may need organization/account "
                "context to confirm."
            ),
            "raw_policy_documents_returned": False,
        },
    }


def _require_role_name(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ToolInputError("role_name is required")
    if normalized.startswith("arn:"):
        parsed = _role_name_from_arn(normalized)
        if not parsed:
            raise ToolInputError("role_name ARN must be an IAM role ARN")
        return parsed
    return normalized


def _require_principal_arn(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ToolInputError("principal_arn is required")
    if ":role/" not in normalized and ":user/" not in normalized:
        raise ToolInputError("principal_arn must be an IAM role or user ARN")
    return normalized


def _require_action(value: str) -> str:
    normalized = value.strip()
    if not normalized or ":" not in normalized:
        raise ToolInputError("action must look like service:Action")
    return normalized


def _require_resource_arn(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ToolInputError("resource_arn is required")
    if not normalized.startswith("arn:"):
        raise ToolInputError("resource_arn must be an ARN")
    return normalized


def _role_name_from_arn(role_arn: str) -> str | None:
    marker = ":role/"
    if marker not in role_arn:
        return None
    return role_arn.split(marker, 1)[1].split("/")[-1] or None


def _trust_policy_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {
            "statement_count": 0,
            "actions": [],
            "service_principals": [],
            "aws_principals": [],
            "federated_principals": [],
        }
    statements = value.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    actions: set[str] = set()
    service_principals: set[str] = set()
    aws_principals: set[str] = set()
    federated_principals: set[str] = set()
    for statement in statements if isinstance(statements, list) else []:
        if not isinstance(statement, dict):
            continue
        actions.update(_string_set(statement.get("Action")))
        principal = statement.get("Principal")
        if isinstance(principal, dict):
            service_principals.update(_string_set(principal.get("Service")))
            aws_principals.update(_string_set(principal.get("AWS")))
            federated_principals.update(_string_set(principal.get("Federated")))
    return {
        "statement_count": len(statements) if isinstance(statements, list) else 0,
        "actions": sorted(actions),
        "service_principals": sorted(service_principals),
        "aws_principals": sorted(aws_principals),
        "federated_principals": sorted(federated_principals),
    }


def _string_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()


def _simulation_evaluation(response: dict[str, Any]) -> dict[str, Any]:
    results = response.get("EvaluationResults", [])
    result = results[0] if results else {}
    decision = str(result.get("EvalDecision") or "unknown")
    return {
        "decision": decision,
        "allowed": decision == "allowed",
        "explicit_deny": decision == "explicitDeny",
        "matched_statement_count": len(result.get("MatchedStatements", [])),
        "matched_statements": [
            {
                "source_policy_id": statement.get("SourcePolicyId"),
                "source_policy_type": statement.get("SourcePolicyType"),
                "start_position": statement.get("StartPosition"),
                "end_position": statement.get("EndPosition"),
            }
            for statement in result.get("MatchedStatements", [])
        ],
        "missing_context_values": [str(value) for value in result.get("MissingContextValues", [])],
    }


def _denial_summary(evaluation: dict[str, Any]) -> dict[str, Any]:
    decision = evaluation["decision"]
    if decision == "allowed":
        status = "allowed"
    elif decision == "explicitDeny":
        status = "explicit_deny"
    elif decision == "implicitDeny":
        status = "implicit_deny"
    else:
        status = "unknown"
    return {
        "status": status,
        "decision": decision,
        "matched_statement_count": evaluation["matched_statement_count"],
        "missing_context_key_count": len(evaluation["missing_context_values"]),
    }


def _likely_policy_layer(evaluation: dict[str, Any]) -> str:
    if evaluation["decision"] == "explicitDeny":
        source_types = {
            str(statement.get("source_policy_type") or "unknown").lower()
            for statement in evaluation["matched_statements"]
        }
        if any("permissionsboundary" in source_type for source_type in source_types):
            return "permissions_boundary_explicit_deny"
        if any(
            "organizations" in source_type or "scp" in source_type
            for source_type in source_types
        ):
            return "service_control_policy_explicit_deny"
        return "identity_or_resource_policy_explicit_deny"
    if evaluation["decision"] == "implicitDeny":
        if evaluation["missing_context_values"]:
            return "missing_context_or_condition_mismatch"
        return "no_matching_allow_or_boundary_scp_limit"
    if evaluation["decision"] == "allowed":
        return "no_denial_detected"
    return "unknown"
