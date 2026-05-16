from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aws_safe_mcp.audit import AuditLogger
from aws_safe_mcp.auth import AwsRuntime
from aws_safe_mcp.tools.apigateway import (
    analyze_api_gateway_authorizer_failures as analyze_api_gateway_authorizer_failures_tool,
)
from aws_safe_mcp.tools.apigateway import (
    explain_api_gateway_dependencies as explain_api_gateway_dependencies_tool,
)
from aws_safe_mcp.tools.apigateway import (
    get_api_gateway_authorizer_summary as get_api_gateway_authorizer_summary_tool,
)
from aws_safe_mcp.tools.apigateway import get_api_gateway_summary as get_api_gateway_summary_tool
from aws_safe_mcp.tools.apigateway import (
    investigate_api_gateway_route as investigate_api_gateway_route_tool,
)
from aws_safe_mcp.tools.apigateway import list_api_gateways as list_api_gateways_tool
from aws_safe_mcp.tools.cloudwatch import (
    check_cloudwatch_logs_writeability as check_cloudwatch_logs_writeability_tool,
)
from aws_safe_mcp.tools.cloudwatch import (
    find_cloudwatch_alarm_coverage_gaps as find_cloudwatch_alarm_coverage_gaps_tool,
)
from aws_safe_mcp.tools.cloudwatch import (
    get_cloudwatch_alarm_summary as get_cloudwatch_alarm_summary_tool,
)
from aws_safe_mcp.tools.cloudwatch import list_cloudwatch_alarms as list_cloudwatch_alarms_tool
from aws_safe_mcp.tools.cloudwatch import (
    list_cloudwatch_log_groups as list_cloudwatch_log_groups_tool,
)
from aws_safe_mcp.tools.cloudwatch import (
    query_cloudwatch_logs_insights as query_cloudwatch_logs_insights_tool,
)
from aws_safe_mcp.tools.cloudwatch import search_cloudwatch_logs as search_cloudwatch_logs_tool
from aws_safe_mcp.tools.dynamodb import (
    check_dynamodb_stream_lambda_readiness as check_dynamodb_stream_lambda_readiness_tool,
)
from aws_safe_mcp.tools.dynamodb import (
    get_dynamodb_table_summary as get_dynamodb_table_summary_tool,
)
from aws_safe_mcp.tools.dynamodb import list_dynamodb_tables as list_dynamodb_tables_tool
from aws_safe_mcp.tools.ecs import get_ecs_service_summary as get_ecs_service_summary_tool
from aws_safe_mcp.tools.ecs import list_ecs_clusters as list_ecs_clusters_tool
from aws_safe_mcp.tools.ecs import list_ecs_services as list_ecs_services_tool
from aws_safe_mcp.tools.eventbridge import (
    audit_eventbridge_target_retry_dlq_safety as audit_eventbridge_target_retry_dlq_safety_tool,
)
from aws_safe_mcp.tools.eventbridge import (
    explain_event_driven_flow as explain_event_driven_flow_tool,
)
from aws_safe_mcp.tools.eventbridge import (
    explain_eventbridge_rule_dependencies as explain_eventbridge_rule_dependencies_tool,
)
from aws_safe_mcp.tools.eventbridge import (
    get_eventbridge_time_sources as get_eventbridge_time_sources_tool,
)
from aws_safe_mcp.tools.eventbridge import (
    investigate_eventbridge_rule_delivery as investigate_eventbridge_rule_delivery_tool,
)
from aws_safe_mcp.tools.eventbridge import (
    list_eventbridge_rules as list_eventbridge_rules_tool,
)
from aws_safe_mcp.tools.iam import (
    explain_iam_simulation_denial as explain_iam_simulation_denial_tool,
)
from aws_safe_mcp.tools.iam import get_iam_role_summary as get_iam_role_summary_tool
from aws_safe_mcp.tools.identity import get_aws_auth_status as get_aws_auth_status_tool
from aws_safe_mcp.tools.identity import get_aws_identity as get_aws_identity_tool
from aws_safe_mcp.tools.kms import check_kms_dependent_path as check_kms_dependent_path_tool
from aws_safe_mcp.tools.kms import (
    find_kms_key_lifecycle_blast_radius as find_kms_key_lifecycle_blast_radius_tool,
)
from aws_safe_mcp.tools.kms import get_kms_key_summary as get_kms_key_summary_tool
from aws_safe_mcp.tools.kms import list_kms_keys as list_kms_keys_tool
from aws_safe_mcp.tools.lambda_tools import (
    analyze_cross_account_lambda_invocation as analyze_cross_account_lambda_invocation_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    audit_async_lambda_failure_path as audit_async_lambda_failure_path_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    check_lambda_permission_path as check_lambda_permission_path_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    check_lambda_to_sqs_sendability as check_lambda_to_sqs_sendability_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    explain_lambda_dependencies as explain_lambda_dependencies_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    explain_lambda_network_access as explain_lambda_network_access_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    get_lambda_alias_version_summary as get_lambda_alias_version_summary_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    get_lambda_event_source_mapping_diagnostics as get_lambda_event_source_mapping_diagnostics_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    get_lambda_recent_errors as get_lambda_recent_errors_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    get_lambda_summary as get_lambda_summary_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    investigate_lambda_cold_start_init as investigate_lambda_cold_start_init_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    investigate_lambda_concurrency_bottlenecks as investigate_lambda_concurrency_bottlenecks_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    investigate_lambda_deployment_drift as investigate_lambda_deployment_drift_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    investigate_lambda_failure as investigate_lambda_failure_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    investigate_lambda_timeout_root_cause as investigate_lambda_timeout_root_cause_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    list_lambda_functions as list_lambda_functions_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    prove_lambda_invocation_path as prove_lambda_invocation_path_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    simulate_lambda_security_group_path as simulate_lambda_security_group_path_tool,
)
from aws_safe_mcp.tools.resource_search import (
    analyze_resource_policy_condition_mismatches as condition_mismatch_tool,
)
from aws_safe_mcp.tools.resource_search import (
    audit_multi_region_drift_failover_readiness as multi_region_drift_tool,
)
from aws_safe_mcp.tools.resource_search import (
    build_log_signal_correlation_timeline as build_log_signal_correlation_timeline_tool,
)
from aws_safe_mcp.tools.resource_search import (
    diagnose_region_partition_mismatches as diagnose_region_partition_mismatches_tool,
)
from aws_safe_mcp.tools.resource_search import (
    export_application_dependency_graph as export_application_dependency_graph_tool,
)
from aws_safe_mcp.tools.resource_search import (
    generate_application_health_narrative as generate_application_health_narrative_tool,
)
from aws_safe_mcp.tools.resource_search import (
    get_cross_service_incident_brief as get_cross_service_incident_brief_tool,
)
from aws_safe_mcp.tools.resource_search import (
    get_risk_scored_dependency_health_summary as get_risk_scored_dependency_health_summary_tool,
)
from aws_safe_mcp.tools.resource_search import (
    plan_end_to_end_transaction_trace as plan_end_to_end_transaction_trace_tool,
)
from aws_safe_mcp.tools.resource_search import (
    run_first_blocked_edge_incident as run_first_blocked_edge_incident_tool,
)
from aws_safe_mcp.tools.resource_search import (
    search_aws_resources as search_aws_resources_tool,
)
from aws_safe_mcp.tools.resource_search import (
    search_aws_resources_by_tag as search_aws_resources_by_tag_tool,
)
from aws_safe_mcp.tools.s3 import (
    check_s3_notification_destination_readiness as check_s3_notification_destination_readiness_tool,
)
from aws_safe_mcp.tools.s3 import get_s3_bucket_summary as get_s3_bucket_summary_tool
from aws_safe_mcp.tools.s3 import list_s3_buckets as list_s3_buckets_tool
from aws_safe_mcp.tools.s3 import list_s3_objects as list_s3_objects_tool
from aws_safe_mcp.tools.sns import (
    audit_sns_fanout_delivery_readiness as audit_sns_fanout_delivery_readiness_tool,
)
from aws_safe_mcp.tools.sns import (
    explain_sns_topic_dependencies as explain_sns_topic_dependencies_tool,
)
from aws_safe_mcp.tools.sns import get_sns_topic_summary as get_sns_topic_summary_tool
from aws_safe_mcp.tools.sns import list_sns_topics as list_sns_topics_tool
from aws_safe_mcp.tools.sqs import (
    analyze_queue_dlq_replay_readiness as analyze_queue_dlq_replay_readiness_tool,
)
from aws_safe_mcp.tools.sqs import (
    check_sqs_to_lambda_delivery as check_sqs_to_lambda_delivery_tool,
)
from aws_safe_mcp.tools.sqs import (
    explain_sqs_queue_dependencies as explain_sqs_queue_dependencies_tool,
)
from aws_safe_mcp.tools.sqs import (
    get_sqs_queue_summary as get_sqs_queue_summary_tool,
)
from aws_safe_mcp.tools.sqs import (
    investigate_sqs_backlog_stall as investigate_sqs_backlog_stall_tool,
)
from aws_safe_mcp.tools.sqs import (
    list_sqs_queues as list_sqs_queues_tool,
)
from aws_safe_mcp.tools.stepfunctions import (
    audit_step_function_retry_catch_safety as audit_step_function_retry_catch_safety_tool,
)
from aws_safe_mcp.tools.stepfunctions import (
    explain_step_function_dependencies as explain_step_function_dependencies_tool,
)
from aws_safe_mcp.tools.stepfunctions import (
    get_step_function_execution_summary as get_step_function_execution_summary_tool,
)
from aws_safe_mcp.tools.stepfunctions import (
    investigate_step_function_failure as investigate_step_function_failure_tool,
)
from aws_safe_mcp.tools.stepfunctions import (
    list_step_functions as list_step_functions_tool,
)


def create_server(runtime: AwsRuntime) -> FastMCP:
    mcp = FastMCP("aws-safe-mcp")
    audit = AuditLogger(redaction=runtime.config.redaction)
    _register_identity_tools(mcp, audit, runtime)
    _register_iam_tools(mcp, audit, runtime)
    _register_kms_tools(mcp, audit, runtime)
    _register_lambda_tools(mcp, audit, runtime)
    _register_step_functions_tools(mcp, audit, runtime)
    _register_s3_tools(mcp, audit, runtime)
    _register_sqs_tools(mcp, audit, runtime)
    _register_sns_tools(mcp, audit, runtime)
    _register_dynamodb_tools(mcp, audit, runtime)
    _register_ecs_tools(mcp, audit, runtime)
    _register_cloudwatch_tools(mcp, audit, runtime)
    _register_api_gateway_tools(mcp, audit, runtime)
    _register_eventbridge_tools(mcp, audit, runtime)
    _register_search_tools(mcp, audit, runtime)
    return mcp


def _register_identity_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("get_aws_auth_status")
    def get_aws_auth_status() -> dict[str, str | bool | None]:
        """Quickly show whether AWS auth is valid and which principal is active."""
        return get_aws_auth_status_tool(runtime)

    @mcp.tool()
    @audit.tool("get_aws_identity")
    def get_aws_identity() -> dict[str, str | bool | None]:
        """Show authenticated AWS account, ARN, profile, region, and read-only mode."""
        return get_aws_identity_tool(runtime)


def _register_iam_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("get_iam_role_summary")
    def get_iam_role_summary(
        role_name: str,
    ) -> dict[str, object]:
        """Summarize one IAM role without returning full policy documents."""
        return get_iam_role_summary_tool(
            runtime,
            role_name=role_name,
        )

    @mcp.tool()
    @audit.tool("explain_iam_simulation_denial")
    def explain_iam_simulation_denial(
        principal_arn: str,
        action: str,
        resource_arn: str,
    ) -> dict[str, object]:
        """Explain IAM simulation denies without returning raw policy documents."""
        return explain_iam_simulation_denial_tool(
            runtime,
            principal_arn=principal_arn,
            action=action,
            resource_arn=resource_arn,
        )


def _register_kms_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("list_kms_keys")
    def list_kms_keys(
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List KMS keys with safe metadata summaries."""
        return list_kms_keys_tool(
            runtime,
            region=region,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_kms_key_summary")
    def get_kms_key_summary(
        key_id: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Summarize one KMS key without cryptographic or policy-document reads."""
        return get_kms_key_summary_tool(
            runtime,
            key_id=key_id,
            region=region,
        )

    @mcp.tool()
    @audit.tool("check_kms_dependent_path")
    def check_kms_dependent_path(
        key_id: str,
        role_arn: str,
        service_principal: str | None = None,
        region: str | None = None,
    ) -> dict[str, object]:
        """Check whether a role and optional AWS service principal can use a KMS key."""
        return check_kms_dependent_path_tool(
            runtime,
            key_id=key_id,
            role_arn=role_arn,
            service_principal=service_principal,
            region=region,
        )

    @mcp.tool()
    @audit.tool("find_kms_key_lifecycle_blast_radius")
    def find_kms_key_lifecycle_blast_radius(
        key_id: str,
        dependent_resource_arns: list[str] | None = None,
        region: str | None = None,
    ) -> dict[str, object]:
        """Find dependent-resource risk for disabled or pending-deletion KMS keys."""
        return find_kms_key_lifecycle_blast_radius_tool(
            runtime,
            key_id=key_id,
            dependent_resource_arns=dependent_resource_arns,
            region=region,
        )


def _register_lambda_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("list_lambda_functions")
    def list_lambda_functions(
        region: str | None = None,
        name_prefix: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List Lambda functions with concise configuration summaries."""
        return list_lambda_functions_tool(
            runtime,
            region=region,
            name_prefix=name_prefix,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_lambda_summary")
    def get_lambda_summary(
        function_name: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Summarize one Lambda function without returning environment values."""
        return get_lambda_summary_tool(
            runtime,
            function_name=function_name,
            region=region,
        )

    @mcp.tool()
    @audit.tool("get_lambda_event_source_mapping_diagnostics")
    def get_lambda_event_source_mapping_diagnostics(
        function_name: str,
        region: str | None = None,
        max_results: int | None = None,
        include_permission_checks: bool = True,
        max_permission_checks: int | None = None,
    ) -> dict[str, object]:
        """Summarize Lambda event source mappings and inferred IAM checks."""
        return get_lambda_event_source_mapping_diagnostics_tool(
            runtime,
            function_name=function_name,
            region=region,
            max_results=max_results,
            include_permission_checks=include_permission_checks,
            max_permission_checks=max_permission_checks,
        )

    @mcp.tool()
    @audit.tool("get_lambda_alias_version_summary")
    def get_lambda_alias_version_summary(
        function_name: str,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Summarize Lambda aliases, published versions, and traffic policy hints."""
        return get_lambda_alias_version_summary_tool(
            runtime,
            function_name=function_name,
            region=region,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("investigate_lambda_deployment_drift")
    def investigate_lambda_deployment_drift(
        function_name: str,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Investigate Lambda alias, version, canary, update, and $LATEST drift."""
        return investigate_lambda_deployment_drift_tool(
            runtime,
            function_name=function_name,
            region=region,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_lambda_recent_errors")
    def get_lambda_recent_errors(
        function_name: str,
        since_minutes: int | None = 60,
        region: str | None = None,
        max_events: int | None = 50,
    ) -> dict[str, object]:
        """Return recent error-like CloudWatch log events for one Lambda."""
        return get_lambda_recent_errors_tool(
            runtime,
            function_name=function_name,
            since_minutes=since_minutes,
            region=region,
            max_events=max_events,
        )

    @mcp.tool()
    @audit.tool("investigate_lambda_failure")
    def investigate_lambda_failure(
        function_name: str,
        since_minutes: int | None = 60,
        region: str | None = None,
    ) -> dict[str, object]:
        """Diagnose recent Lambda failures from config, metrics, and logs."""
        return investigate_lambda_failure_tool(
            runtime,
            function_name=function_name,
            since_minutes=since_minutes,
            region=region,
        )

    @mcp.tool()
    @audit.tool("investigate_lambda_cold_start_init")
    def investigate_lambda_cold_start_init(
        function_name: str,
        since_minutes: int | None = 60,
        region: str | None = None,
    ) -> dict[str, object]:
        """Diagnose Lambda cold-start and init failure signals from config, metrics, and logs."""
        return investigate_lambda_cold_start_init_tool(
            runtime,
            function_name=function_name,
            since_minutes=since_minutes,
            region=region,
        )

    @mcp.tool()
    @audit.tool("investigate_lambda_timeout_root_cause")
    def investigate_lambda_timeout_root_cause(
        function_name: str,
        since_minutes: int | None = 60,
        region: str | None = None,
    ) -> dict[str, object]:
        """Diagnose likely Lambda timeout root causes from metrics, logs, deps, and network."""
        return investigate_lambda_timeout_root_cause_tool(
            runtime,
            function_name=function_name,
            since_minutes=since_minutes,
            region=region,
        )

    @mcp.tool()
    @audit.tool("audit_async_lambda_failure_path")
    def audit_async_lambda_failure_path(
        function_name: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Audit async Lambda retry, destination, DLQ, throttle, and concurrency posture."""
        return audit_async_lambda_failure_path_tool(
            runtime,
            function_name=function_name,
            region=region,
        )

    @mcp.tool()
    @audit.tool("investigate_lambda_concurrency_bottlenecks")
    def investigate_lambda_concurrency_bottlenecks(
        function_name: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Correlate Lambda throttles, reserved concurrency, and event sources."""
        return investigate_lambda_concurrency_bottlenecks_tool(
            runtime,
            function_name=function_name,
            region=region,
        )

    @mcp.tool()
    @audit.tool("explain_lambda_dependencies")
    def explain_lambda_dependencies(
        function_name: str,
        region: str | None = None,
        include_permission_checks: bool = True,
        max_permission_checks: int | None = None,
    ) -> dict[str, object]:
        """Map one Lambda's dependencies and run inferred IAM permission checks."""
        return explain_lambda_dependencies_tool(
            runtime,
            function_name=function_name,
            region=region,
            include_permission_checks=include_permission_checks,
            max_permission_checks=max_permission_checks,
        )

    @mcp.tool()
    @audit.tool("explain_lambda_network_access")
    def explain_lambda_network_access(
        function_name: str,
        region: str | None = None,
        target_url: str | None = None,
    ) -> dict[str, object]:
        """Trace inferred internet and private network reachability for one Lambda."""
        return explain_lambda_network_access_tool(
            runtime,
            function_name=function_name,
            region=region,
            target_url=target_url,
        )

    @mcp.tool()
    @audit.tool("simulate_lambda_security_group_path")
    def simulate_lambda_security_group_path(
        function_name: str,
        target_cidr: str,
        target_port: int,
        target_security_group_id: str | None = None,
        region: str | None = None,
    ) -> dict[str, object]:
        """Simulate Lambda security-group egress and optional target ingress."""
        return simulate_lambda_security_group_path_tool(
            runtime,
            function_name=function_name,
            target_cidr=target_cidr,
            target_port=target_port,
            target_security_group_id=target_security_group_id,
            region=region,
        )

    @mcp.tool()
    @audit.tool("check_lambda_permission_path")
    def check_lambda_permission_path(
        function_name: str,
        action: str,
        resource_arn: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Check if a Lambda execution role is allowed to perform one action on one ARN."""
        return check_lambda_permission_path_tool(
            runtime,
            function_name=function_name,
            action=action,
            resource_arn=resource_arn,
            region=region,
        )

    @mcp.tool()
    @audit.tool("check_lambda_to_sqs_sendability")
    def check_lambda_to_sqs_sendability(
        function_name: str,
        queue_url: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Check whether one Lambda appears able to send messages to one SQS queue."""
        return check_lambda_to_sqs_sendability_tool(
            runtime,
            function_name=function_name,
            queue_url=queue_url,
            region=region,
        )

    @mcp.tool()
    @audit.tool("prove_lambda_invocation_path")
    def prove_lambda_invocation_path(
        function_name: str,
        caller_principal: str,
        source_arn: str | None = None,
        region: str | None = None,
    ) -> dict[str, object]:
        """Prove the resource-policy and caller-policy edges for Lambda invocation."""
        return prove_lambda_invocation_path_tool(
            runtime,
            function_name=function_name,
            caller_principal=caller_principal,
            source_arn=source_arn,
            region=region,
        )

    @mcp.tool()
    @audit.tool("analyze_cross_account_lambda_invocation")
    def analyze_cross_account_lambda_invocation(
        function_name: str,
        caller_principal: str,
        source_arn: str | None = None,
        region: str | None = None,
    ) -> dict[str, object]:
        """Analyze cross-account Lambda invocation trust and proof status."""
        return analyze_cross_account_lambda_invocation_tool(
            runtime,
            function_name=function_name,
            caller_principal=caller_principal,
            source_arn=source_arn,
            region=region,
        )


def _register_step_functions_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("list_step_functions")
    def list_step_functions(
        region: str | None = None,
        name_prefix: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List Step Functions state machines."""
        return list_step_functions_tool(
            runtime,
            region=region,
            name_prefix=name_prefix,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_step_function_execution_summary")
    def get_step_function_execution_summary(
        execution_arn: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Summarize one Step Functions execution with redacted input/output."""
        return get_step_function_execution_summary_tool(
            runtime,
            execution_arn=execution_arn,
            region=region,
        )

    @mcp.tool()
    @audit.tool("investigate_step_function_failure")
    def investigate_step_function_failure(
        execution_arn: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Diagnose one Step Functions execution failure."""
        return investigate_step_function_failure_tool(
            runtime,
            execution_arn=execution_arn,
            region=region,
        )

    @mcp.tool()
    @audit.tool("audit_step_function_retry_catch_safety")
    def audit_step_function_retry_catch_safety(
        state_machine_arn: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Audit Step Functions task retry/catch coverage without returning definitions."""
        return audit_step_function_retry_catch_safety_tool(
            runtime,
            state_machine_arn=state_machine_arn,
            region=region,
        )

    @mcp.tool()
    @audit.tool("explain_step_function_dependencies")
    def explain_step_function_dependencies(
        state_machine_arn: str,
        region: str | None = None,
        include_permission_checks: bool = True,
        max_permission_checks: int | None = None,
    ) -> dict[str, object]:
        """Map one Step Function's task dependencies and inferred IAM checks."""
        return explain_step_function_dependencies_tool(
            runtime,
            state_machine_arn=state_machine_arn,
            region=region,
            include_permission_checks=include_permission_checks,
            max_permission_checks=max_permission_checks,
        )


def _register_s3_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("list_s3_buckets")
    def list_s3_buckets(max_results: int | None = None) -> dict[str, object]:
        """List account-level S3 buckets; region is not a bucket-location filter."""
        return list_s3_buckets_tool(
            runtime,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("list_s3_objects")
    def list_s3_objects(
        bucket: str,
        prefix: str | None = None,
        max_keys: int | None = 50,
        region: str | None = None,
    ) -> dict[str, object]:
        """List metadata for objects in one S3 bucket without fetching contents."""
        return list_s3_objects_tool(
            runtime,
            bucket=bucket,
            prefix=prefix,
            max_keys=max_keys,
            region=region,
        )

    @mcp.tool()
    @audit.tool("get_s3_bucket_summary")
    def get_s3_bucket_summary(
        bucket: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Summarize S3 bucket metadata without reading object contents."""
        return get_s3_bucket_summary_tool(
            runtime,
            bucket=bucket,
            region=region,
        )

    @mcp.tool()
    @audit.tool("check_s3_notification_destination_readiness")
    def check_s3_notification_destination_readiness(
        bucket: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Check S3 notification destinations without reading object bodies."""
        return check_s3_notification_destination_readiness_tool(
            runtime,
            bucket=bucket,
            region=region,
        )


def _register_dynamodb_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("list_dynamodb_tables")
    def list_dynamodb_tables(
        region: str | None = None,
        name_prefix: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List DynamoDB table names without scanning or reading items."""
        return list_dynamodb_tables_tool(
            runtime,
            region=region,
            name_prefix=name_prefix,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_dynamodb_table_summary")
    def get_dynamodb_table_summary(
        table_name: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Summarize one DynamoDB table without scans or item reads."""
        return get_dynamodb_table_summary_tool(
            runtime,
            table_name=table_name,
            region=region,
        )

    @mcp.tool()
    @audit.tool("check_dynamodb_stream_lambda_readiness")
    def check_dynamodb_stream_lambda_readiness(
        table_name: str,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Check DynamoDB stream-to-Lambda readiness without reading records."""
        return check_dynamodb_stream_lambda_readiness_tool(
            runtime,
            table_name=table_name,
            region=region,
            max_results=max_results,
        )


def _register_sqs_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("list_sqs_queues")
    def list_sqs_queues(
        region: str | None = None,
        name_prefix: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List SQS queues without receiving messages."""
        return list_sqs_queues_tool(
            runtime,
            region=region,
            name_prefix=name_prefix,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_sqs_queue_summary")
    def get_sqs_queue_summary(
        queue_url: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Summarize SQS queue metadata without receiving messages."""
        return get_sqs_queue_summary_tool(
            runtime,
            queue_url=queue_url,
            region=region,
        )

    @mcp.tool()
    @audit.tool("explain_sqs_queue_dependencies")
    def explain_sqs_queue_dependencies(
        queue_url: str,
        region: str | None = None,
        include_permission_checks: bool = True,
        max_permission_checks: int | None = None,
    ) -> dict[str, object]:
        """Map SQS producers, consumers, DLQ, and inferred permissions."""
        return explain_sqs_queue_dependencies_tool(
            runtime,
            queue_url=queue_url,
            region=region,
            include_permission_checks=include_permission_checks,
            max_permission_checks=max_permission_checks,
        )

    @mcp.tool()
    @audit.tool("check_sqs_to_lambda_delivery")
    def check_sqs_to_lambda_delivery(
        queue_url: str,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Check SQS-to-Lambda event source mapping delivery readiness."""
        return check_sqs_to_lambda_delivery_tool(
            runtime,
            queue_url=queue_url,
            region=region,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("investigate_sqs_backlog_stall")
    def investigate_sqs_backlog_stall(
        queue_url: str,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Correlate SQS backlog, Lambda mappings, visibility timeout, DLQ, and throttles."""
        return investigate_sqs_backlog_stall_tool(
            runtime,
            queue_url=queue_url,
            region=region,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("analyze_queue_dlq_replay_readiness")
    def analyze_queue_dlq_replay_readiness(
        dlq_queue_url: str,
        source_queue_urls: list[str] | None = None,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Inspect whether an SQS DLQ replay appears safe before any replay action."""
        return analyze_queue_dlq_replay_readiness_tool(
            runtime,
            dlq_queue_url=dlq_queue_url,
            source_queue_urls=source_queue_urls,
            region=region,
            max_results=max_results,
        )


def _register_sns_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("list_sns_topics")
    def list_sns_topics(
        region: str | None = None,
        name_prefix: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List SNS topics without publishing messages."""
        return list_sns_topics_tool(
            runtime,
            region=region,
            name_prefix=name_prefix,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_sns_topic_summary")
    def get_sns_topic_summary(
        topic_arn: str,
        region: str | None = None,
        max_subscriptions: int | None = None,
    ) -> dict[str, object]:
        """Summarize SNS topic metadata and subscriptions safely."""
        return get_sns_topic_summary_tool(
            runtime,
            topic_arn=topic_arn,
            region=region,
            max_subscriptions=max_subscriptions,
        )

    @mcp.tool()
    @audit.tool("explain_sns_topic_dependencies")
    def explain_sns_topic_dependencies(
        topic_arn: str,
        region: str | None = None,
        include_permission_checks: bool = True,
        max_permission_checks: int | None = None,
    ) -> dict[str, object]:
        """Map SNS subscriptions, DLQs, and inferred delivery permissions."""
        return explain_sns_topic_dependencies_tool(
            runtime,
            topic_arn=topic_arn,
            region=region,
            include_permission_checks=include_permission_checks,
            max_permission_checks=max_permission_checks,
        )

    @mcp.tool()
    @audit.tool("audit_sns_fanout_delivery_readiness")
    def audit_sns_fanout_delivery_readiness(
        topic_arn: str,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Audit SNS fanout delivery readiness without publishing messages."""
        return audit_sns_fanout_delivery_readiness_tool(
            runtime,
            topic_arn=topic_arn,
            region=region,
            max_results=max_results,
        )


def _register_ecs_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("list_ecs_clusters")
    def list_ecs_clusters(
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List ECS clusters."""
        return list_ecs_clusters_tool(runtime, region=region, max_results=max_results)

    @mcp.tool()
    @audit.tool("list_ecs_services")
    def list_ecs_services(
        cluster: str,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List ECS services in one cluster."""
        return list_ecs_services_tool(
            runtime,
            cluster=cluster,
            region=region,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_ecs_service_summary")
    def get_ecs_service_summary(
        cluster: str,
        service: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Summarize one ECS service and its task definition safely."""
        return get_ecs_service_summary_tool(
            runtime,
            cluster=cluster,
            service=service,
            region=region,
        )


def _register_cloudwatch_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("list_cloudwatch_alarms")
    def list_cloudwatch_alarms(
        region: str | None = None,
        name_prefix: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List CloudWatch alarms with linked resource hints."""
        return list_cloudwatch_alarms_tool(
            runtime,
            region=region,
            name_prefix=name_prefix,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_cloudwatch_alarm_summary")
    def get_cloudwatch_alarm_summary(
        alarm_name: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Summarize one CloudWatch alarm and likely linked resources."""
        return get_cloudwatch_alarm_summary_tool(
            runtime,
            alarm_name=alarm_name,
            region=region,
        )

    @mcp.tool()
    @audit.tool("find_cloudwatch_alarm_coverage_gaps")
    def find_cloudwatch_alarm_coverage_gaps(
        resource_type: str,
        resource_name: str,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Find missing alarm coverage and suggest metric dimensions."""
        return find_cloudwatch_alarm_coverage_gaps_tool(
            runtime,
            resource_type=resource_type,
            resource_name=resource_name,
            region=region,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("list_cloudwatch_log_groups")
    def list_cloudwatch_log_groups(
        region: str | None = None,
        name_prefix: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List CloudWatch log groups visible to the active AWS credentials."""
        return list_cloudwatch_log_groups_tool(
            runtime,
            region=region,
            name_prefix=name_prefix,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("search_cloudwatch_logs")
    def search_cloudwatch_logs(
        log_group_name: str,
        query: str,
        since_minutes: int | None = 60,
        max_results: int | None = 50,
        region: str | None = None,
    ) -> dict[str, object]:
        """Search one CloudWatch log group with bounded filter_log_events."""
        return search_cloudwatch_logs_tool(
            runtime,
            log_group_name=log_group_name,
            query=query,
            since_minutes=since_minutes,
            max_results=max_results,
            region=region,
        )

    @mcp.tool()
    @audit.tool("query_cloudwatch_logs_insights")
    def query_cloudwatch_logs_insights(
        log_group_name: str,
        query: str,
        since_minutes: int | None = 60,
        max_results: int | None = 50,
        region: str | None = None,
    ) -> dict[str, object]:
        """Run a bounded Logs Insights query against one log group."""
        return query_cloudwatch_logs_insights_tool(
            runtime,
            log_group_name=log_group_name,
            query=query,
            since_minutes=since_minutes,
            max_results=max_results,
            region=region,
        )

    @mcp.tool()
    @audit.tool("check_cloudwatch_logs_writeability")
    def check_cloudwatch_logs_writeability(
        log_group_name: str,
        role_arn: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Check whether a role can write to one CloudWatch Logs log group."""
        return check_cloudwatch_logs_writeability_tool(
            runtime,
            log_group_name=log_group_name,
            role_arn=role_arn,
            region=region,
        )


def _register_api_gateway_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("list_api_gateways")
    def list_api_gateways(
        region: str | None = None,
        name_prefix: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List REST, HTTP, and WebSocket API Gateway APIs."""
        return list_api_gateways_tool(
            runtime,
            region=region,
            name_prefix=name_prefix,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_api_gateway_summary")
    def get_api_gateway_summary(
        api_id: str,
        api_type: str | None = None,
        region: str | None = None,
    ) -> dict[str, object]:
        """Summarize one API Gateway API without invoking it."""
        return get_api_gateway_summary_tool(
            runtime,
            api_id=api_id,
            api_type=api_type,
            region=region,
        )

    @mcp.tool()
    @audit.tool("get_api_gateway_authorizer_summary")
    def get_api_gateway_authorizer_summary(
        api_id: str,
        api_type: str | None = None,
        region: str | None = None,
    ) -> dict[str, object]:
        """Summarize API Gateway authorizers and attached routes."""
        return get_api_gateway_authorizer_summary_tool(
            runtime,
            api_id=api_id,
            api_type=api_type,
            region=region,
        )

    @mcp.tool()
    @audit.tool("analyze_api_gateway_authorizer_failures")
    def analyze_api_gateway_authorizer_failures(
        api_id: str,
        route_key: str | None = None,
        api_type: str | None = None,
        region: str | None = None,
        max_events: int | None = None,
    ) -> dict[str, object]:
        """Analyze API Gateway authorizer 401/403 risks without invoking the API."""
        return analyze_api_gateway_authorizer_failures_tool(
            runtime,
            api_id=api_id,
            route_key=route_key,
            api_type=api_type,
            region=region,
            max_events=max_events,
        )

    @mcp.tool()
    @audit.tool("explain_api_gateway_dependencies")
    def explain_api_gateway_dependencies(
        api_id: str,
        api_type: str | None = None,
        region: str | None = None,
    ) -> dict[str, object]:
        """Map API Gateway routes to integrations and Lambda invoke policy checks."""
        return explain_api_gateway_dependencies_tool(
            runtime,
            api_id=api_id,
            api_type=api_type,
            region=region,
        )

    @mcp.tool()
    @audit.tool("investigate_api_gateway_route")
    def investigate_api_gateway_route(
        api_id: str,
        route_key: str | None = None,
        method: str | None = None,
        path: str | None = None,
        api_type: str | None = None,
        region: str | None = None,
        max_events: int | None = None,
    ) -> dict[str, object]:
        """Diagnose one API Gateway route, Lambda permission, and Lambda errors."""
        return investigate_api_gateway_route_tool(
            runtime,
            api_id=api_id,
            route_key=route_key,
            method=method,
            path=path,
            api_type=api_type,
            region=region,
            max_events=max_events,
        )


def _register_eventbridge_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("list_eventbridge_rules")
    def list_eventbridge_rules(
        region: str | None = None,
        event_bus_name: str | None = None,
        name_prefix: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """List EventBridge rules with target counts and target service summaries."""
        return list_eventbridge_rules_tool(
            runtime,
            region=region,
            event_bus_name=event_bus_name,
            name_prefix=name_prefix,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_eventbridge_time_sources")
    def get_eventbridge_time_sources(
        region: str | None = None,
        event_bus_name: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Summarize EventBridge schedules, archives, replays, and Scheduler schedules."""
        return get_eventbridge_time_sources_tool(
            runtime,
            region=region,
            event_bus_name=event_bus_name,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("explain_eventbridge_rule_dependencies")
    def explain_eventbridge_rule_dependencies(
        rule_name: str,
        event_bus_name: str | None = None,
        region: str | None = None,
        include_permission_checks: bool = True,
        max_permission_checks: int | None = None,
    ) -> dict[str, object]:
        """Map one EventBridge rule to targets, DLQs, roles, and permission checks."""
        return explain_eventbridge_rule_dependencies_tool(
            runtime,
            rule_name=rule_name,
            event_bus_name=event_bus_name,
            region=region,
            include_permission_checks=include_permission_checks,
            max_permission_checks=max_permission_checks,
        )

    @mcp.tool()
    @audit.tool("investigate_eventbridge_rule_delivery")
    def investigate_eventbridge_rule_delivery(
        rule_name: str,
        event_bus_name: str | None = None,
        region: str | None = None,
        since_minutes: int | None = 60,
    ) -> dict[str, object]:
        """Diagnose EventBridge delivery from config, metrics, DLQs, and permissions."""
        return investigate_eventbridge_rule_delivery_tool(
            runtime,
            rule_name=rule_name,
            event_bus_name=event_bus_name,
            region=region,
            since_minutes=since_minutes,
        )

    @mcp.tool()
    @audit.tool("audit_eventbridge_target_retry_dlq_safety")
    def audit_eventbridge_target_retry_dlq_safety(
        rule_name: str,
        event_bus_name: str | None = None,
        region: str | None = None,
        since_minutes: int | None = 60,
    ) -> dict[str, object]:
        """Audit EventBridge target retry, DLQ, and silent-drop safety."""
        return audit_eventbridge_target_retry_dlq_safety_tool(
            runtime,
            rule_name=rule_name,
            event_bus_name=event_bus_name,
            region=region,
            since_minutes=since_minutes,
        )

    @mcp.tool()
    @audit.tool("explain_event_driven_flow")
    def explain_event_driven_flow(
        name_fragment: str | None = None,
        event_source: str | None = None,
        detail_type: str | None = None,
        detail_path: str | None = None,
        detail_value: str | None = None,
        region: str | None = None,
        max_rules: int | None = 10,
    ) -> dict[str, object]:
        """Stitch EventBridge, Step Functions, and Lambda dependencies from intent fields."""
        return explain_event_driven_flow_tool(
            runtime,
            name_fragment=name_fragment,
            event_source=event_source,
            detail_type=detail_type,
            detail_path=detail_path,
            detail_value=detail_value,
            region=region,
            max_rules=max_rules,
        )


def _register_search_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("diagnose_region_partition_mismatches")
    def diagnose_region_partition_mismatches(
        resource_refs: list[str],
        expected_region: str | None = None,
        expected_partition: str | None = None,
        region: str | None = None,
    ) -> dict[str, object]:
        """Check resource references and endpoint overrides for region/partition drift."""
        return diagnose_region_partition_mismatches_tool(
            runtime,
            resource_refs=resource_refs,
            expected_region=expected_region,
            expected_partition=expected_partition,
            region=region,
        )

    @mcp.tool()
    @audit.tool("search_aws_resources")
    def search_aws_resources(
        query: str,
        services: list[str] | None = None,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Search known AWS resource names across safe read-only discovery tools."""
        return search_aws_resources_tool(
            runtime,
            query=query,
            services=services,
            region=region,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("search_aws_resources_by_tag")
    def search_aws_resources_by_tag(
        tag_key: str,
        tag_value: str | None = None,
        region: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, object]:
        """Search tagged resources and group them by service/resource type."""
        return search_aws_resources_by_tag_tool(
            runtime,
            tag_key=tag_key,
            tag_value=tag_value,
            region=region,
            max_results=max_results,
        )

    @mcp.tool()
    @audit.tool("get_cross_service_incident_brief")
    def get_cross_service_incident_brief(
        query: str,
        region: str | None = None,
        max_matches: int | None = None,
    ) -> dict[str, object]:
        """Compose a bounded incident brief from existing safe discovery tools."""
        return get_cross_service_incident_brief_tool(
            runtime,
            query=query,
            region=region,
            max_matches=max_matches,
        )

    @mcp.tool()
    @audit.tool("build_log_signal_correlation_timeline")
    def build_log_signal_correlation_timeline(
        query: str,
        region: str | None = None,
        max_matches: int | None = None,
    ) -> dict[str, object]:
        """Build a bounded timeline from alarms and Lambda log signals."""
        return build_log_signal_correlation_timeline_tool(
            runtime,
            query=query,
            region=region,
            max_matches=max_matches,
        )

    @mcp.tool()
    @audit.tool("plan_end_to_end_transaction_trace")
    def plan_end_to_end_transaction_trace(
        seed_resource: str,
        region: str | None = None,
        max_matches: int | None = None,
    ) -> dict[str, object]:
        """Return an ordered transaction trace plan from a seed resource name."""
        return plan_end_to_end_transaction_trace_tool(
            runtime,
            seed_resource=seed_resource,
            region=region,
            max_matches=max_matches,
        )

    @mcp.tool()
    @audit.tool("get_risk_scored_dependency_health_summary")
    def get_risk_scored_dependency_health_summary(
        application_prefix: str,
        region: str | None = None,
        max_matches: int | None = None,
    ) -> dict[str, object]:
        """Score discovered application resources for dependency health risks."""
        return get_risk_scored_dependency_health_summary_tool(
            runtime,
            application_prefix=application_prefix,
            region=region,
            max_matches=max_matches,
        )

    @mcp.tool()
    @audit.tool("export_application_dependency_graph")
    def export_application_dependency_graph(
        application_prefix: str,
        region: str | None = None,
        max_matches: int | None = None,
    ) -> dict[str, object]:
        """Export a redacted application dependency graph from safe discovery."""
        return export_application_dependency_graph_tool(
            runtime,
            application_prefix=application_prefix,
            region=region,
            max_matches=max_matches,
        )

    @mcp.tool()
    @audit.tool("run_first_blocked_edge_incident")
    def run_first_blocked_edge_incident(
        seed_resource: str,
        symptom: str,
        region: str | None = None,
        max_matches: int | None = None,
    ) -> dict[str, object]:
        """Run bounded diagnostics and stop at the first blocked or unknown edge."""
        return run_first_blocked_edge_incident_tool(
            runtime,
            seed_resource=seed_resource,
            symptom=symptom,
            region=region,
            max_matches=max_matches,
        )

    @mcp.tool()
    @audit.tool("analyze_resource_policy_condition_mismatches")
    def analyze_resource_policy_condition_mismatches(
        source_arn: str,
        target_arn: str,
        condition_summaries: list[dict[str, object]],
    ) -> dict[str, object]:
        """Analyze redacted resource-policy source condition summaries."""
        return condition_mismatch_tool(
            source_arn=source_arn,
            target_arn=target_arn,
            condition_summaries=condition_summaries,
        )

    @mcp.tool()
    @audit.tool("audit_multi_region_drift_failover_readiness")
    def audit_multi_region_drift_failover_readiness(
        application_prefix: str,
        regions: list[str],
        max_matches: int | None = None,
    ) -> dict[str, object]:
        """Compare discovered application resources across regions for drift."""
        return multi_region_drift_tool(
            runtime,
            application_prefix=application_prefix,
            regions=regions,
            max_matches=max_matches,
        )

    @mcp.tool()
    @audit.tool("generate_application_health_narrative")
    def generate_application_health_narrative(
        application_prefix: str,
        region: str | None = None,
        max_matches: int | None = None,
    ) -> dict[str, object]:
        """Generate an incident-ready application health narrative."""
        return generate_application_health_narrative_tool(
            runtime,
            application_prefix=application_prefix,
            region=region,
            max_matches=max_matches,
        )
