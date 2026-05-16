from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aws_safe_mcp.audit import AuditLogger
from aws_safe_mcp.auth import AwsRuntime
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
from aws_safe_mcp.tools.cloudwatch import cloudwatch_log_search as cloudwatch_log_search_tool
from aws_safe_mcp.tools.cloudwatch import (
    cloudwatch_logs_insights_query as cloudwatch_logs_insights_query_tool,
)
from aws_safe_mcp.tools.cloudwatch import (
    get_cloudwatch_alarm_summary as get_cloudwatch_alarm_summary_tool,
)
from aws_safe_mcp.tools.cloudwatch import list_cloudwatch_alarms as list_cloudwatch_alarms_tool
from aws_safe_mcp.tools.cloudwatch import (
    list_cloudwatch_log_groups as list_cloudwatch_log_groups_tool,
)
from aws_safe_mcp.tools.dynamodb import (
    dynamodb_table_summary as dynamodb_table_summary_tool,
)
from aws_safe_mcp.tools.dynamodb import list_dynamodb_tables as list_dynamodb_tables_tool
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
from aws_safe_mcp.tools.identity import aws_auth_status as get_aws_auth_status
from aws_safe_mcp.tools.identity import aws_identity as get_aws_identity
from aws_safe_mcp.tools.lambda_tools import (
    check_lambda_permission_path as check_lambda_permission_path_tool,
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
    investigate_lambda_failure as investigate_lambda_failure_tool,
)
from aws_safe_mcp.tools.lambda_tools import (
    list_lambda_functions as list_lambda_functions_tool,
)
from aws_safe_mcp.tools.resource_search import search_aws_resources as search_aws_resources_tool
from aws_safe_mcp.tools.s3 import get_s3_bucket_summary as get_s3_bucket_summary_tool
from aws_safe_mcp.tools.s3 import list_s3_buckets as list_s3_buckets_tool
from aws_safe_mcp.tools.s3 import list_s3_objects as list_s3_objects_tool
from aws_safe_mcp.tools.sns import (
    explain_sns_topic_dependencies as explain_sns_topic_dependencies_tool,
)
from aws_safe_mcp.tools.sns import get_sns_topic_summary as get_sns_topic_summary_tool
from aws_safe_mcp.tools.sns import list_sns_topics as list_sns_topics_tool
from aws_safe_mcp.tools.sqs import (
    explain_sqs_queue_dependencies as explain_sqs_queue_dependencies_tool,
)
from aws_safe_mcp.tools.sqs import get_sqs_queue_summary as get_sqs_queue_summary_tool
from aws_safe_mcp.tools.sqs import list_sqs_queues as list_sqs_queues_tool
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
    _register_lambda_tools(mcp, audit, runtime)
    _register_step_functions_tools(mcp, audit, runtime)
    _register_s3_tools(mcp, audit, runtime)
    _register_sqs_tools(mcp, audit, runtime)
    _register_sns_tools(mcp, audit, runtime)
    _register_dynamodb_tools(mcp, audit, runtime)
    _register_cloudwatch_tools(mcp, audit, runtime)
    _register_api_gateway_tools(mcp, audit, runtime)
    _register_eventbridge_tools(mcp, audit, runtime)
    _register_search_tools(mcp, audit, runtime)
    return mcp


def _register_identity_tools(mcp: FastMCP, audit: AuditLogger, runtime: AwsRuntime) -> None:
    @mcp.tool()
    @audit.tool("aws_auth_status")
    def aws_auth_status() -> dict[str, str | bool | None]:
        """Quickly show whether AWS auth is valid and which principal is active."""
        return get_aws_auth_status(runtime)

    @mcp.tool()
    @audit.tool("aws_identity")
    def aws_identity() -> dict[str, str | bool | None]:
        """Show authenticated AWS account, ARN, profile, region, and read-only mode."""
        return get_aws_identity(runtime)


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
    ) -> dict[str, object]:
        """Trace inferred internet and private network reachability for one Lambda."""
        return explain_lambda_network_access_tool(
            runtime,
            function_name=function_name,
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
    @audit.tool("dynamodb_table_summary")
    def dynamodb_table_summary(
        table_name: str,
        region: str | None = None,
    ) -> dict[str, object]:
        """Summarize one DynamoDB table without scans or item reads."""
        return dynamodb_table_summary_tool(
            runtime,
            table_name=table_name,
            region=region,
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
    @audit.tool("cloudwatch_log_search")
    def cloudwatch_log_search(
        log_group_name: str,
        query: str,
        since_minutes: int | None = 60,
        max_results: int | None = 50,
        region: str | None = None,
    ) -> dict[str, object]:
        """Search one CloudWatch log group with bounded filter_log_events."""
        return cloudwatch_log_search_tool(
            runtime,
            log_group_name=log_group_name,
            query=query,
            since_minutes=since_minutes,
            max_results=max_results,
            region=region,
        )

    @mcp.tool()
    @audit.tool("cloudwatch_logs_insights_query")
    def cloudwatch_logs_insights_query(
        log_group_name: str,
        query: str,
        since_minutes: int | None = 60,
        max_results: int | None = 50,
        region: str | None = None,
    ) -> dict[str, object]:
        """Run a bounded Logs Insights query against one log group."""
        return cloudwatch_logs_insights_query_tool(
            runtime,
            log_group_name=log_group_name,
            query=query,
            since_minutes=since_minutes,
            max_results=max_results,
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
