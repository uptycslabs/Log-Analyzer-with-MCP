#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
from typing import List, Callable, Any, Type, Optional
from functools import wraps
import asyncio

from mcp.server.fastmcp import FastMCP

from .resources.cloudwatch_logs_resource import CloudWatchLogsResource
from .tools.search_tools import CloudWatchLogsSearchTools
from .tools.analysis_tools import CloudWatchLogsAnalysisTools
from .tools.correlation_tools import CloudWatchLogsCorrelationTools

# Parse command line arguments
parser = argparse.ArgumentParser(description="CloudWatch Logs Analyzer MCP Server")
parser.add_argument(
    "--profile", type=str, help="AWS profile name to use for credentials"
)
parser.add_argument("--region", type=str, help="AWS region name to use for API calls")
parser.add_argument(
    "--stateless", action="store_true", help="Stateless HTTP mode", default=False
)
parser.add_argument(
    "--no-default-creds",
    action="store_true",
    help="Disable default credential chain; require per-call credentials",
    default=False,
)
args, unknown = parser.parse_known_args()


# Create the MCP server for CloudWatch logs
mcp = FastMCP("CloudWatch Logs Analyzer", stateless_http=args.stateless)

# Initialize our resource and tools classes with the specified AWS profile and region
cw_resource = CloudWatchLogsResource(
    profile_name=args.profile,
    region_name=args.region,
    no_default_creds=args.no_default_creds,
)
search_tools = CloudWatchLogsSearchTools(
    profile_name=args.profile,
    region_name=args.region,
    no_default_creds=args.no_default_creds,
)
analysis_tools = CloudWatchLogsAnalysisTools(
    profile_name=args.profile,
    region_name=args.region,
    no_default_creds=args.no_default_creds,
)
correlation_tools = CloudWatchLogsCorrelationTools(
    profile_name=args.profile,
    region_name=args.region,
    no_default_creds=args.no_default_creds,
)

# Capture the parsed CLI profile and region in separate variables
default_profile = args.profile
default_region = args.region
no_default_creds = args.no_default_creds


# Helper decorator to handle profile, region, and AWS credentials for tools
def with_aws_config(tool_class: Type, method_name: Optional[str] = None) -> Callable:
    """
    Decorator that handles the profile, region, and AWS credentials for tool functions.
    Creates a new instance of the specified tool class with the correct credentials.

    When aws_access_key_id/aws_secret_access_key/aws_session_token are provided,
    they are used directly (e.g., from Juno's AssumeRole). Otherwise, falls back
    to profile/region or default credential chain.

    Args:
        tool_class: The class to instantiate with the credentials
        method_name: Optional method name if different from the decorated function
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            try:
                # Pop account_id - used by Juno for credential resolution, not by the tool itself
                kwargs.pop("account_id", None)
                profile = kwargs.pop("profile", None) or default_profile
                region = kwargs.pop("region", None) or default_region
                # Extract direct credential parameters (from Juno's AssumeRole)
                aws_access_key_id = kwargs.pop("aws_access_key_id", None)
                aws_secret_access_key = kwargs.pop("aws_secret_access_key", None)
                aws_session_token = kwargs.pop("aws_session_token", None)

                tool_instance = tool_class(
                    profile_name=profile,
                    region_name=region,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key,
                    aws_session_token=aws_session_token,
                    no_default_creds=no_default_creds,
                )
                target_method = method_name or func.__name__
                method = getattr(tool_instance, target_method)
                result = method(**kwargs)
                if asyncio.iscoroutine(result):
                    return await result
                return result
            except AttributeError as e:
                raise RuntimeError(
                    f"Method {target_method} not found in {tool_class.__name__}, {e}"
                ) from e
            except Exception as e:
                raise RuntimeError(
                    f"An error {e} occurred while executing {target_method} in {tool_class.__name__}"
                ) from e

        return wrapper

    return decorator


# ==============================
# Resource Handlers
# ==============================


@mcp.resource("logs://groups")
def get_log_groups() -> str:
    """Get a list of all CloudWatch Log Groups"""
    # Use default values for parameters
    prefix = None
    limit = 50
    next_token = None

    return cw_resource.get_log_groups(prefix, limit, next_token)


@mcp.resource("logs://groups/filter/{prefix}")
def get_filtered_log_groups(prefix: str) -> str:
    """
    Get a filtered list of CloudWatch Log Groups by prefix

    Args:
        prefix: The prefix to filter log groups by
    """
    # Default values for other parameters
    limit = 50
    next_token = None

    return cw_resource.get_log_groups(prefix, limit, next_token)


@mcp.resource("logs://groups/{log_group_name}")
def get_log_group_details(log_group_name: str) -> str:
    """Get detailed information about a specific log group"""
    return cw_resource.get_log_group_details(log_group_name)


@mcp.resource("logs://groups/{log_group_name}/streams")
def get_log_streams(log_group_name: str) -> str:
    """
    Get a list of log streams for a specific log group

    Args:
        log_group_name: The name of the log group
    """
    # Use default limit value
    limit = 20
    return cw_resource.get_log_streams(log_group_name, limit)


@mcp.resource("logs://groups/{log_group_name}/streams/{log_stream_name}")
def get_log_events(log_group_name: str, log_stream_name: str) -> str:
    """
    Get log events from a specific log stream

    Args:
        log_group_name: The name of the log group
        log_stream_name: The name of the log stream
    """
    # Use default limit value
    limit = 100
    return cw_resource.get_log_events(log_group_name, log_stream_name, limit)


@mcp.resource("logs://groups/{log_group_name}/sample")
def get_log_sample(log_group_name: str) -> str:
    """
    Get a sample of recent logs from a log group

    Args:
        log_group_name: The name of the log group
    """
    # Use default limit value
    limit = 10
    return cw_resource.get_log_sample(log_group_name, limit)


@mcp.resource("logs://groups/{log_group_name}/recent-errors")
def get_recent_errors(log_group_name: str) -> str:
    """
    Get recent error logs from a log group

    Args:
        log_group_name: The name of the log group
    """
    # Use default hours value
    hours = 24
    return cw_resource.get_recent_errors(log_group_name, hours)


@mcp.resource("logs://groups/{log_group_name}/metrics")
def get_log_metrics(log_group_name: str) -> str:
    """
    Get log volume metrics for a log group

    Args:
        log_group_name: The name of the log group
    """
    # Use default hours value
    hours = 24
    return cw_resource.get_log_metrics(log_group_name, hours)


@mcp.resource("logs://groups/{log_group_name}/structure")
def analyze_log_structure(log_group_name: str) -> str:
    """Analyze and provide information about the structure of logs"""
    return cw_resource.analyze_log_structure(log_group_name)


# ==============================
# Prompts
# ==============================


@mcp.prompt()
def list_cloudwatch_log_groups(
    prefix: str = None, profile: str = None, region: str = None
) -> str:
    """
    Prompt for listing and exploring CloudWatch log groups.

    Args:
        prefix: Optional prefix to filter log groups by name
        profile: Optional AWS profile name to use for credentials
        region: Optional AWS region name to use for API calls
    """
    profile_text = f" using profile '{profile}'" if profile else ""
    region_text = f" in region '{region}'" if region else ""
    prefix_text = f" with prefix '{prefix}'" if prefix else ""

    return f"""I'll help you explore the CloudWatch log groups in your AWS environment{profile_text}{region_text}.

First, I'll list the available log groups{prefix_text}.

For each log group, I can help you:
1. Get detailed information about the group (retention, size, etc.)
2. Check for recent errors or patterns
3. View metrics like volume and activity
4. Sample recent logs to understand the content
5. Search for specific patterns or events

Let me know which log group you'd like to explore further, or if you'd like to refine the search with a different prefix.
"""


@mcp.prompt()
def analyze_cloudwatch_logs(
    log_group_name: str, profile: str = None, region: str = None
) -> str:
    """
    Prompt for analyzing CloudWatch logs to help identify issues, patterns, and insights.

    Args:
        log_group_name: The name of the log group to analyze
        profile: Optional AWS profile name to use for credentials
        region: Optional AWS region name to use for API calls
    """
    profile_text = f" using profile '{profile}'" if profile else ""
    region_text = f" in region '{region}'" if region else ""

    return f"""Please analyze the following CloudWatch logs from the {log_group_name} log group{profile_text}{region_text}.

First, I'll get you some information about the log group:
1. Get the basic log group structure to understand the format of logs
2. Check for any recent errors
3. Examine the log volume metrics
4. Analyze a sample of recent logs

Based on this information, please:
- Identify any recurring errors or exceptions
- Look for unusual patterns or anomalies
- Suggest possible root causes for any issues found
- Recommend actions to resolve or mitigate problems
- Provide insights on performance or resource utilization

Feel free to ask for additional context if needed, such as:
- Correlation with logs from other services
- More specific time ranges for analysis
- Queries for specific error messages or events
"""


# ==============================
# Tool Handlers
# ==============================


@mcp.tool()
@with_aws_config(CloudWatchLogsResource, method_name="get_log_groups")
async def list_log_groups(
    account_id: str,
    region: str,
    prefix: str = None,
    limit: int = 50,
    next_token: str = None,
    profile: str = None,
    aws_access_key_id: str = None,
    aws_secret_access_key: str = None,
    aws_session_token: str = None,
) -> str:
    """
    List available CloudWatch log groups with optional filtering by prefix.

    Args:
        account_id: AWS account ID for the target account
        region: AWS region name (e.g., us-east-1, eu-west-1)
        prefix: Optional prefix to filter log groups by name
        limit: Maximum number of log groups to return (default: 50)
        next_token: Token for pagination to get the next set of results

    Returns:
        JSON string with log groups information
    """
    # Function body is handled by the decorator
    pass


@mcp.tool()
@with_aws_config(CloudWatchLogsSearchTools)
async def search_logs(
    account_id: str,
    region: str,
    log_group_name: str,
    query: str,
    hours: int = 24,
    start_time: str = None,
    end_time: str = None,
    profile: str = None,
    aws_access_key_id: str = None,
    aws_secret_access_key: str = None,
    aws_session_token: str = None,
) -> str:
    """
    Search logs using CloudWatch Logs Insights query.

    Args:
        account_id: AWS account ID for the target account
        region: AWS region name (e.g., us-east-1, eu-west-1)
        log_group_name: The log group to search
        query: CloudWatch Logs Insights query syntax
        hours: Number of hours to look back
        start_time: Optional ISO8601 start time
        end_time: Optional ISO8601 end time

    Returns:
        JSON string with search results
    """
    # Function body is handled by the decorator
    pass


@mcp.tool()
@with_aws_config(CloudWatchLogsSearchTools)
async def search_logs_multi(
    account_id: str,
    region: str,
    log_group_names: List[str],
    query: str,
    hours: int = 24,
    start_time: str = None,
    end_time: str = None,
    profile: str = None,
    aws_access_key_id: str = None,
    aws_secret_access_key: str = None,
    aws_session_token: str = None,
) -> str:
    """
    Search logs across multiple log groups using CloudWatch Logs Insights.

    Args:
        account_id: AWS account ID for the target account
        region: AWS region name (e.g., us-east-1, eu-west-1)
        log_group_names: List of log groups to search
        query: CloudWatch Logs Insights query in Logs Insights syntax
        hours: Number of hours to look back (default: 24)
        start_time: Optional ISO8601 start time
        end_time: Optional ISO8601 end time

    Returns:
        JSON string with search results
    """
    # Function body is handled by the decorator
    pass


@mcp.tool()
@with_aws_config(CloudWatchLogsSearchTools)
async def filter_log_events(
    account_id: str,
    region: str,
    log_group_name: str,
    filter_pattern: str,
    hours: int = 24,
    start_time: str = None,
    end_time: str = None,
    profile: str = None,
    aws_access_key_id: str = None,
    aws_secret_access_key: str = None,
    aws_session_token: str = None,
) -> str:
    """
    Filter log events by pattern across all streams in a log group.

    Args:
        account_id: AWS account ID for the target account
        region: AWS region name (e.g., us-east-1, eu-west-1)
        log_group_name: The log group to filter
        filter_pattern: The pattern to search for (CloudWatch Logs filter syntax)
        hours: Number of hours to look back
        start_time: Optional ISO8601 start time
        end_time: Optional ISO8601 end time

    Returns:
        JSON string with filtered events
    """
    # Function body is handled by the decorator
    pass


@mcp.tool()
@with_aws_config(CloudWatchLogsAnalysisTools)
async def summarize_log_activity(
    account_id: str,
    region: str,
    log_group_name: str,
    hours: int = 24,
    start_time: str = None,
    end_time: str = None,
    profile: str = None,
    aws_access_key_id: str = None,
    aws_secret_access_key: str = None,
    aws_session_token: str = None,
) -> str:
    """
    Generate a summary of log activity over a specified time period.

    Args:
        account_id: AWS account ID for the target account
        region: AWS region name (e.g., us-east-1, eu-west-1)
        log_group_name: The log group to analyze
        hours: Number of hours to look back
        start_time: Optional ISO8601 start time
        end_time: Optional ISO8601 end time

    Returns:
        JSON string with activity summary
    """
    # Function body is handled by the decorator
    pass


@mcp.tool()
@with_aws_config(CloudWatchLogsAnalysisTools)
async def find_error_patterns(
    account_id: str,
    region: str,
    log_group_name: str,
    hours: int = 24,
    start_time: str = None,
    end_time: str = None,
    profile: str = None,
    aws_access_key_id: str = None,
    aws_secret_access_key: str = None,
    aws_session_token: str = None,
) -> str:
    """
    Find common error patterns in logs.

    Args:
        account_id: AWS account ID for the target account
        region: AWS region name (e.g., us-east-1, eu-west-1)
        log_group_name: The log group to analyze
        hours: Number of hours to look back
        start_time: Optional ISO8601 start time
        end_time: Optional ISO8601 end time

    Returns:
        JSON string with error patterns
    """
    # Function body is handled by the decorator
    pass


@mcp.tool()
@with_aws_config(CloudWatchLogsCorrelationTools)
async def correlate_logs(
    account_id: str,
    region: str,
    log_group_names: List[str],
    search_term: str,
    hours: int = 24,
    start_time: str = None,
    end_time: str = None,
    profile: str = None,
    aws_access_key_id: str = None,
    aws_secret_access_key: str = None,
    aws_session_token: str = None,
) -> str:
    """
    Correlate logs across multiple AWS services using a common search term.

    Args:
        account_id: AWS account ID for the target account
        region: AWS region name (e.g., us-east-1, eu-west-1)
        log_group_names: List of log group names to search
        search_term: Term to search for in logs (request ID, transaction ID, etc.)
        hours: Number of hours to look back
        start_time: Optional ISO8601 start time
        end_time: Optional ISO8601 end time

    Returns:
        JSON string with correlated events
    """
    # Function body is handled by the decorator
    pass


def main() -> None:
    # Run the MCP server
    mcp.run()


if __name__ == "__main__":
    main()
