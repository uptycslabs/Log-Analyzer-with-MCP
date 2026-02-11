#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import asyncio
import boto3
import json
from datetime import datetime

from . import handle_exceptions
from .utils import get_time_range


class CloudWatchLogsAnalysisTools:
    """Tools for analyzing CloudWatch Logs data."""

    def __init__(self, profile_name=None, region_name=None,
                 aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None,
                 no_default_creds=False):
        """Initialize the CloudWatch Logs client.

        Args:
            profile_name: Optional AWS profile name to use for credentials
            region_name: Optional AWS region name to use for API calls
            aws_access_key_id: Optional AWS access key ID (for direct credential injection)
            aws_secret_access_key: Optional AWS secret access key (for direct credential injection)
            aws_session_token: Optional AWS session token (for temporary credentials)
            no_default_creds: If True, require explicit credentials and never use default chain
        """
        self.profile_name = profile_name
        self.region_name = region_name
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token
        self.no_default_creds = no_default_creds

        # Lazy initialization - only create client when needed
        self._session = None
        self._logs_client = None

    def _get_session(self):
        """Get or create a boto3 session with the configured credentials."""
        if self._session is None:
            if self.aws_access_key_id and self.aws_secret_access_key:
                # Use directly provided credentials (e.g., from Juno's AssumeRole)
                self._session = boto3.Session(
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key,
                    aws_session_token=self.aws_session_token,
                    region_name=self.region_name
                )
            elif self.no_default_creds:
                # Explicit credentials required but not provided
                raise ValueError(
                    "No credentials provided. When --no-default-creds is set, "
                    "aws_access_key_id and aws_secret_access_key must be provided."
                )
            else:
                # Use specified profile/region or default credential chain
                self._session = boto3.Session(
                    profile_name=self.profile_name, region_name=self.region_name
                )
        return self._session

    @property
    def logs_client(self):
        """Lazy initialization of CloudWatch Logs client."""
        if self._logs_client is None:
            self._logs_client = self._get_session().client("logs")
        return self._logs_client

    @handle_exceptions
    async def summarize_log_activity(
        self,
        log_group_name: str,
        hours: int = 24,
        start_time: str = None,
        end_time: str = None,
    ) -> str:
        """
        Generate a summary of log activity over a specified time period.

        Args:
            log_group_name: The log group to analyze
            hours: Number of hours to look back
            start_time: Start time in ISO8601 format
            end_time: End time in ISO8601 format

        Returns:
            JSON string with activity summary
        """
        start_ts, end_ts = get_time_range(hours, start_time, end_time)

        # Use CloudWatch Logs Insights to get a summary
        query = """
        stats count(*) as logEvents,
              count_distinct(stream) as streams
        | sort @timestamp desc
        | limit 1000
        """

        # Start the query
        start_query_response = self.logs_client.start_query(
            logGroupName=log_group_name,
            startTime=start_ts,
            endTime=end_ts,
            queryString=query,
        )

        query_id = start_query_response["queryId"]

        # Poll for query results
        response = None
        while response is None or response["status"] == "Running":
            await asyncio.sleep(1)  # Wait before checking again
            response = self.logs_client.get_query_results(queryId=query_id)

        # Get the hourly distribution
        hourly_query = """
        stats count(*) as count by bin(1h)
        | sort @timestamp desc
        | limit 24
        """

        # Start the hourly query
        hourly_query_response = self.logs_client.start_query(
            logGroupName=log_group_name,
            startTime=start_ts,
            endTime=end_ts,
            queryString=hourly_query,
        )

        hourly_query_id = hourly_query_response["queryId"]

        # Poll for hourly query results
        hourly_response = None
        while hourly_response is None or hourly_response["status"] == "Running":
            await asyncio.sleep(1)  # Wait before checking again
            hourly_response = self.logs_client.get_query_results(
                queryId=hourly_query_id
            )

        # Process the main summary results
        summary = {
            "timeRange": {
                "start": datetime.fromtimestamp(start_ts / 1000).isoformat(),
                "end": datetime.fromtimestamp(end_ts / 1000).isoformat(),
                "hours": hours,
            },
            "logEvents": 0,
            "uniqueStreams": 0,
            "hourlyDistribution": [],
        }

        # Extract the main stats
        for result in response.get("results", []):
            for field in result:
                if field["field"] == "logEvents":
                    summary["logEvents"] = int(field["value"])
                elif field["field"] == "streams":
                    summary["uniqueStreams"] = int(field["value"])

        # Extract the hourly distribution
        for result in hourly_response.get("results", []):
            hour_data = {}
            for field in result:
                if field["field"] == "bin(1h)":
                    hour_data["hour"] = field["value"]
                elif field["field"] == "count":
                    hour_data["count"] = int(field["value"])

            if hour_data:
                summary["hourlyDistribution"].append(hour_data)

        return json.dumps(summary, indent=2)

    @handle_exceptions
    async def find_error_patterns(
        self,
        log_group_name: str,
        hours: int = 24,
        start_time: str = None,
        end_time: str = None,
    ) -> str:
        """
        Find common error patterns in logs.

        Args:
            log_group_name: The log group to analyze
            hours: Number of hours to look back
            start_time: Start time in ISO8601 format
            end_time: End time in ISO8601 format

        Returns:
            JSON string with error patterns
        """
        start_ts, end_ts = get_time_range(hours, start_time, end_time)

        # Query for error logs
        error_query = """
        filter @message like /(?i)(error|exception|fail|traceback)/
        | stats count(*) as errorCount by @message
        | sort errorCount desc
        | limit 20
        """

        # Start the query
        start_query_response = self.logs_client.start_query(
            logGroupName=log_group_name,
            startTime=start_ts,
            endTime=end_ts,
            queryString=error_query,
        )

        query_id = start_query_response["queryId"]

        # Poll for query results
        response = None
        while response is None or response["status"] == "Running":
            await asyncio.sleep(1)  # Wait before checking again
            response = self.logs_client.get_query_results(queryId=query_id)

        # Process the results
        error_patterns = {
            "timeRange": {
                "start": datetime.fromtimestamp(start_ts / 1000).isoformat(),
                "end": datetime.fromtimestamp(end_ts / 1000).isoformat(),
                "hours": hours,
            },
            "errorPatterns": [],
        }

        for result in response.get("results", []):
            pattern = {}
            for field in result:
                if field["field"] == "@message":
                    pattern["message"] = field["value"]
                elif field["field"] == "errorCount":
                    pattern["count"] = int(field["value"])

            if pattern:
                error_patterns["errorPatterns"].append(pattern)

        return json.dumps(error_patterns, indent=2)
