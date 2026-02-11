#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import asyncio
import boto3
import json
import time
from datetime import datetime
from typing import List

from . import handle_exceptions
from .utils import get_time_range


class CloudWatchLogsSearchTools:
    """Tools for searching and querying CloudWatch Logs."""

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
    async def search_logs(
        self,
        log_group_name: str,
        query: str,
        hours: int = 24,
        start_time: str = None,
        end_time: str = None,
    ) -> str:
        """
        Search logs using CloudWatch Logs Insights query.

        Args:
            log_group_name: The log group to search
            query: CloudWatch Logs Insights query syntax
            hours: Number of hours to look back
            start_time: Start time in ISO8601 format
            end_time: End time in ISO8601 format

        Returns:
            JSON string with search results
        """
        return await self.search_logs_multi(
            [log_group_name], query, hours, start_time, end_time
        )

    @handle_exceptions
    async def search_logs_multi(
        self,
        log_group_names: List[str],
        query: str,
        hours: int = 24,
        start_time: str = None,
        end_time: str = None,
    ) -> str:
        """
        Search logs across multiple log groups using CloudWatch Logs Insights query.

        Args:
            log_group_names: List of log groups to search
            query: CloudWatch Logs Insights query syntax
            hours: Number of hours to look back
            start_time: Start time in ISO8601 format
            end_time: End time in ISO8601 format

        Returns:
            JSON string with search results
        """
        start_ts, end_ts = get_time_range(hours, start_time, end_time)
        # Start the query
        query_start_time = time.time()
        start_query_response = self.logs_client.start_query(
            logGroupNames=log_group_names,
            startTime=start_ts,
            endTime=end_ts,
            queryString=query,
            limit=100,
        )
        query_id = start_query_response["queryId"]

        # Poll for query results
        response = None
        while response is None or response["status"] == "Running":
            await asyncio.sleep(1)  # Wait before checking again
            response = self.logs_client.get_query_results(queryId=query_id)
            elapsed_time = time.time() - query_start_time

            # Avoid long-running queries
            if response["status"] == "Running":
                # Check if we've been running too long (60 seconds)
                if elapsed_time > 60:
                    return json.dumps(
                        {
                            "status": "Timeout",
                            "error": "Search query failed to complete within time limit",
                        },
                        indent=2,
                    )

        # Process and format the results
        formatted_results = {
            "status": response["status"],
            "statistics": response.get("statistics", {}),
            "searchedLogGroups": log_group_names,
            "results": [],
        }

        for result in response.get("results", []):
            result_dict = {}
            for field in result:
                result_dict[field["field"]] = field["value"]
            formatted_results["results"].append(result_dict)

        return json.dumps(formatted_results, indent=2)

    @handle_exceptions
    async def filter_log_events(
        self,
        log_group_name: str,
        filter_pattern: str,
        hours: int = 24,
        start_time: str = None,
        end_time: str = None,
    ) -> str:
        """
        Filter log events by pattern across all streams in a log group.

        Args:
            log_group_name: The log group to filter
            filter_pattern: The pattern to search for (CloudWatch Logs filter syntax)
            hours: Number of hours to look back
            start_time: Start time in ISO8601 format
            end_time: End time in ISO8601 format

        Returns:
            JSON string with filtered events
        """
        start_ts, end_ts = get_time_range(hours, start_time, end_time)
        response = self.logs_client.filter_log_events(
            logGroupName=log_group_name,
            filterPattern=filter_pattern,
            startTime=start_ts,
            endTime=end_ts,
            limit=100,
        )

        events = response.get("events", [])
        formatted_events = []

        for event in events:
            formatted_events.append(
                {
                    "timestamp": datetime.fromtimestamp(
                        event.get("timestamp", 0) / 1000
                    ).isoformat(),
                    "message": event.get("message"),
                    "logStreamName": event.get("logStreamName"),
                }
            )

        return json.dumps(formatted_events, indent=2)
