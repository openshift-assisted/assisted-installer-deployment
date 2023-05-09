"""Module for command line utility to fetch a single triage ticket"""
import argparse
import logging
import os
import sys

from tools.jira_client import JiraClientFactory
from tools.triage.ticket_search import (
    JiraAttachmentDownloader,
    TicketFetcher,
    TicketParser,
    TicketQuery,
)
from tools.triage.ticket_search.directory_cache import DirectoryCache

from .command import Command
from .workflow_data import WorkflowData


class SearchForTickets(Command):
    """Responsible for fetching a single ticket for a triage issue"""

    def __init__(self):
        """Constructor"""
        self.args = []
        self.unknown_args = []
        self.logger = logging.getLogger(__name__)

    def get_command_key(self) -> str:
        return "search_for_tickets"

    def get_friendly_name(self) -> str:
        return "Search for tickets"

    def run(self, workflow_data: WorkflowData) -> WorkflowData:
        """This runs the command"""
        # Set up the ticket fetcher
        self.workflow_data = workflow_data
        # Adding dry_run_stream forces the client to be "read only"
        client = JiraClientFactory.create(self.args.jira_access_token, dry_run_stream=sys.stdout)
        directory_cache = DirectoryCache()
        jira_attachment_downloader = JiraAttachmentDownloader(client, workflow_data, directory_cache)
        ticket_parser = TicketParser(jira_attachment_downloader)
        ticket_fetcher = TicketFetcher(ticket_parser, client)

        # Set up the JQL query
        query = TicketQuery.create().days_query(self.args.days)
        if self.args.jql is not None:
            query = query.jql_clause(" ".join(self.args.jql))

        # Filter by openshift version if this has been provided
        if self.args.openshift_version is not None:
            query = query.openshift_version(self.args.openshift_version[0])
            self.workflow_data["filter_by_openshift_version"] = self.args.openshift_version[0]

        # After all options in the query have been processed, add the JQL to the workflow data
        self.workflow_data["jql"] = query.build()

        # Paginate and process the query
        # This causes the logs to be downloaded and extracted if this has not already been done
        page_size = 100
        total_number_of_items = ticket_fetcher.count_for_query(query)
        self.workflow_data["total_number_of_items"] = total_number_of_items
        self.workflow_data["tickets_without_logs"] = 0
        self.logger.debug(f"Total number of items: {total_number_of_items}")
        self.workflow_data["issue_ids"] = {}
        for startIndex in range(0, total_number_of_items, page_size):
            tickets = ticket_fetcher.fetch_page_by_query(query, page_size, startIndex)
            for ticket in tickets:
                # If we have already cached the ticket, this will be empty
                self.workflow_data["issue_ids"][ticket.key] = {}
                # Store some workflow metadata with the ticket so that it may be loaded if skipping search
                self.workflow_data.map_field_to_ticket(ticket.key, "openshift_version", ticket.openshift_version)
                self.workflow_data.map_field_to_ticket(ticket.key, "platform_type", ticket.platform_type)
                self.workflow_data.map_field_to_ticket(ticket.key, "olm_operators", ticket.olm_operators)
                self.workflow_data.map_field_to_ticket(ticket.key, "configured_features", ticket.configured_features)
                directory_cache.save_metadata(ticket)
        # Once all tickets have been downloaded, return the workflow data with the ID's processed
        return self.workflow_data

    def process_arguments(self):
        """Process any command specific arguments"""
        parser = argparse.ArgumentParser(add_help=True)
        login_group = parser.add_argument_group(title="login options")
        login_args = login_group.add_argument_group()
        login_args.add_argument(
            "--jira-access-token",
            default=os.environ.get("JIRA_ACCESS_TOKEN"),
            help="PAT (personal access token) for accessing Jira",
        )
        query_group = parser.add_argument_group(title="query parameters")
        query_args = query_group.add_argument_group()
        query_args.add_argument(
            "-j", "--jql", required=False, default=None, metavar="STRING", nargs="+", help="Additional JQL statement"
        )
        query_args.add_argument("-d", "--days", default=7, help="Number of days worth of tickets to pull")
        query_args.add_argument(
            "-v",
            "--openshift_version",
            required=False,
            default=None,
            metavar="STRING",
            nargs="+",
            help="Filter by the specified openshift version",
        )
        self.args, self.unknown_args = parser.parse_known_args()
