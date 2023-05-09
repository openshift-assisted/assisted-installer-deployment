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
)
from tools.triage.ticket_search.directory_cache import DirectoryCache

from .command import Command
from .workflow_data import WorkflowData


class FetchById(Command):
    """Responsible for fetching a single ticket for a triage issue"""

    def __init__(self):
        """Constructor"""
        self.args = []
        self.unknown_args = []
        self.logger = logging.getLogger(__name__)

    def get_command_key(self) -> str:
        return "fetch_by_id"

    def get_friendly_name(self) -> str:
        return "Fetch by ID"

    def run(self, workflow_data: WorkflowData) -> WorkflowData:
        """This runs the command"""
        self.workflow_data = workflow_data
        # Adding dry_run_stream forces the client to be "read only"
        client = JiraClientFactory.create(self.args.jira_access_token, dry_run_stream=sys.stdout)
        directory_cache = DirectoryCache()
        jira_attachment_downloader = JiraAttachmentDownloader(client, workflow_data)
        ticket_parser = TicketParser(jira_attachment_downloader)
        ticket_fetcher = TicketFetcher(ticket_parser, client, directory_cache)
        ticket = ticket_fetcher.fetch_single_ticket_by_key(self.args.issue_id)
        self.workflow_data["issue_ids"] = {}
        self.workflow_data["issue_ids"][self.args.issue_id] = {}
        self.workflow_data.map_field_to_ticket(ticket.key, "openshift_version", ticket.openshift_version)
        self.workflow_data.map_field_to_ticket(ticket.key, "platform_type", ticket.platform_type)
        self.workflow_data.map_field_to_ticket(ticket.key, "olm_operators", ticket.olm_operators)
        self.workflow_data.map_field_to_ticket(ticket.key, "configured_features", ticket.configured_features)
        directory_cache.save_metadata(ticket)
        # Once the ticket has been downloaded, return the workflow data with the ID processed
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
        query_group = parser.add_argument_group(title="query")
        query_args = query_group.add_argument_group()
        query_args.add_argument("--issue-id", required=True, help="JIRA issue ID for the triage ticket")
        self.args, self.unknown_args = parser.parse_known_args()
