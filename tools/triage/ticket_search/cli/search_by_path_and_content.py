"""Module for command line utility to fetch a single triage ticket"""
import argparse
import logging
import os

from tools.triage.ticket_search import ActionGrep, FilePathRecursor
from tools.triage.ticket_search.directory_cache import DirectoryCache
from tools.triage.ticket_search.settings import DATA_DIRECTORY

from .command import Command
from .workflow_data import WorkflowData


class SearchByPathAndContent(Command):
    """Responsible for fetching a single ticket for a triage issue"""

    def __init__(self):
        """Constructor"""
        self.args = []
        self.unknown_args = []
        self.issue_cache = DirectoryCache()
        self.logger = logging.getLogger(__name__)

    def get_command_key(self) -> str:
        return "search_by_path_and_content"

    def get_friendly_name(self) -> str:
        return "Search by path and content"

    def run(self, workflow_data: WorkflowData) -> WorkflowData:
        """This runs the command"""

        # Set up the recursor to grep directories.
        self.workflow_data = workflow_data
        content_regex = " ".join(self.args.content_search)

        path_regex = " ".join(self.args.path_search)
        self.workflow_data["content_search"] = content_regex
        self.workflow_data["path_search"] = path_regex

        # Set up the filsystem recursion to match only the path regex
        self.grep_recursor = FilePathRecursor(
            ActionGrep(content_regex, workflow_data), recurse_after_action=False, path_match_regex=path_regex
        )

        # Go through the downloaded Jira tickets and grep them for the desired content
        # If issue ID's have been supplied from a previous step, attempt to use those.

        root_dir = f"{DATA_DIRECTORY}"
        entries = {}
        if "issue_ids" not in workflow_data:
            entries = self.issue_cache.get_cached_issue_ids()
        else:
            entries = workflow_data["issue_ids"]
        count = 1
        self.logger.debug(f"{entries}")
        tickets = {}
        for entry in entries:
            # Load the metadata for this ticket back from the cache
            tickets[entry] = self.issue_cache.load_metadata(entry)
            # mself.workflow_data.load_ticket_metadata(entry)
            full_path = os.path.join(root_dir, entry)
            self.logger.debug(f"Processing entry {count}/{len(entries)} ({entry}) ({full_path})")
            self.grep_recursor.recurse(full_path)
            count += 1

        # Now go through the matches and aggregate counts
        if "matches" in workflow_data:
            for issue_id in workflow_data["matches"].keys():
                if "metadata" not in self.workflow_data["matches"][issue_id]:
                    self.workflow_data["matches"][issue_id]["metadata"] = {}

                    workflow_data.increment_count(
                        "openshift_version_counts", "matches", tickets[issue_id].openshift_version
                    )
                    workflow_data.increment_count("platform_type_counts", "matches", tickets[issue_id].platform_type)
                    self.workflow_data["matches"][issue_id]["metadata"]["openshift_version"] = tickets[
                        issue_id
                    ].openshift_version
                    self.workflow_data["matches"][issue_id]["metadata"]["platform_type"] = tickets[
                        issue_id
                    ].platform_type

                    if "olm_operators" not in self.workflow_data["matches"][issue_id]["metadata"]:
                        self.workflow_data["matches"][issue_id]["metadata"]["olm_operators"] = []
                    # olm_operators
                    for olm_operator in self.workflow_data["matches"][issue_id]["metadata"]["olm_operators"]:
                        workflow_data.increment_count("olm_operator_counts", "matches", olm_operator)
                        self.workflow_data["matches"][issue_id]["metadata"]["olm_operators"] += [olm_operator]

                    if "configured_features" not in self.workflow_data["matches"][issue_id]["metadata"]:
                        self.workflow_data["matches"][issue_id]["metadata"]["configured_features"] = []
                    # configured features
                    for configured_feature in self.workflow_data["matches"][issue_id]["metadata"][
                        "configured_features"
                    ]:
                        workflow_data.increment_count("configured_feature_counts", "matches", configured_feature)
                        self.workflow_data["matches"][issue_id]["metadata"]["configured_features"] += [
                            configured_feature
                        ]

        return self.workflow_data

    def process_arguments(self):
        """Process any command specific arguments"""
        parser = argparse.ArgumentParser(add_help=True)
        path_and_content_group = parser.add_argument_group(title="path and content search parameters")
        path_and_content_args = path_and_content_group.add_argument_group()
        path_and_content_args.add_argument(
            "-c",
            "--content_search",
            required=True,
            metavar="STRING",
            nargs="+",
            help="The text or regular expression for the file content filter",
        )
        path_and_content_args.add_argument(
            "-p",
            "--path_search",
            required=True,
            metavar="STRING",
            nargs="+",
            help="Path or regular expression for files to be checked for content",
        )
        path_and_content_args.add_argument(
            "-v",
            "--openshift_version",
            required=False,
            default=None,
            metavar="STRING",
            nargs="+",
            help="Filter by the specified openshift version",
        )
        self.args, self.unknown_args = parser.parse_known_args()
