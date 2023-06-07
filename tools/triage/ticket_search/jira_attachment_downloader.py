import datetime
import logging
import os

import jira

from tools.triage.ticket_search.cli.workflow_data import WorkflowData
from tools.triage.ticket_search.issue_cache import IssueCache
from tools.triage.ticket_search.settings import DATA_DIRECTORY
from tools.triage.ticket_search.timer import Timer
from tools.triage.utils.extraction import GzipFileExtractor, ShutilExtractor

from .action_extract_archive import ActionExtractArchive
from .file_path_recursor import FilePathRecursor


class JiraAttachmentDownloader:
    """Downloads Jira attachments for a ticket and extracts their contents"""

    def __init__(self, jira_client: jira.JIRA, workflow_data: WorkflowData, issue_cache: "IssueCache"):
        """Constructor"""
        self.extraction_recursor = FilePathRecursor(
            on_file_action_class=ActionExtractArchive(extractors=[ShutilExtractor(), GzipFileExtractor()]),
            recurse_after_action=True,
        )
        self.jira_client = jira_client
        self.workflow_data = workflow_data
        self.issue_cache = issue_cache
        self.logger = logging.getLogger(__name__)

    def download_attachments_for_ticket(self, issue):
        # If we already have the issue in cache, no need to do anything further
        if self.issue_cache.exists(issue.key):
            return
        timer = Timer()
        self.logger.info(f"Downloading {issue.key} as it is not present in the cache {timer.get_start_time()}")
        try:
            destination_path = os.path.join(f"{DATA_DIRECTORY}", issue.key)
            if os.path.exists(destination_path):
                # If the directory has already been downloaded from the issue then skip it
                self.logger.info(
                    f"Skipping download for {issue.key} as this has already been downloaded. {datetime.datetime.now()}"
                )
                return
            if not os.path.exists(destination_path):
                os.mkdir(destination_path)
            if len(issue.fields.attachment) > 0:
                for attachment in issue.fields.attachment:
                    # We occasionally get an issue here if the server is busy, does not appear to be possible to detect this easily.
                    # Downloaded content will be the HTML for a Jira error page but I don't think we have access to response code.
                    # Official docs do not appear to show any error handling.
                    # https://jira.readthedocs.io/examples.html#attachments
                    # Might be better to use http API to obtain download URL and use the requests library so that we can obtain status codes etc.
                    content = attachment.get()
                    filename = os.path.join(destination_path, attachment.filename)
                    with open(filename, "wb") as out:
                        out.write(content, "utf-8")
            else:
                if "tickets_without_logs" not in self.workflow_data:
                    self.workflow_data["tickets_without_logs"] = 0
                self.workflow_data["tickets_without_logs"] += 1

        except (Exception, OSError) as e:
            self.logger.error(f"Unable to download attachments for issue {issue.key} due to error {e}")
            if e is not None:
                raise e
        timer.end()
        self.logger.info(
            f"Finished downloading {issue.key} (took {timer.get_duration()} seconds) \nStarting extraction {timer.get_end_time()}"
        )
        timer.reset_and_start()
        self.extraction_recursor.recurse(destination_path)
        timer.end()
        self.logger.info(
            f"Finished extracting {issue.key} {timer.get_end_time()} (took {timer.get_duration()} seconds)"
        )
        self.logger.info(f"Downloading + Extraction took {timer.get_cumulative_duration()} seconds")
