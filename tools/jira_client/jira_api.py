import logging

import retry
from jira import JIRA, JIRAError

from .consts import CLOSED_STATUS

logger = logging.getLogger(__name__)


class JiraAPI:
    def __init__(self, jira_client) -> None:
        self._jira_client: JIRA = jira_client

    def link_issue_to_root_issue(self, issue, root_issue):
        logger.info("Linking %s as related to %s", issue.key, root_issue.key)
        self._jira_client.create_issue_link("relates to", issue.key, root_issue.key)

    def close_issue(self, issue):
        logger.info("Closing issue %s", issue)
        self._jira_client.transition_issue(issue.key, CLOSED_STATUS)

    def link_and_close_issue(self, issue, linked_issue=None):
        if linked_issue:
            self.link_issue_to_root_issue(issue, linked_issue)
        self.close_issue(issue)

    @retry.retry(exceptions=JIRAError, tries=3, delay=2, logger=logger)  # being resilient to 401 statuses
    def get_issue_comments(self, issue):
        return self._jira_client.comments(issue)
