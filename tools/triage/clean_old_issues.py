import argparse
import logging
import os
from typing import Final

import jira

from tools.jira_client import JiraClientFactory
from tools.jira_client.consts import CLOSED_STATUS
from tools.triage.common import JIRA_PROJECT

LOG_LEVEL_DEFAULT: Final[str] = "INFO"
ISSUES_LIMIT_DEFAULT: Final[int] = 50
DAYS_DEFAULT: Final[int] = 180


def get_logger(log_level: str) -> logging.Logger:
    """
    Args:
        log_level: log level

    Returns:
        formatted logger with log-level.
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(stream_handler)

    return logger


def fetch_issues_from_jira(
    jira_client: jira.JIRA,
    jira_project_key: str,
    logger: logging.Logger,
    created_before: int = DAYS_DEFAULT,
    issues_limit: int = ISSUES_LIMIT_DEFAULT,
) -> list[jira.Issue]:
    """Fetches and returns all issues from a given Jira project which created at least created_before days.

    Args:
        jira_client: Jira client for interacting with Jira API.
        jira_project_key: Jira Project's key to fetch issues from.
        logger: Logger.
        created_before: Created before at least created_before days old.
        issues_limit: Maximum number of issues.

    Returns:
        list of matching issues.
    """

    result_list = jira_client.search_issues(
        f"project = {jira_project_key} AND attachments IS NOT EMPTY AND created <= -{created_before}d",
        maxResults=issues_limit,
    )
    logger.info(f"Found {len(result_list)} issues")

    return list(result_list)


def update_issues(jira_client: jira.JIRA, issues: list[jira.Issue], logger: logging.Logger):
    """Removes watchers & attachments from given issues and then closes them.

    Args:
        jira_client: Jira client for interacting with Jira API.
        issues: Given issues.
        logger: Logger.

    Raises:
        ExceptionGroup: when jira client fails to remove a watcher or attachment from an issue, or when it fails to close an issue.
    """

    errors = []

    for issue in issues:
        for watcher in jira_client.watchers(issue).watchers:
            try:
                jira_client.remove_watcher(issue.key, watcher.name)
                logger.debug(f"Removed watcher {watcher.name} from issue {issue.key}.")
            except jira.JIRAError as e:
                logger.debug(f"Failed to remove watcher {watcher.name} from issue {issue.key}: ", exc_info=str(e))
                errors.append(e)

        for attachment in issue.fields.attachment:
            try:
                jira_client.delete_attachment(attachment.id)
                logger.debug(f"Removed attachment {attachment.filename} from issue {issue.key}.")
            except jira.JIRAError as e:
                logger.debug(
                    f"Failed to remove attachment {attachment.filename} from issue {issue.key}: ", exc_info=str(e)
                )
                errors.append(e)

        try:
            jira_client.transition_issue(issue.key, CLOSED_STATUS)
            logger.debug(f"Closed issue {issue.key}.")
        except jira.JIRAError as e:
            logger.debug(f"Failed to close issue {issue.key}:", exc_info=str(e))
            errors.append(e)

    if errors:
        for error in errors:
            logger.exception("Error while updating issue in Jira.", exc_info=error)
        raise ExceptionGroup("Failed to update all issues.", errors)


def main():
    parser = argparse.ArgumentParser(
        description="Removing watchers & attachments from old issues and then closing them."
    )
    parser.add_argument(
        "--jira-access-token",
        type=str,
        default=os.environ.get("JIRA_ACCESS_TOKEN"),
        required=False,
        help="Personal access token for accessing Jira.",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=DAYS_DEFAULT,
        required=False,
        help="Age from which tickets are considered old and will be addressed in days.",
    )
    parser.add_argument(
        "--issues-limit",
        type=int,
        default=ISSUES_LIMIT_DEFAULT,
        required=False,
        help="Maximum number of issues to update.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=LOG_LEVEL_DEFAULT,
        required=False,
        help="Log level",
    )

    args = parser.parse_args()

    logger = get_logger(args.log_level.upper())

    if args.jira_access_token is None:
        raise RuntimeError("No Jira access token was given.")

    jira_client = JiraClientFactory.create(jira_access_token=args.jira_access_token)

    issues = fetch_issues_from_jira(
        jira_client=jira_client,
        jira_project_key=JIRA_PROJECT,
        created_before=args.days,
        logger=logger,
        issues_limit=args.issues_limit,
    )

    update_issues(jira_client=jira_client, issues=issues, logger=logger)

    logger.info("Successfully updated issues:")
    for issue in issues:
        logger.info(issue.key)


if __name__ == "__main__":
    main()
