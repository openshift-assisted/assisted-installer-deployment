import argparse
import logging
import os
from typing import Callable, Final

import jira
from retry import retry

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

    result_list = apply_function_with_retry(
        jira_client.search_issues,
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
    successfully_updated_issues: set[str] = set()
    unsuccessfully_updated_issues: set[str] = set()

    for issue in issues:
        for watcher in apply_function_with_retry(jira_client.watchers, issue).watchers:
            if not watcher.active:
                continue
            try:
                apply_function_with_retry(jira_client.remove_watcher, issue.key, watcher.name)
                logger.debug(f"Removed watcher {watcher.name} from issue {issue.key}.")
            except jira.JIRAError as e:
                logger.debug(f"Failed to remove watcher {watcher.name} from issue {issue.key}: ", exc_info=str(e))
                errors.append(e)
                unsuccessfully_updated_issues.add(issue.key)

        for attachment in issue.fields.attachment:
            try:
                apply_function_with_retry(jira_client.delete_attachment, attachment.id)
                logger.debug(f"Removed attachment {attachment.filename} from issue {issue.key}.")
            except jira.JIRAError as e:
                logger.debug(
                    f"Failed to remove attachment {attachment.filename} from issue {issue.key}: ", exc_info=str(e)
                )
                errors.append(e)
                unsuccessfully_updated_issues.add(issue.key)

        try:
            apply_function_with_retry(jira_client.transition_issue, issue.key, CLOSED_STATUS)
            logger.debug(f"Closed issue {issue.key}.")
        except jira.JIRAError as e:
            logger.debug(f"Failed to close issue {issue.key}:", exc_info=str(e))
            errors.append(e)
            unsuccessfully_updated_issues.add(issue.key)

    logger.info("failed to update issues:")
    for issue_key in unsuccessfully_updated_issues:
        logger.info(issue_key)
    successfully_updated_issues = {issue.key for issue in issues} - unsuccessfully_updated_issues
    logger.info("successfully updates issues:")
    for issue_key in successfully_updated_issues:
        logger.info(issue_key)

    if errors:
        for error in errors:
            logger.exception("Error while updating issue in Jira.", exc_info=error)
        raise ExceptionGroup("Failed to update all issues.", errors)


@retry(exceptions=jira.JIRAError, tries=3, delay=1)
def apply_function_with_retry(function: Callable, *args, **kwargs):
    return function(*args, **kwargs)


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


if __name__ == "__main__":
    main()
