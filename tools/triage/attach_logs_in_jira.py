#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import tarfile
from functools import partial
from pathlib import Path
from typing import Optional

import jira
import retry

from tools.jira_client import JiraClientFactory
from tools.triage.common import get_or_create_triage_ticket
from tools.utils import days_ago

DEFAULT_DAYS_TO_ATTACH_LOGS = 3
JIRA_ATTACHMENT_MAX_SIZE = 50 * 2**20  # 50MiB

logger = logging.getLogger(__name__)
stream_handler = logging.StreamHandler(sys.stderr)
stream_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
logger.addHandler(stream_handler)


def _archive_dir(directory: Path) -> Path:
    archived_file = Path(f"{directory}.tar.gz")
    logger.info("Archiving directory %s to %s", directory, archived_file)
    with tarfile.open(archived_file, "w:gz") as tar:
        tar.add(directory, directory.name)

    return archived_file


def _split_file(path: Path, chunk_size: int) -> None:
    logger.info("Splitting %s to several files", path)
    with path.open("rb") as whole_file:
        read_chunk = partial(whole_file.read, chunk_size)
        for i, chunk in enumerate(iter(read_chunk, b"")):
            with open(f"{path}-part-{i}", "wb") as part_file:
                part_file.write(chunk)


@retry.retry(exceptions=jira.JIRAError, tries=3, logger=logger)
def _attach_logs_for_cluster(jira_client: jira.JIRA, cluster_logs_dir: Path):
    issue = get_or_create_triage_ticket(jira_client=jira_client, failure_id=cluster_logs_dir.name)

    for artifact in cluster_logs_dir.iterdir():
        if artifact.is_dir():
            if Path(f"{artifact}.tar.gz").exists():
                logger.debug("Skip archiving %s as it's already archived", artifact)
            else:
                artifact = _archive_dir(artifact)

        if artifact.stat().st_size > JIRA_ATTACHMENT_MAX_SIZE:
            _split_file(artifact, chunk_size=JIRA_ATTACHMENT_MAX_SIZE)

    for artifact in cluster_logs_dir.iterdir():
        if artifact.is_dir() or artifact.stat().st_size > JIRA_ATTACHMENT_MAX_SIZE:
            logger.debug("Skip %s as it had been replaced with other files", artifact)
            continue

        matching_attachments = [
            attachment for attachment in issue.fields.attachment if artifact.name == attachment.filename
        ]
        if len(matching_attachments) > 0 and matching_attachments[0].size == artifact.stat().st_size:
            logger.debug("File %s already exists at %s. Skipping upload", artifact, issue)
            continue

        logger.info("Attaching %s to issue %s", artifact, issue)
        jira_client.add_attachment(issue=issue, attachment=str(artifact))


def attach_logs_in_jira(source_dir: Path, jira_access_token: str, max_days: Optional[int] = None):
    jira_client = JiraClientFactory.create(jira_access_token=jira_access_token)

    errors = []

    for cluster_logs_dir in source_dir.iterdir():
        date = cluster_logs_dir.name.split("_")[0]
        if max_days is not None and days_ago(date) > max_days:
            logger.debug(
                "Ignoring old cluster dir %s as it was created more than %d days ago", cluster_logs_dir.name, max_days
            )
            continue

        try:
            _attach_logs_for_cluster(jira_client, cluster_logs_dir)
        except (jira.JIRAError, RuntimeError) as err:
            errors.append(err)

    if errors:
        for error in errors:
            logger.error("Error while attaching logs in Jira", exc_info=error)

        raise ExceptionGroup("Failed attaching logs for all issues", errors)


def main():
    parser = argparse.ArgumentParser(
        description="Create a Jira ticket for each installation attempt, and upload artifacts as Jira attachments."
    )

    parser.add_argument("--source-dir", help="Local directory with logs for all clusters")
    parser.add_argument("-v", "--verbose", action="store_true", help="Output verbose logging")
    parser.add_argument(
        "--max-days",
        default=DEFAULT_DAYS_TO_ATTACH_LOGS,
        type=int,
        help="Create tickets only for failures that happened the last amount of days. Earlier failures will be ignored",
    )
    parser.add_argument(
        "--jira-access-token",
        default=os.environ.get("JIRA_ACCESS_TOKEN"),
        required=False,
        help="Personal access token for accessing Jira",
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    attach_logs_in_jira(
        source_dir=Path(args.source_dir),
        jira_access_token=args.jira_access_token,
        max_days=args.max_days,
    )


if __name__ == "__main__":
    main()
