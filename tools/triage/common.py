import functools
import json
import logging
from enum import Enum
from itertools import filterfalse
from typing import Callable

import dateutil.parser
import jira
import requests
from retry import retry

from tools.triage.exceptions import FailedToGetMetadataException
from tools.triage.utils.extraction.jira_attachment_querier.jira_remote_archive_querier import (
    JiraAttachmentsQuerier,
)

JIRA_PROJECT = "AITRIAGE"
JIRA_SUMMARY = "cloud.redhat.com failure: {failure_id}"
LOGS_COLLECTOR = "http://assisted-logs-collector.usersys.redhat.com"

logger = logging.getLogger(__name__)


class SignaturesSource(Enum):
    LOGS_SERVER = "logs_server"
    JIRA = "jira"


@retry(exceptions=jira.exceptions.JIRAError, tries=3, delay=10, logger=logger)
def get_or_create_triage_ticket(jira_client: jira.JIRA, failure_id: str) -> jira.Issue:
    summary = JIRA_SUMMARY.format(failure_id=failure_id)

    matching_issues = jira_client.search_issues(
        f'project = "{JIRA_PROJECT}" AND summary ~ "{summary}"', fields=["attachment", "status", "labels"]
    )

    if len(matching_issues) == 0:
        logger.info("Creating an issue for %s", summary)
        return jira_client.create_issue(
            project=JIRA_PROJECT,
            summary=summary,
            components=[{"name": "Cloud-Triage"}],
            priority={"name": "Blocker"},
            issuetype={"name": "Bug"},
        )

    if len(matching_issues) == 1:
        logger.debug("Using pre-existing issue %s", matching_issues[0])
        return matching_issues[0]

    raise RuntimeError(
        f"Found more than one matching issue for '{summary}': {', '.join(issue.key for issue in matching_issues)}"
    )


def get_cluster_logs_base_url(failure_id: str) -> str:
    return f"{LOGS_COLLECTOR}/files/{failure_id}"


def clean_metadata_json(md):
    installation_start_time = dateutil.parser.isoparse(md["cluster"]["install_started_at"])

    def host_deleted_before_installation_started(host):
        if deleted_at := host.get("deleted_at"):
            return dateutil.parser.isoparse(deleted_at) < installation_start_time
        return False

    md["cluster"]["deleted_hosts"] = list(filter(host_deleted_before_installation_started, md["cluster"]["hosts"]))
    md["cluster"]["hosts"] = list(filterfalse(host_deleted_before_installation_started, md["cluster"]["hosts"]))

    return md


@functools.lru_cache(maxsize=1000)
def get_metadata_json(
    cluster_url: str,
    jira_client: jira.JIRA,
    issue_key: str,
    signatures_source: SignaturesSource = SignaturesSource.LOGS_SERVER,
):
    try:
        if signatures_source == SignaturesSource.JIRA:
            jira_querier = JiraAttachmentsQuerier(
                jira_client=jira_client, issue_key=issue_key, attachment_file_name="metadata.json", logger=logger
            )
            return clean_metadata_json(json.loads(jira_querier.get(mode="rb")))

        res = requests.get("{}/metadata.json".format(cluster_url))
        res.raise_for_status()
        return clean_metadata_json(res.json())

    except Exception as e:
        raise FailedToGetMetadataException from e


@retry(exceptions=jira.JIRAError, tries=3, delay=1)
def apply_function_with_retry(function: Callable, *args, **kwargs):
    return function(*args, **kwargs)
