import logging

import jira
from retry import retry


JIRA_PROJECT = "AITRIAGE"
JIRA_SUMMARY = "cloud.redhat.com failure: {failure_id}"
LOGS_COLLECTOR = "http://assisted-logs-collector.usersys.redhat.com"

log = logging.getLogger(__name__)


@retry(exceptions=jira.exceptions.JIRAError, tries=3, delay=10)
def get_or_create_triage_ticket(jira_client: jira.JIRA, failure_id: str) -> jira.Issue:
    summary = JIRA_SUMMARY.format(failure_id=failure_id)

    matching_issues = jira_client.search_issues(
        f'project = "{JIRA_PROJECT}" AND summary ~ "{summary}"', fields=["attachment", "status"]
    )

    if len(matching_issues) == 0:
        log.info("Creating an issue for %s", summary)
        return jira_client.create_issue(
            project=JIRA_PROJECT,
            summary=summary,
            components=[{"name": "Cloud-Triage"}],
            priority={"name": "Blocker"},
            issuetype={"name": "Bug"},
        )

    if len(matching_issues) == 1:
        log.debug("Using pre-existing issue %s", matching_issues[0])
        return matching_issues[0]

    raise RuntimeError(
        f"Found more than one matching issue for '{summary}': {', '.join(issue.key for issue in matching_issues)}"
    )


def get_cluster_logs_base_url(failure_id: str) -> str:
    return f"{LOGS_COLLECTOR}/files/{failure_id}"
