#!/usr/bin/env python3
"""
This script gets a list of the filed clusters from the assisted-logs-server
For each cluster, which does not already has a triaging Jira ticket, it creates one
"""
import argparse
import logging
import os
import sys
import tempfile

import jira
import requests
from retry import retry

from tools.jira_client import CLOSED_STATUS, JiraClientFactory
from tools.triage import close_by_signature
from tools.triage.add_triage_signature import (
    CUSTOM_FIELD_DOMAIN,
    CUSTOM_FIELD_IGNORED_DOMAINS,
    custom_field_name,
    process_ticket_with_signatures,
)
from tools.triage.common import (
    JIRA_PROJECT,
    LOGS_COLLECTOR,
    SignaturesSource,
    apply_function_with_retry,
    get_cluster_logs_base_url,
    get_metadata_json,
    get_or_create_triage_ticket,
)
from tools.utils import days_ago

DEFAULT_DAYS_TO_HANDLE = 30
DEFAULT_DAYS_TO_ADD_SIGNATURES = 3

logger = logging.getLogger(__name__)


@retry(exceptions=jira.exceptions.JIRAError, tries=3, delay=10, logger=logger)
def close_custom_domain_user_ticket(jira_client, issue_key):
    issue = jira_client.issue(issue_key)
    if issue.raw["fields"].get(custom_field_name(CUSTOM_FIELD_DOMAIN)) in CUSTOM_FIELD_IGNORED_DOMAINS:
        logger.info("closing custom user's issue: %s", issue_key)
        jira_client.transition_issue(issue_key, CLOSED_STATUS)
        jira_client.add_comment(issue_key, "Automatically closing the issue for the specified domain.")


def main(args):
    jira_client = JiraClientFactory.create(args.jira_access_token)

    pull_secret_file = args.pull_secret_file

    if args.pull_secret_contents:
        pull_secret_tmp_file = tempfile.NamedTemporaryFile(mode="w")
        pull_secret_file = pull_secret_tmp_file.name
        pull_secret_tmp_file.write(args.pull_secret_contents)
        pull_secret_tmp_file.flush()

    signatures_source = SignaturesSource(args.signatures_source)

    if signatures_source == SignaturesSource.JIRA:
        failed_clusters = apply_function_with_retry(
            jira_client.search_issues, f"project = {JIRA_PROJECT} AND created >= -{DEFAULT_DAYS_TO_HANDLE}d"
        )

    else:
        res = requests.get("{}/files/".format(LOGS_COLLECTOR))
        res.raise_for_status()
        failed_clusters = res.json()

    for failure in failed_clusters:
        failure_name = (
            failure.fields.summary.split()[2] if signatures_source == SignaturesSource.JIRA else failure["name"]
        )
        date = failure_name.split("_")[0]
        days_ago_creation = days_ago(date)

        if not args.all and days_ago_creation > DEFAULT_DAYS_TO_HANDLE:
            continue

        logs_url = get_cluster_logs_base_url(failure_name)
        issue_key = failure.key if signatures_source == SignaturesSource.JIRA else ""

        metadata = get_metadata_json(
            cluster_url=logs_url, jira_client=jira_client, issue_key=issue_key, signatures_source=signatures_source
        )

        if metadata["cluster"]["status"] != "error":
            continue

        issue = get_or_create_triage_ticket(jira_client, failure_name)

        if issue.fields.status.name == "Closed":
            logger.debug("Skipping closed issue %s", issue.key)
            continue

        if not args.all and days_ago_creation > DEFAULT_DAYS_TO_ADD_SIGNATURES:
            logger.debug("Skipping issue %s which is %d days old", issue.key, days_ago_creation)
            continue

        logger.debug("Processing issue %s", issue.key)

        process_ticket_with_signatures(
            jira_client,
            logs_url,
            issue.key,
            only_specific_signatures=None,
            dry_run_file=sys.stdout if args.dry_run else None,
            pull_secret_file=pull_secret_file,
            signatures_source=signatures_source,
        )

        close_custom_domain_user_ticket(jira_client, issue.key)
        close_by_signature.run_using_json(args.filters_json, jira_client, [issue])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    loginGroup = parser.add_argument_group(title="login options")
    loginArgs = loginGroup.add_mutually_exclusive_group()
    loginArgs.add_argument(
        "--jira-access-token",
        default=os.environ.get("JIRA_ACCESS_TOKEN"),
        required=False,
        help="PAT (personal access token) for accessing Jira",
    )

    pull_secrets_group = parser.add_argument_group(title="Pull Secret")
    pull_secrets = pull_secrets_group.add_mutually_exclusive_group(required=False)
    pull_secrets.add_argument(
        "--pull-secret-file",
        default=os.environ.get("PULL_SECRET_FILE"),
        required=False,
        help="path to pull-secret.json file",
    )
    pull_secrets.add_argument(
        "--pull-secret-contents",
        default=os.environ.get("PULL_SECRET_CONTENTS"),
        required=False,
        help="pull secret acutal file contents",
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Try creating Triage Tickets for all failures. Default is just for failures in the past 30 days",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Output verbose logging")
    parser.add_argument(
        "--filters-json",
        help="At the end of the run, filter and close issues that applied to "
        "the rules in a given json file which has the format: "
        "{signature_type: {root_issue: message}}",
        default=os.path.join(os.path.dirname(os.path.realpath(__file__)), "triage_resolving_filters.json"),
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="If true, Jira issues will be generated; otherwise, the anticipated issues will be displayed on stdout",
    )
    parser.add_argument(
        "--signatures-source",
        default=os.environ.get("SIGNATURES_SOURCE", SignaturesSource.LOGS_SERVER.value),
        required=False,
        help="Signatures will get created from the specified data source",
        choices=[source.value for source in SignaturesSource],
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARN, format="%(levelname)-10s %(message)s")
    logger = logging.getLogger(__name__)
    logging.getLogger("__main__").setLevel(logging.INFO)

    if args.verbose:
        logging.getLogger("__main__").setLevel(logging.DEBUG)

    main(args)
