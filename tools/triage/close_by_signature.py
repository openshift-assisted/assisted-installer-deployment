#!/usr/bin/env python3

import argparse
import json
import logging
import os
import pprint
import sys
import tempfile
import textwrap

from tools.jira_client import JiraClientFactory
from tools.jira_client.jira_api import JiraAPI

from tools.triage import Filters

from add_triage_signature import (
    config_logger,
    get_issues,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def parse_args():
    desc = textwrap.dedent(
        """\
        Automatically resolve triage tickets that are linked to known issues by
        signature type and/or common message in the signature comment body.
        Root issues can be linked to given signature messages, and if provided they
        will be linked to the resolved issues on close.
    """
    )
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-v", "--verbose", action="store_true", help="Output verbose logging")

    parser.add_argument(
        "--jira-access-token",
        default=os.environ.get("JIRA_ACCESS_TOKEN"),
        required=False,
        help="PAT (personal access token) for accessing Jira",
    )

    selectors_group = parser.add_argument_group(title="Issues selection")
    selectors = selectors_group.add_mutually_exclusive_group(required=True)
    selectors.add_argument(
        "-r",
        "--recent-issues",
        action="store_true",
        help="Handle recent (30 days) Triaging Tickets",
    )
    selectors.add_argument(
        "-a",
        "--all-issues",
        action="store_true",
        help="Handle all Triaging Tickets",
    )
    selectors.add_argument(
        "-i",
        "--issue",
        required=False,
        help="Triage issue key",
    )

    filter_group = parser.add_argument_group(title="Filter by")
    filters = filter_group.add_mutually_exclusive_group(required=True)
    filters.add_argument(
        "-f",
        "--filter",
        nargs="+",
        help="Filter issues that applied to the format signature_type:root_issue:message",
    )
    filters.add_argument(
        "--filters-json",
        help="Filter issues that applied to the rules in a given json file "
        "which has the format: "
        "{signature_type: {root_issue: message}}",
    )

    dry_run_group = parser.add_argument_group(title="Dry run options")
    dry_run_args = dry_run_group.add_mutually_exclusive_group()
    dry_run_args.add_argument(
        "-d", "--dry-run", action="store_true", help="Dry run. Don't update tickets. Write output to stdout"
    )
    dry_run_args.add_argument(
        "-t", "--dry-run-temp", action="store_true", help="Dry run. Don't update tickets. Write output to a temp file"
    )

    return parser.parse_args()


def read_filters_file(path):
    # json format: { signature_type: { root_issue: { message } }
    with open(path) as fp:
        filters_json = json.load(fp)

    logger.debug("Filters file data=%s", pprint.pformat(filters_json))
    return filters_json


def get_dry_run_stream(args):
    if args.dry_run_temp:
        return tempfile.NamedTemporaryFile(mode="w", delete=False)
    elif args.dry_run:
        return sys.stdout


def run_using_json(path, jira_client, issues):
    logger.debug("Starting issue resolver task using filters json=%s", path)
    filters_json = read_filters_file(path)
    filters = Filters.from_json(jira_client, filters_json)
    logger.debug(f"Filtering issues: {filters}")
    jira_api = JiraAPI(jira_client, logger)
    Filters.close_issues_by_filters(jira_api, issues, filters)


def run_using_cli(args):
    config_logger(args.verbose)

    logger.debug("Starting issue resolver task using CLI with args=%s", pprint.pformat(args.__dict__))
    dry_run_stream = get_dry_run_stream(args)
    jira_client = JiraClientFactory.create(args.jira_access_token, dry_run_stream)

    issues = get_issues(jira_client, args.issue, only_recent=args.recent_issues)

    jira_api = JiraAPI(jira_client, logger)
    try:
        if args.filters_json:
            filters_json = read_filters_file(args.filters_json)
            filters = Filters.from_json(jira_client, filters_json)
            Filters.close_issues_by_filters(jira_api, issues, filters)
        else:
            filters = Filters.from_args(jira_client, args)
            Filters.close_issues_by_filters(jira_api, issues, filters)
    finally:
        if dry_run_stream:
            dry_run_stream.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    run_using_cli(parse_args())
