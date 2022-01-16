#!/usr/bin/env python3
import os
import json
import argparse
import dataclasses
from typing import List

import jira
import requests

import consts


FILTER_ID = 12380672


@dataclasses.dataclass(order=True)
class IssueData:
    email_domain: str
    user: str
    key: str
    url: str
    features: List[str]


def _get_issues_data(issues):
    for issue in issues:
        key = issue.key
        url = issue.permalink()
        user = issue.raw["fields"]["customfield_12319044"]
        email_domain = issue.raw["fields"]["customfield_12319045"]

        features = [label.replace("FEATURE-", "")
                    for label in issue.raw["fields"]["labels"]
                    if "FEATURE" in label]

        # filtering some non-important "features"
        features = [feature for feature in features
                    if feature not in (
                        "Requested-hostname",
                        "Requsted-hostname",  # leaving the value with the typo for backwards compatibility
                        "NetworkType",
                    )]

        yield IssueData(key=key, url=url, user=user, email_domain=email_domain, features=features)


def _post_message(webhook, text):
    if webhook is None:
        # dry-run mode, just printing it raw
        print(text)
    else:
        response = requests.post(webhook, data=json.dumps({"text": text}), headers={'Content-type': 'application/json'})
        response.raise_for_status()


def triage_status_report(jira_client, filter_id, webhook):
    jira_filter = jira_client.filter(filter_id)
    issues = jira_client.search_issues(jira_filter.jql)

    filter_url = jira_filter.viewUrl
    text = f"There are <{filter_url}|{len(issues)} new triage tickets>\n"

    table = ""
    for issue in sorted(_get_issues_data(issues)):
        table += f"<{issue.url}|{issue.key}>   {issue.user:<15} {issue.email_domain:<15} {issue.features}\n"

    if table:
        text += '```{}```'.format(table)

    _post_message(webhook, text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jira-access-token", default=os.environ.get("JIRA_ACCESS_TOKEN"), required=False,
                        help="PAT (personal access token) for accessing Jira")
    parser.add_argument("--webhook", default=os.environ.get("WEBHOOK"),
                        help="Slack channel url to post information. Not specifying implies dry-run")
    parser.add_argument("--filter-id", default=FILTER_ID, help="Jira filter id")
    args = parser.parse_args()

    client = jira.JIRA(consts.JIRA_SERVER, token_auth=args.jira_access_token)

    triage_status_report(client, args.filter_id, args.webhook)


if __name__ == "__main__":
    main()
