#!/usr/bin/env python3
import os
import json
import argparse
import dataclasses
from typing import List

import jira
import requests

JIRA_SERVER = "https://issues.redhat.com"
FILTER_ID = 12380672


@dataclasses.dataclass(order=True)
class IssueData:
    email_domain: str
    user: str
    key: str
    url: str
    features: List[str]
    manufacturers: List[str]


def get_hw_manufacturers(host_details):
    manufacturers = []

    table = [line for line in host_details.split("\n")
             if line and "Host extra details" not in line]
    header, hosts = table[0], table[1:]
    for host in hosts:
        for info, content in zip(header.split("||"), host.split("|")):
            if "manufacturer" in info:
                manufacturers.append(content.strip())
                break

    return manufacturers


def _get_issues_data(jira_client, issues):
    for issue in issues:
        manufacturers = "Unknown"
        for comment in jira_client.comments(issue):
            if "Host extra details" not in comment.body:
                continue

            manufacturers = get_hw_manufacturers(host_details=comment.body)

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

        yield IssueData(
            key=key,
            url=url,
            user=user,
            email_domain=email_domain,
            features=features,
            manufacturers=manufacturers,
        )


def _post_message(webhook, text):
    if webhook is None:
        # dry-run mode, just printing it raw
        print(text)
    else:
        response = requests.post(webhook, data=json.dumps({"text": text}), headers={'Content-type': 'application/json'})
        response.raise_for_status()


def main(jira_client, filter_id, webhook):
    jira_filter = jira_client.filter(filter_id)
    issues = jira_client.search_issues(jira_filter.jql)

    filter_url = jira_filter.viewUrl
    text = f"There are <{filter_url}|{len(issues)} new triage tickets>\n"

    table = ""
    for issue in sorted(_get_issues_data(jira_client, issues)):
        entry = f"<{issue.url}|{issue.key}>   {issue.user:<20} {issue.email_domain:<15}\n"

        if issue.features:
            entry += f'\tFeatures:      {", ".join(issue.features)}\n'

        if issue.manufacturers:
            entry += f'\tManufacturers: {", ".join(issue.manufacturers)}\n'

        table += entry

    if table:
        text += '```{}```'.format(table)

    _post_message(webhook, text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--jira-username", default=os.environ.get("JIRA_USERNAME"),
                        help="Jira username for accessing triage tickets")
    parser.add_argument("--jira-password", default=os.environ.get("JIRA_PASSWORD"),
                        help="Jira password for accessing triage tickets")
    parser.add_argument("--webhook", default=os.environ.get("WEBHOOK"),
                        help="Slack channel url to post information. Not specifying implies dry-run")
    parser.add_argument("--filter-id", default=FILTER_ID, help="Jira filter id")
    args = parser.parse_args()

    client = jira.JIRA(JIRA_SERVER, basic_auth=(args.jira_username, args.jira_password))

    main(client, args.filter_id, args.webhook)
