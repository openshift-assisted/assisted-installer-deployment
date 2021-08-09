import os
import jira
import json
import requests
import argparse

JIRA_SERVER = "https://issues.redhat.com"
FILTER_ID = 12380672

def main(jira_client, filter_id ,webhook):
    filter = jira_client.filter(filter_id)
    issues = jira_client.search_issues(filter.jql)
    issues_count = len(issues)
    if  issues_count == 0:
        return

    filter_url = filter.viewUrl
    text = f"There are <{filter_url}|{issues_count} new triage tickets>\n"
    email_domains = list()
    feature = list()
    ticket_text = ""
    for issue in issues:
        key = issue.key
        url = issue.permalink()
        labels = list()
        for label in issue.raw["fields"]["labels"]:
            if "FEATURE" in label:
                labels.append(label.replace("FEATURE-",""))

        email_domain = issue.raw["fields"]["customfield_12319045"]
        ticket_text += f"<{url}|{key}>   {email_domain:<20} {labels}\n"

        email_domains.append(email_domain)
        feature += labels
    text += '```{}```'.format(ticket_text)
    r = requests.post(webhook, data=json.dumps({"text":text}), headers={'Content-type': 'application/json'})

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--jira-creds", "-jc", required=True, help="Jira credentials in the format of user:password")
    parser.add_argument("--webhook", "-wh", required=True, help="Slack channel url to post information")
    parser.add_argument("--filter-id", default=FILTER_ID, help="Jira filter id")
    args = parser.parse_args()

    jira_user, jira_pass = args.jira_creds.split(":")
    client = jira.JIRA(JIRA_SERVER, basic_auth=(jira_user, jira_pass))

    main(client, args.filter_id, args.webhook)