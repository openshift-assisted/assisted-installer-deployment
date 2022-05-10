#!/usr/bin/env python

# Adds links on Jira ticket to the given github PR

import argparse
import os
import logging

import jira

import consts


logging.basicConfig(level=logging.WARN, format='%(levelname)-10s %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)
isVerbose = False


def log_exception(msg):
    if isVerbose:
        logger.exception(msg)
    else:
        logger.error(msg)


# when trying to add a remote link, the method tries to get the application links, which only Jira admin
# have access to. Since adding remote links works even without it, here we are monkey-patching (shudder) the
# function to do nothing
def monkeyPatchApplicationLinks(jira_client):
    def dummyApplicationLinks():
        return []

    jira_client.applicationlinks = dummyApplicationLinks

    return jira_client


PR_LINK_PREFIX = "Github PR link: "
PR_LINK_COMMENT_FORMAT = PR_LINK_PREFIX + "{}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--jira-access-token", default=os.environ.get("JIRA_ACCESS_TOKEN"), required=False,
                        help="PAT (personal access token) for accessing Jira")
    parser.add_argument("-i", "--issue", required=True, help="Issue key")
    parser.add_argument("-l", "--pr-link", required=True, help="PR link")
    parser.add_argument("-v", "--verbose", action="store_true", help="Output verbose logging")
    args = parser.parse_args()

    if args.verbose:
        isVerbose = True
        logging.getLogger("__main__").setLevel(logging.DEBUG)

    j = jira.JIRA(consts.JIRA_SERVER, token_auth=args.jira_access_token, validate=True)
    j1 = monkeyPatchApplicationLinks(j)

    issue = j1.issue(args.issue)

    pr_found = False
    links = j1.remote_links(issue)
    for link in links:
        print(link.object.title, link.object.url)
        if link.object.url == args.pr_link:
            print("PR already exist: {}".format(link.object.title))
            pr_found = True

    if not pr_found:
        print("PR not found adding it: {}".format(args.pr_link))
        o = dict(title=args.pr_link, url=args.pr_link)
        j1.add_remote_link(issue, o)
