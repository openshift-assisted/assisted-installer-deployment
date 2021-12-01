#!/usr/bin/env python3
"""This script gets a list of the filed tests from testgrid.

For each failure, which does not already has an open triage Jira ticket, it creates one.
"""
import argparse
import logging
import netrc
import os
import sys
import re
from urllib.parse import urlparse
import requests
import jira
from retry import retry
from add_triage_signature import (
    get_credentials_from_netrc, get_jira_client,
)

DEFAULT_WATCHERS = ["mkowalsk"]


TEST_VERSION_REGEX = re.compile(r'.*-(\d\.[^-]+)-.*')
TEST_STATUS_URL = "https://testgrid.k8s.io/redhat-assisted-installer/summary"
TEST_RUNS_URL = 'https://testgrid.k8s.io/redhat-assisted-installer/table?tab={}&width=10&dashboard=redhat-assisted-installer'
JIRA_SERVER = "https://issues.redhat.com/"
DEFAULT_NETRC_FILE = "~/.netrc"
JIRA_SUMMARY = "CI test: {test_id} ({last_pass})"

JIRA_DESCRIPTION = """
{{color:red}}Do not manually edit this description, it will get automatically over-written{{color}}

*Test Status*: {status}
*Test Details:* [{test_id}|https://testgrid.k8s.io/redhat-assisted-installer#{test_id}]
*Last Test failure:* https://prow.ci.openshift.org/view/gcs/origin-ci-test/logs/{test_id}/{last_fail}
{tests_list}
"""


def format_summary(failure_data):
    return JIRA_SUMMARY.format(**failure_data)


def get_all_triage_tickets(jclient):
    query = 'filter in ("assisted installer triaging CI issues")'
    return [i.fields.summary for i in jclient.search_issues(query, maxResults=None)]


def add_watchers(jclient, issue):
    for watcher in DEFAULT_WATCHERS:
        jclient.add_watcher(issue.key, watcher)


def get_last_failure_instance(test_id):
    res = requests.get(TEST_RUNS_URL.format(test_id))
    res.raise_for_status()
    return res.json()['changelists'][0]


def get_overall_tests(test_data):
    return [t for t in test_data['tests']
            if t['display_name'] == 'Overall']


def get_last_pass(test_data):
    return get_overall_tests(test_data)[0]['pass_timestamp']


def format_labels(failure_data):
    return ["AI_CI_TEST_{test_id}".format(**failure_data)]


def format_description(failure_data):
    tests_list = "*Failed tests:*\n"
    for test in failure_data['failed_tests']:
        tests_list += " * {}\n".format(test)
    failure_data["tests_list"] = tests_list
    return JIRA_DESCRIPTION.format(**failure_data)


def create_jira_ticket(jclient, existing_tickets, test_id, test_data):
    last_pass_timestamp = get_last_pass(test_data)
    summary = format_summary({"test_id": test_id,
                              "last_pass": last_pass_timestamp})
    if summary in existing_tickets:
        logger.debug("issue found: %s", summary)
        return None

    failed_tests = [t['display_name'] for t in test_data['tests'] if t['display_name'] != 'Overall']
    test_status = test_data['status']
    i = get_last_failure_instance(test_id)
    new_issue = jclient.create_issue(project="AITRIAGE",
                                     description=format_description({"test_id": test_id,
                                                                     "last_fail": i,
                                                                     "failed_tests": failed_tests,
                                                                     "status": test_status,
                                                                     }),
                                     summary=summary,
                                     versions=[{'name': 'OpenShift {}'.format(TEST_VERSION_REGEX.findall(test_id)[0])}],
                                     components=[{'name': "CI-Triage"}],
                                     priority={'name': 'Blocker'},
                                     issuetype={'name': 'Bug'},
                                     labels=format_labels({"test_id": test_id}))

    logger.info("issue created: %s", new_issue)
    add_watchers(jclient, new_issue)
    return new_issue


def is_test_failing(test_data):
    # Following is the old way to check if a grid is failing - once the testgrid bug
    # described below is fixed, this code can be restored:
    # failing = test_data['overall_status'] == "FAILING"
    # return failing

    # testgrid has a bug where it marks successful tests as "FAILING", just because they
    # have failed test cases. But sometimes test cases are allowed to fail while the run itself is
    # "passing", but testgrid doesn't take that into account - so it marks a grid as "FAILING" even though
    # its "Overall" row is green. When the "Overall" row is green but the test is marked as failing, the
    # overall tests don't get included in the `tests` list, so we use that to detect this scenario.
    actually_failing = len(get_overall_tests(test_data)) > 0

    return actually_failing


def get_failed_tests():
    try:
        res = requests.get(TEST_STATUS_URL)
        res.raise_for_status()
        tests = {n: data for n, data in res.json().items() if is_test_failing(data)}
        return tests
    except Exception:
        logger.exception("Error getting list of failed tests")
        raise


@retry(exceptions=jira.exceptions.JIRAError, tries=3, delay=10)
def main(arg):
    if arg.user_password is None:
        username, password = get_credentials_from_netrc(urlparse(JIRA_SERVER).hostname, arg.netrc)
    else:
        try:
            [username, password] = arg.user_password.split(":", 1)
        except Exception:
            logger.error("Failed to parse user:password")

    jclient = get_jira_client(username, password)

    try:
        failed_tests = get_failed_tests()
    except Exception:
        sys.exit(1)

    existing_tickets = get_all_triage_tickets(jclient)

    for failed_test in failed_tests:
        create_jira_ticket(jclient, existing_tickets, failed_test, failed_tests[failed_test])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    loginGroup = parser.add_argument_group(title="login options")
    loginArgs = loginGroup.add_mutually_exclusive_group()
    loginArgs.add_argument("--netrc", default="~/.netrc", required=False, help="netrc file")
    loginArgs.add_argument("-up", "--user-password", required=False,
                           help="Username and password in the format of user:pass")
    parser.add_argument("-v", "--verbose", action="store_true", help="Output verbose logging")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARN, format='%(levelname)-10s %(message)s')
    logger = logging.getLogger(__name__)
    logging.getLogger("__main__").setLevel(logging.INFO)

    if args.verbose:
        logging.getLogger("__main__").setLevel(logging.DEBUG)

    main(args)
