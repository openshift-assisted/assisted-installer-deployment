#!/usr/bin/env python

# A tool to perform various operations on Jira


import os
import sys
import csv
import jira
import pprint
import argparse
import netrc
import logging
import textwrap
import urllib.request, urllib.error, urllib.parse
from tabulate import tabulate
from urllib.parse import urlparse
from collections import defaultdict
from collections import OrderedDict


JIRA_SERVER = "https://issues.redhat.com/"

#FIELD_DELIVERED_PERCENT = 'customfield_13614'
#FIELD_RESOLVED_PERCENT = 'customfield_13615'
#FIELD_STORY_POINTS = 'customfield_10004'
#FIELD_TEST_PATH = 'customfield_11800'
#FIELD_TEST_SERVERS = 'customfield_13605'
#FIELD_INT_MONKEY_TESTS = 'customfield_13400'
#FIELD_INT_UPGRADE_TESTS = 'customfield_13600'
#FIELD_PROJECT_NAME = 'customfield_13603'
#FIELD_PROJECT_HASH = 'customfield_13604'
#AUTO_DELIVERY_TEST = 'customfield_13600'
#FIELD_ROOTFS_STAR_HASH = 'customfield_11201'
#FIELD_TEST_NAME = 'customfield_11401'

MAX_RESULTS = 100

SEARCH_QUERY_EPICS = 'project = MGMT AND component = "MGMT OCP Metal" AND type = Epic AND filter = '
CURRENT_VERSION_FILTER = '12347072'
NEXT_VERSION_FILTER = '12347073'

logging.basicConfig(level=logging.WARN, format='%(levelname)-10s %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)
isVerbose = False


def jira_default_login():
    raise Exception("feature not yet supported")


def log_exception(msg):
    if isVerbose:
        logger.exception(msg)
    else:
        logger.error(msg)


def jira_netrc_login(netrcFile):
    cred = netrc.netrc(os.path.expanduser(netrcFile))
    username, _, password = cred.authenticators(urlparse(JIRA_SERVER).hostname)
    logger.info("log-in with username: %s", username)
    return jira.JIRA(JIRA_SERVER, basic_auth=(username, password))


def get_task_weight(issue):
    # Story Points (customfield_10004) can act as weight of each task
    points = get_raw_field(issue, FIELD_STORY_POINTS)
    if points is None:
        return 1
    else:
        return int(points)


def get_raw_field(issue, fieldName):
    try:
        return issue.raw['fields'][fieldName]
    except:
        return None


def get_assignee(issue):
    try:
        return issue.fields.assignee.displayName
    except:
        try:
            return issue.raw['fields']['assignee']['displayName']
        except:
            return "Unassigned"

def format_key_for_print(key, isMarkdown):
    if not isMarkdown:
        return key

    return f"[{key}](https://issues.redhat.com/browse/{key})"

def get_data_for_print(issues, isTT=False, withStatus=True, withAssignee=True, withFixVersion=False,
                       isMarkdown=False):
    headers = ['key', 'summary', 'component', 'priority']
    if withStatus:
        headers.append('status')
    if withAssignee:
        headers.append('assignee')
    if isTT:
        headers.append('test-path')
    if withFixVersion:
        headers.append('fixVersion')

    table = []
    for i in issues:
        row = {'key': format_key_for_print(i.key, isMarkdown=isMarkdown), 'summary': i.fields.summary,
               'component': [c.name for c in i.fields.components], 'priority': i.fields.priority.name}
        if withStatus:
            row['status'] = i.fields.status
        if withFixVersion:
            row['fixVersion'] = "" if len(i.fields.fixVersions) == 0 else i.fields.fixVersions[0].name
        if withAssignee:
            assignee = get_assignee(i)
            row['assignee'] = assignee
        if isTT:
            row['test-path'] = get_raw_field(i, FIELD_TEST_PATH)
        table.append(row)

    return headers, table


def print_report_csv(issues, isTT=False):
    headers, data = get_data_for_print(issues, isTT)
    csvout = csv.DictWriter(sys.stdout, delimiter='|', fieldnames=headers)
    csvout.writeheader()
    for row in data:
        csvout.writerow(row)


def print_report_table(issues, isTT=False, isMarkdown=False):
    _, data = get_data_for_print(issues, isTT, isMarkdown=isMarkdown)
    format = "github" if isMarkdown else "psql"
    print(tabulate(data, headers="keys", tablefmt=format))


class JiraTool(object):
    def __init__(self, jira, maxResults=MAX_RESULTS):
        self._jira = jira
        self._maxResults = maxResults

    def jira(self):
        return self._jira

    def link_tickets(self, ticket, to_ticket):
        try:
            logger.info("linking %s to %s", to_ticket.key, ticket.key)
            res = self._jira.create_issue_link("relates to", ticket, to_ticket)
            res.raise_for_status()
        except Exception as e:
            logger.exceptio("Error linking to %s", to_ticket.key, e)

    def add_watchers(self, ticket, watchers):
        try:
            for watcher in watchers:
                logger.info("Adding %s as watcher to %s", watcher, ticket.key)
                self._jira.add_watcher(ticket.key, watcher)
        except Exception as e:
            logger.exception("Error adding watcher to %s", ticket.key)

    def remove_watchers(self, ticket, watchers):
        try:
            for watcher in watchers:
                logger.info("removing %s as watcher from %s", watcher, ticket.key)
                self._jira.remove_watcher(ticket.key, watcher)
        except Exception as e:
            logger.exception("Error removing watcher to %s", ticket.key)

    def get_selected_issues(self, issues, isEpicTasks=False, is_issue_links=False):
        if not isEpicTasks and not is_issue_links:
            return issues
        elif is_issue_links:
            linked_issue_keys = []
            linked_issues = []
            for i in issues:
                for l in i.fields.issuelinks:
                    linked_issue_keys.append(self.extract_linked_issue(l).key)

            if len(linked_issue_keys):
                linked_issues =  self._jira.search_issues("issue in (%s)" % (",".join(linked_issue_keys)),
                                                          maxResults=self._maxResults)
            return linked_issues

        return self._jira.search_issues("\"Epic Link\" in (%s)" % (",".join([i.key for i in issues])),
                                        maxResults=self._maxResults)

    @staticmethod
    def extract_linked_issue(issue_link):
        try:
            return issue_link.outwardIssue
        except:
            return issue_link.inwardIssue


    def remove_links(self, ticket, to_remove):
        for l in ticket.fields.issuelinks:
            key = self.extract_linked_issue(l).key


            if key == to_remove.key:
                try:
                    logger.info("removing link %s", key)
                    l.delete()
                except Exception as e:
                    log_exception("Error removing link {}".format(key))

    def get_issues_in_epic(self, key):
        issues = self._jira.search_issues("\"Epic Link\" in (%s)" % key, maxResults=self._maxResults)
        if len(issues) == 0:
            epic = self._jira.issue(key)
            issues = [self._jira.issue(s.key) for s in epic.fields.subtasks]
        return issues

    def calculate_progress_for_issues(self, key):
        issues = self.get_issues_in_epic(key)
        total = 0
        closed = 0
        resolved = 0
        for issue in issues:
            logger.debug("   Issue in epic: %s", issue)
            if issue.fields.project.name in ["Documentation", "QA"]:
                continue
            points = get_task_weight(issue)
            total = total + points
            if issue.fields.status.name.lower() in ["closed"]:
                closed = closed + points
            elif issue.fields.status.name.lower() in ["resolved", "done"] and issue.fields.project.name == "UI":
                closed = closed + points
            elif issue.fields.status.name.lower() in ["resolved", "done"]:
                resolved = resolved + points
        return total, closed, resolved

    def get_issues_from_search_url(self, issue, test_type):
        if test_type == "upgrade":
            query = get_raw_field(issue, FIELD_INT_UPGRADE_TESTS)
        else:
            query = get_raw_field(issue, FIELD_INT_MONKEY_TESTS)

        if 'jql=' in str(query):
            try:
                return self._jira.search_issues(urllib.parse.unquote(query.split('jql=')[1].replace('+', '%20')),
                                                maxResults=self._maxResults)
            except Exception as ex:
            logging.error('Failed to get query {}'.format(ex))
                    return []
        else:
            logger.warn("Could not parse {} test links".format(test_type))
            return []

    def update_integration_status(self, issue, status):
        comment_text = "Testing progress\n\n"
        comment_text += status
        comment = self._find_integration_status_comment(issue.key, "Testing progress")
        if comment is not None:
            comment.update(body=comment_text)
        else:
            self._jira.add_comment(issue.key, comment_text)

    def _find_integration_status_comment(self, issueKey, identifyingString):
        comments = self._jira.comments(issueKey)
        for comment in comments:
            if identifyingString in comment.body:
                return comment
        return None

    def generate_integration_report(self, issue, tests, upgrade_tests, isJiraFormat=False):
        report = "\n"
        if not isJiraFormat:
            report += "ticket: {} - {}\n".format(issue.key, issue.fields.summary)
            report += "status: {}\n\n".format(issue.fields.status)

        tablefmt = "jira" if isJiraFormat else "psql"

        _, data = get_data_for_print(tests, withStatus=(not isJiraFormat), withAssignee=False)
        report += "Test results:\n"
        report += tabulate(data, headers="keys", tablefmt=tablefmt) + "\n"

        report += "Upgrade test results:\n"
        _, data = get_data_for_print(upgrade_tests, withStatus=(not isJiraFormat), withAssignee=False)
        report += tabulate(data, headers="keys", tablefmt=tablefmt) + "\n"

        return report

    def get_integration_status(self, issue):
        if issue.fields.project.name != "Integration":
            logger.error("Expecting {} to be an integration ticket".format(key))
            sys.exit(1)
        tests_issues = self.get_issues_from_search_url(issue, "monkey")
        upgrade_tests_issues = self.get_issues_from_search_url(issue, "upgrade")

        return tests_issues, upgrade_tests_issues

    def update_epic(self, key):
        try:
            epic = self._jira.issue(key)
            if epic.fields.issuetype.name != "Epic":
                logger.warn("Issue %s is not an Epic", epic.key)
                return
            logger.info("updating Epic %s", key)

            if epic.fields.project.name == "QA":
                return
            total, closed, resolved = self.calculate_progress_for_issues(key)
            if total == 0:
                deliveredPercent = 0
                resolvedPercent = 0
            else:
                deliveredPercent = 100 * float(closed)/float(total)
                resolvedPercent = 100 * float(resolved + closed)/float(total)
            strDeliveredPercent = "%s%%" % int(deliveredPercent)
            strResolvedPercent = "%s%%" % int(resolvedPercent)
            prevDeliveredPercent = get_raw_field(epic, FIELD_DELIVERED_PERCENT)
            prevResolvedPercent = get_raw_field(epic, FIELD_RESOLVED_PERCENT)
            if prevResolvedPercent != strResolvedPercent or prevDeliveredPercent != strDeliveredPercent:
                epic.update(fields={FIELD_DELIVERED_PERCENT: strDeliveredPercent,
                                    FIELD_RESOLVED_PERCENT: strResolvedPercent},
                            notify=False)
            else:
                logger.debug("Progress of epic %s, not changed. Skipping update", epic.key)
        except Exception as e:
            log_exception("error updating Epic {}".format(key))


class buildEpicFilterAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super(buildEpicFilterAction, self).__init__(option_strings, dest, nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, SEARCH_QUERY_EPICS + values)


def calc_tests_success_rate(issues):
    class TestStats():
        def __init__(self):
            self._passed_count = 0
            self._failed_count = 0
            self._other_count = 0

        def add_test(self, status):
            if status.lower() == 'passed':
                self._passed_count += 1
            elif status.lower() in ('failed', 'triaged', 'invalid'):
                self._failed_count += 1
            else:
                self._other_count += 1
        def __str__(self):
            return "passed %{}".format(float(self._passed_count)*100/(self._passed_count+self._failed_count))

    tests = defaultdict(TestStats)
    for issue in issues:
        try:
            test_name = get_raw_field(issue, FIELD_TEST_NAME)[0]
        except:
            print("Filter for test resuts must contain only TT issues in the results")
            return
        tests[test_name].add_test(issue.fields.status.name)

    table = []
    for name, stats in tests.items():
        total = stats._passed_count+stats._failed_count
        row = OrderedDict([('test', name),
               ('passed', stats._passed_count),
               ('failed', stats._failed_count),
               ('passed rate', int(float(stats._passed_count)*100/total))])
        table.append(row)
    print(tabulate(table, headers="keys", tablefmt="psql"))

if __name__ == "__main__":
    helpDescription = textwrap.dedent("""
    Tool to help perform common operations on Jira tickets
    Use it to select Jirat ticket using one of the selection arguments,
    then perform one of the supported operations on the selected ticket.
    """)

    helpEpilog = textwrap.dedent("""
    Usage examples:
    \tChange the fixVersion of STOR-1111 to v1.1.1:
    \t\tjira_cmd.py -i STOR-1111 -f v1.1.1

    \tIf STOR-1111 is an Epic, change fixVersion of tickets in the Epic to v1.1.1
    \t\tjira_cmd.py -i STOR-1111 -et -f v1.1.1

    \tPrint all Epics for current relase
    \t\tjira_cmd.py -ce -p

    \tPrint all tickets that belong to Epics for current relase
    \t\tjira_cmd.py -ce -et -p

    """)
    parser = argparse.ArgumentParser(epilog=helpEpilog,
                                     description=helpDescription,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    loginGroup = parser.add_argument_group(title="Jira login options")
    loginArgs = loginGroup.add_mutually_exclusive_group()
    loginArgs.add_argument("--netrc", default="~/.netrc", help="netrc file")
    loginArgs.add_argument("-d", "--default-user", action="store_true", help="Login using default tester user")
    selectorsGroup = parser.add_argument_group(title="Issues selection")
    selectors = selectorsGroup.add_mutually_exclusive_group(required=True)
    selectors.add_argument("-s", "--search-query", required=False, help="Search query to use")
    selectors.add_argument("-i", "--issue", required=False, help="Issue key")
    selectors.add_argument("-bz", "--bz-issue", required=False, help="BZ issue key")
    selectors.add_argument("-I", "--integration-status", help="Select the TT issues running for an integration ticket")
    selectors.add_argument("-nf", "--named-filter", action=buildEpicFilterAction, dest="search_query",  help="Search for Epics matching the given named filter")
    selectors.add_argument("-tt", "--triaging-tickets", action='store_const',
                           dest="search_query", const='project = MGMT AND component = "Assisted-installer Triage"', help="Search for Assisted Installer triaging tickets")
    selectors.add_argument("-ce", "--current-version-epics", action='store_const',
                           dest="search_query", const=SEARCH_QUERY_EPICS + CURRENT_VERSION_FILTER, help="Search for Epics planned for current version")
    selectors.add_argument("-ne", "--next-version-epics", action="store_const",
                           dest="search_query", const=SEARCH_QUERY_EPICS + NEXT_VERSION_FILTER, help="Search for Epics planned for next version")
    parser.add_argument("-li", "--linked-issues", action="store_true", help="Output the issues linked to selected issues")
    parser.add_argument("-m", "--max-results", default=MAX_RESULTS, help="Maximum results to return for search query")
    parser.add_argument("-t", "--tt-report", action="store_true", help="Search output tailored for for TT tickets")
    parser.add_argument("-v", "--verbose", action="store_true", help="Output verbose logging")
    parser.add_argument("-et", "--epic-tasks", action="store_true", help="Operate on tickets that belong to epics in selection, instead of the selected tickets themselves")
    opsGroup = parser.add_argument_group(title="Operations to perform on selected issues")
    ops = opsGroup.add_mutually_exclusive_group(required=True)
    ops.add_argument("-p", "--print-report", action="store_true", help="Print issues details")
    ops.add_argument("-pc", "--print-csv-report", action="store_true", help="Print issues details")
    ops.add_argument("-pmd", "--print-markdown-report", action="store_true", help="Print issues details")
    ops.add_argument("-al", "--link-to", default=None, help="Link tickets from search result to provided ticket")
    ops.add_argument("-rl", "--remove-link", default=None, help="Remove the provided ticket tickets in search results")
    ops.add_argument("-aw", "--add-watchers", default=None, nargs="+", help="Add the watcher to the selected tickets")
    ops.add_argument("-rw", "--remove-watchers", default=None, nargs="+", help="Remove the watcher from the selected tickets")
    ops.add_argument("-e", "--update-epic-progress", action="store_true", help="update epics progress according to its issues")
    ops.add_argument("-S", "--print-servers", action="store_true", help="Print the rackattack servers that the test used")
    ops.add_argument("-f", "--fix-version", help="Set the fixVersion of selected tickets")
    ops.add_argument("-ui", "--update-integration", action="store_true", help="Update integration ticket with the status of the tests. This option is only valid with the -I selectors")
    ops.add_argument("-tr", "--test-success-rate", action="store_true", help="Calculate tests success rate")
    args = parser.parse_args()

    if args.verbose:
        isVerbose = True
        logging.getLogger("__main__").setLevel(logging.DEBUG)

    if args.update_integration and args.integration_status is None:
        logger.error("'Update integration' operation is only valid with the 'integration status' selector")
        sys.exit(1)

    if args.default_user:
        j = jira_default_login()
    else:
        j = jira_netrc_login(args.netrc)
    jiraTool = JiraTool(j, maxResults=args.max_results)

    if args.integration_status is not None:
        try:
            issue = jiraTool.jira().issue(args.integration_status)
        except:
            log_exception("Could not get issue {}".format(args.integration_status))
            sys.exit(1)

        tests, upgrade_tests = jiraTool.get_integration_status(issue)
        if args.update_integration:
            status = jiraTool.generate_integration_report(issue, tests, upgrade_tests, isJiraFormat=True)
            jiraTool.update_integration_status(issue, status)

        print(jiraTool.generate_integration_report(issue, tests, upgrade_tests, isJiraFormat=False))
        sys.exit()

    if args.issue is not None:
        issues = [jiraTool.jira().issue(args.issue)]
    elif args.bz_issue is not None:
        issues = jiraTool.jira().search_issues('project = OCPBUGSM AND component = assisted-installer and summary ~ "{}"'.format(args.bz_issue))
    else:
        issues = jiraTool.jira().search_issues(args.search_query, maxResults=args.max_results)

    if args.update_epic_progress:
        for epic in issues:
            jiraTool.update_epic(epic.key)
        sys.exit(0)

    if args.test_success_rate:
        calc_tests_success_rate(issues)

    if args.add_watchers is not None or args.remove_watchers is not None:
        if args.add_watchers is not None:
            for i in jiraTool.get_selected_issues(issues, args.epic_tasks, args.linked_issues):
                jiraTool.add_watchers(i, args.add_watchers)

        if args.remove_watchers is not None:
            for i in jiraTool.get_selected_issues(issues, args.epic_tasks, args.linked_issues):
                jiraTool.remove_watchers(i, args.remove_watchers)
        sys.exit()

    if args.link_to is not None or args.remove_link is not None:
        if args.link_to is not None:
            to_ticket = jiraTool.jira().issue(args.link_to)
            logger.info("Linking search result to %s", to_ticket.key)
            for i in jiraTool.get_selected_issues(issues, args.epic_tasks, args.linked_issues):
                jiraTool.link_tickets(i, to_ticket)

        if args.remove_link is not None:
            to_remove = jiraTool.jira().issue(args.remove_link)
            logger.info("Removing link to %s from search result to: ", to_remove)
            for i in jiraTool.get_selected_issues(issues, args.epic_tasks, args.linked_issues):
                jiraTool.remove_links(i, to_remove)
        sys.exit()

    if args.fix_version is not None:
        for i in jiraTool.get_selected_issues(issues, args.epic_tasks, args.linked_issues):
            if len(i.fields.fixVersions) != 1 or args.fix_version != i.fields.fixVersions[0].name:
                if i.fields.status.name in ["Closed"]:
                    logger.info("Not changing fixVersion of {}, because it is {}".format(i.key,
                                                                                         i.fields.status))
                    continue

                logger.info("setting fixVersion %s to issue %s", args.fix_version, i.key)
                i.fields.fixVersions = [{'name': args.fix_version}]
                try:
                    i.update(fields={'fixVersions': i.fields.fixVersions},
                             notify=False)
                except:
                    log_exception("Could not set fixVersion of {}".format(i.key))
            else:
                logger.info("issue {} is already at fixVersion {}".format(i.key, args.fix_version))
        sys.exit()

    if args.print_servers:
        for i in jiraTool.get_selected_issues(issues, args.epic_tasks, args.linked_issues):
            try:
                servers = get_raw_field(i, FIELD_TEST_SERVERS)
                if servers is None:
                    continue
                print("%s:" % i.key)
                for server in servers:
                    print(server)
            except:
                pass
                sys.exit()

    if args.print_report:
        print_report_table(jiraTool.get_selected_issues(issues, args.epic_tasks, args.linked_issues), args.tt_report)
    elif args.print_markdown_report:
        print_report_table(jiraTool.get_selected_issues(issues, args.epic_tasks, args.linked_issues), args.tt_report,
                           isMarkdown=True)
    elif args.print_csv_report:
        print_report_csv(jiraTool.get_selected_issues(issues, args.epic_tasks, args.linked_issues), args.tt_report)
