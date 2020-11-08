#!/usr/bin/env python
# pylint: disable=invalid-name,bare-except

# A tool to perform various operations on Jira



import os
import sys
import csv
import argparse
import netrc
import logging
import textwrap
from urllib.parse import urlparse
from tabulate import tabulate
import jira


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

def get_data_for_print(issues, withStatus=True, withAssignee=True, withFixVersion=False,
                       isMarkdown=False):
    headers = ['key', 'summary', 'component', 'priority']
    if withStatus:
        headers.append('status')
    if withAssignee:
        headers.append('assignee')
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
        table.append(row)

    return headers, table


def print_report_csv(issues):
    headers, data = get_data_for_print(issues)
    csvout = csv.DictWriter(sys.stdout, delimiter='|', fieldnames=headers)
    csvout.writeheader()
    for row in data:
        csvout.writerow(row)


def print_report_table(issues, isMarkdown=False):
    _, data = get_data_for_print(issues, isMarkdown=isMarkdown)
    fmt = "github" if isMarkdown else "psql"
    print(tabulate(data, headers="keys", tablefmt=fmt))


class JiraTool():
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
        except:
            logger.exceptio("Error linking to %s", to_ticket.key)

    def add_watchers(self, ticket, watchers):
        try:
            for watcher in watchers:
                logger.info("Adding %s as watcher to %s", watcher, ticket.key)
                self._jira.add_watcher(ticket.key, watcher)
        except:
            logger.exception("Error adding watcher to %s", ticket.key)

    def remove_watchers(self, ticket, watchers):
        try:
            for watcher in watchers:
                logger.info("removing %s as watcher from %s", watcher, ticket.key)
                self._jira.remove_watcher(ticket.key, watcher)
        except:
            logger.exception("Error removing watcher to %s", ticket.key)

    def get_selected_issues(self, issues, isEpicTasks=False, is_issue_links=False):
        if not isEpicTasks and not is_issue_links:
            return issues

        if is_issue_links:
            linked_issue_keys = []
            linked_issues = []
            for i in issues:
                for l in i.fields.issuelinks:
                    linked_issue_keys.append(self.extract_linked_issue(l).key)

            if linked_issue_keys:
                linked_issues = self._jira.search_issues("issue in (%s)" % (",".join(set(linked_issue_keys))),
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
                except:
                    log_exception("Error removing link {}".format(key))

    def get_issues_in_epic(self, key):
        issues = self._jira.search_issues("\"Epic Link\" in (%s)" % key, maxResults=self._maxResults)
        if len(issues) == 0:
            epic = self._jira.issue(key)
            issues = [self._jira.issue(s.key) for s in epic.fields.subtasks]
        return issues


class buildEpicFilterAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super(buildEpicFilterAction, self).__init__(option_strings, dest, nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, SEARCH_QUERY_EPICS + values)


def filter_issue_status(issues, statuses):
    if not statuses:
        return issues

    filtered_issues = []
    for i in issues:
        if i.fields.status.name in statuses:
            filtered_issues.append(i)

    return filtered_issues


def main(args):
    j = jira_netrc_login(args.netrc)
    jiraTool = JiraTool(j, maxResults=args.max_results)

    if args.issue is not None:
        issues = [jiraTool.jira().issue(args.issue)]
    elif args.bz_issue is not None:
        issues = jiraTool.jira().search_issues('project = OCPBUGSM AND component = assisted-installer and summary ~ "{}"'.format(args.bz_issue))
    else:
        issues = jiraTool.jira().search_issues(args.search_query, maxResults=args.max_results)

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
                    logger.info("Not changing fixVersion of %s because it is %s", i.key, i.fields.status)
                    continue

                logger.info("setting fixVersion %s to issue %s", args.fix_version, i.key)
                i.fields.fixVersions = [{'name': args.fix_version}]
                try:
                    i.update(fields={'fixVersions': i.fields.fixVersions},
                             notify=False)
                except:
                    log_exception("Could not set fixVersion of {}".format(i.key))
            else:
                logger.info("issue %s is already at fixVersion %s", i.key, args.fix_version)
        sys.exit()

    issues = jiraTool.get_selected_issues(issues, args.epic_tasks, args.linked_issues)

    if args.print_report:
        print_report_table(filter_issue_status(issues, args.include_status))
    elif args.print_markdown_report:
        print_report_table(filter_issue_status(issues, args.include_status),
                           isMarkdown=True)
    elif args.print_csv_report:
        print_report_csv(filter_issue_status(issues, args.include_status))


if __name__ == "__main__":
    valid_status = ['QE Review', 'To Do', 'Done', 'Obsolete', 'Code Review', 'In Progress']
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
    selectorsGroup = parser.add_argument_group(title="Issues selection")
    selectors = selectorsGroup.add_mutually_exclusive_group(required=True)
    selectors.add_argument("-s", "--search-query", required=False, help="Search query to use")
    selectors.add_argument("-i", "--issue", required=False, help="Issue key")
    selectors.add_argument("-bz", "--bz-issue", required=False, help="BZ issue key")
    selectors.add_argument("-nf", "--named-filter", action=buildEpicFilterAction, dest="search_query",
                           help="Search for Epics matching the given named filter")
    selectors.add_argument("-tt", "--triaging-tickets", action='store_const',
                           dest="search_query", const='project = MGMT AND component = "Assisted-installer Triage"',
                           help="Search for Assisted Installer triaging tickets")
    selectors.add_argument("-ce", "--current-version-epics", action='store_const',
                           dest="search_query", const=SEARCH_QUERY_EPICS + CURRENT_VERSION_FILTER,
                           help="Search for Epics planned for current version")
    selectors.add_argument("-ne", "--next-version-epics", action="store_const",
                           dest="search_query", const=SEARCH_QUERY_EPICS + NEXT_VERSION_FILTER, help="Search for Epics planned for next version")
    parser.add_argument("-li", "--linked-issues", action="store_true", help="Output the issues linked to selected issues")
    parser.add_argument("-m", "--max-results", default=MAX_RESULTS, help="Maximum results to return for search query")
    parser.add_argument("-v", "--verbose", action="store_true", help="Output verbose logging")
    parser.add_argument("-et", "--epic-tasks", action="store_true",
                        help="Operate on tickets that belong to epics in selection, "
                        + "instead of the selected tickets themselves")
    parser.add_argument("-is", "--include-status", nargs="+", choices=valid_status,
                        help="filter issues based on supplied statuses when printing the issues details")
    opsGroup = parser.add_argument_group(title="Operations to perform on selected issues")
    ops = opsGroup.add_mutually_exclusive_group(required=True)
    ops.add_argument("-p", "--print-report", action="store_true", help="Print issues details")
    ops.add_argument("-pc", "--print-csv-report", action="store_true", help="Print issues details")
    ops.add_argument("-pmd", "--print-markdown-report", action="store_true", help="Print issues details")
    ops.add_argument("-al", "--link-to", default=None, help="Link tickets from search result to provided ticket")
    ops.add_argument("-rl", "--remove-link", default=None, help="Remove the provided ticket tickets in search results")
    ops.add_argument("-aw", "--add-watchers", default=None, nargs="+", help="Add the watcher to the selected tickets")
    ops.add_argument("-rw", "--remove-watchers", default=None, nargs="+", help="Remove the watcher from the selected tickets")
    ops.add_argument("-f", "--fix-version", help="Set the fixVersion of selected tickets")
    args = parser.parse_args()

    if args.verbose:
        isVerbose = True
        logging.getLogger("__main__").setLevel(logging.DEBUG)

    main(args)
