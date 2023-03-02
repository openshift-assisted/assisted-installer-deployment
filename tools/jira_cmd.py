#!/usr/bin/env python
# pylint: disable=invalid-name,bare-except

# A tool to perform various operations on Jira

import argparse
import csv
import io
import json
import logging
import os
import pprint
import re
import sys
import textwrap
from collections import Counter

from tabulate import tabulate

from tools.jira_client import JiraClientFactory

FIELD_SPRINT = "customfield_12310940"
FIELD_CONTRIBUTORS = "customfield_12315950"

MAX_RESULTS = 100
TRIAGE_MAX_RESULTS = 300

SEARCH_QUERY_EPICS = 'project = MGMT AND component = "MGMT OCP Metal" AND type = Epic AND filter = '
CURRENT_VERSION_FILTER = "12347072"
NEXT_VERSION_FILTER = "12347073"
VALID_PRINT_FIELDS = ["key", "summary", "component", "priority", "status", "assignee", "fixVersion", "sprint"]
DEFAULT_PRINT_FIELDS = ["component", "priority", "status", "assignee"]
PERMENANT_PRINT_FIELDS = ["key", "summary"]
TEAM_COMPONENT_PREFIX = "AI-Team"
NONE_EDGE_COMPONENTS = ["MGMT Integration"]
PROJECT_LABELS = ["KNI-EDGE-4.8", "KNI-EDGE-4.8-DAY2"]
ADMIN_ROLE_ID = "10002"

logging.basicConfig(level=logging.WARN, format="%(levelname)-10s %(message)s")
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)
isVerbose = False
isDryRun = False


def log_exception(msg):
    if isVerbose:
        logger.exception(msg)
    else:
        logger.error(msg)


def get_raw_field(issue, fieldName):
    try:
        return issue.fields.__dict__[fieldName]
    except Exception:
        return None


def get_sprint_name(issue):
    sprint_str = get_raw_field(issue, FIELD_SPRINT)
    if not sprint_str:
        return None

    m = re.findall(r",name=([^,]+),", sprint_str[0])
    if not m:
        return None

    return m[0]


def get_sprint_id(issue):
    sprint_str = get_raw_field(issue, FIELD_SPRINT)
    if not sprint_str:
        return None

    m = re.findall(r",sequence=([0-9]+),", sprint_str[0])
    if not m:
        return None

    return int(m[0])


def get_assignee(issue):
    try:
        return issue.fields.assignee.displayName
    except Exception:
        try:
            return issue.raw["fields"]["assignee"]["displayName"]
        except Exception:
            return "Unassigned"


def format_key_for_print(key, isMarkdown):
    if not isMarkdown:
        return key

    return f"[{key}](https://issues.redhat.com/browse/{key})"


def get_data_for_print(issues, issues_count=None, print_fields=None):
    if not print_fields:
        print_fields = DEFAULT_PRINT_FIELDS

    headers = PERMENANT_PRINT_FIELDS + print_fields
    if issues_count:
        headers.append("count")

    table = []
    for i in issues:
        row = {}
        if "key" in headers:
            row["key"] = i.key
        if "summary" in headers:
            row["summary"] = i.fields.summary
        if "component" in headers:
            row["component"] = [c.name for c in i.fields.components]
        if "priority" in headers:
            try:
                row["priority"] = i.fields.priority.name
            except Exception:
                row["priority"] = i.fields.priority
        if "status" in headers:
            row["status"] = str(i.fields.status)
        if "fixVersion" in headers:
            row["fixVersion"] = "" if len(i.fields.fixVersions) == 0 else i.fields.fixVersions[0].name
        if "assignee" in headers:
            assignee = get_assignee(i)
            row["assignee"] = assignee
        if "sprint" in headers:
            sid = get_sprint_id(i)
            if sid:
                row["sprint"] = "({}) {}".format(sid, get_sprint_name(i))
            else:
                row["sprint"] = ""
        if issues_count:
            row["count"] = issues_count[i.key]
        table.append(row)

    return headers, table


def print_report_csv(issues, issues_count=None, print_fields=None):
    headers, data = get_data_for_print(issues, issues_count=issues_count, print_fields=print_fields)
    output = io.StringIO()
    csvout = csv.DictWriter(output, delimiter="|", fieldnames=headers)
    csvout.writeheader()
    for row in data:
        csvout.writerow(row)

    return output.getvalue()


def print_report_json(issues, issues_count=None, print_fields=None):
    _, data = get_data_for_print(issues, issues_count=issues_count, print_fields=print_fields)
    return json.dumps(data)


def print_report_table(issues, isMarkdown=False, issues_count=None, print_fields=None):
    _, data = get_data_for_print(issues, issues_count=issues_count, print_fields=print_fields)
    fmt = "github" if isMarkdown else "psql"
    return tabulate(data, headers="keys", tablefmt=fmt)


def print_raw(issues):
    for i in issues:
        pprint.pprint(i.raw)


class JiraTool:
    def __init__(self, j, maxResults=MAX_RESULTS):
        self._jira = j
        self._maxResults = maxResults
        self._admin_in_projects = {}

    def jira(self):
        return self._jira

    def is_admin_in_project(self, project):
        try:
            return self._admin_in_projects[project]
        except Exception:
            pass

        is_admin = False
        try:
            is_admin = self._jira.my_permissions(project)["permissions"]["PROJECT_ADMIN"]["havePermission"]
        except Exception:
            log_exception("Cannot get permissions for project {}".format(project))

        self._admin_in_projects[project] = is_admin
        return is_admin

    def link_tickets(self, ticket, to_ticket):
        try:
            logger.info("linking %s to %s", to_ticket.key, ticket.key)
            res = self._jira.create_issue_link("relates to", ticket, to_ticket)
            res.raise_for_status()
        except Exception:
            logger.exception("Error linking to %s", to_ticket.key)

    def update_issue_fields(self, issue, fields_dict):
        if isDryRun:
            print("Updating issue {} with fields: {}".format(issue.key, fields_dict))
        else:
            issue.update(fields=fields_dict, notify=self.is_admin_in_project(issue.fields.project.key))

    def add_assignee_as_contributor(self, ticket):
        try:
            assignee = ticket.fields.assignee
            if not assignee:
                logger.debug("Ticket %s is not assigned", ticket.key)
                return

            contributors = get_raw_field(ticket, FIELD_CONTRIBUTORS)
            if not contributors:
                contributors = []
            contributor_names = [u.name for u in contributors]
            if assignee.name in contributor_names:
                logger.debug("%s is already contributor of %s", assignee.name, ticket.key)
                return
            contributor_names.append(assignee.name)
            logger.info("Adding %s as contributor to %s", assignee.name, ticket.key)
            self.update_issue_fields(ticket, {FIELD_CONTRIBUTORS: [{"name": u} for u in contributor_names]})
        except Exception:
            logger.exception("Error adding contributor to %s", ticket.key)

    def add_watchers(self, ticket, watchers):
        try:
            for watcher in watchers:
                logger.info("Adding %s as watcher to %s", watcher, ticket.key)
                self._jira.add_watcher(ticket.key, watcher)
        except Exception:
            logger.exception("Error adding watcher to %s", ticket.key)

    def remove_watchers(self, ticket, watchers):
        try:
            for watcher in watchers:
                logger.info("removing %s as watcher from %s", watcher, ticket.key)
                self._jira.remove_watcher(ticket.key, watcher)
        except Exception:
            logger.exception("Error removing watcher to %s", ticket.key)

    @staticmethod
    def get_team_component(issue):
        for c in issue.fields.components:
            if c.name.startswith(TEAM_COMPONENT_PREFIX):
                return c
        return None

    @staticmethod
    # Returns True if one of the components provided is assigend to the issue
    def get_existing_components(issue, components):
        existing = []
        for c in issue.fields.components:
            for rc in components:
                if rc == c.name:
                    existing.append(rc)
        return existing

    @staticmethod
    def get_project_labels(issue):
        labels = []
        for label in issue.fields.labels:
            if label in PROJECT_LABELS:
                labels.append(label)

        return labels

    # There can only be one team component for an issue, so adding
    # a team component, will replace the previous team component
    def add_component(self, issue, component):
        is_team_component = False
        if component.startswith(TEAM_COMPONENT_PREFIX):
            is_team_component = True
        names = []
        for c in issue.fields.components:
            if c.name == component:
                logger.debug("%s, is already in %s", component, issue.key)
                return
            if is_team_component and c.name.startswith(TEAM_COMPONENT_PREFIX):
                logger.info("Removing team component %s from %s", c.name, issue.key)
            else:
                names.append({"name": c.name})
        names.append({"name": component})
        logger.info("add_component: updating %s with components: %s", issue.key, names)
        self.update_issue_fields(issue, {"components": names})

    def remove_component(self, issue, component):
        was_found = False
        names = []
        for c in issue.fields.components:
            if c.name == component:
                logger.info("removing %s from %s", component, issue.key)
                was_found = True
            else:
                names.append({"name": c.name})
        if not was_found:
            logger.debug("remove_component: component %s not found in %s", component, issue.key)
        else:
            logger.info("remove_component: updating %s with components: %s", issue.key, names)
            self.update_issue_fields(issue, {"components": names})

    def add_labels(self, issue, labels):
        new_labels = labels.copy()
        for label in issue.fields.labels:
            if label in labels:
                logger.debug("%s, is already in %s", label, issue.key)
            else:
                new_labels.append(label)
        if new_labels != issue.fields.labels:
            logger.info("add_labels: updating %s with labels: %s", issue.key, new_labels)
            self.update_issue_fields(issue, {"labels": new_labels})

    def remove_labels(self, issue, labels):
        was_found = False
        new_labels = []
        for label in issue.fields.labels:
            if label in labels:
                logger.info("removing %s from %s", label, issue.key)
                was_found = True
            else:
                new_labels.append(label)
        if not was_found:
            logger.debug("remove_labels: labels %s not found in %s", labels, issue.key)
        else:
            logger.info("remove_labels: updating %s with labels: %s", issue.key, new_labels)
            self.update_issue_fields(issue, {"labels": new_labels})

    def remove_comment(self, issue, identifying_string):
        was_found = False
        comments = self._jira.comments(issue.key)
        for comment in comments:
            if identifying_string in comment.body:
                was_found = True
                comment.delete()
                logger.info("remove_comment: removing comment '%s' from %s", identifying_string, issue.key)
                print("Removing comment: {}".format(comment.body))

        if not was_found:
            logger.debug("remove_comment: comment '%s' not found in %s", identifying_string, issue.key)

    def get_selected_linked_issues(self, issues):
        linked_issue_keys = []
        linked_issues = []
        for i in issues:
            for label in i.fields.issuelinks:
                linked_issue_keys.append(self.extract_linked_issue(label).key)

        issue_keys_count = Counter(linked_issue_keys)
        if linked_issue_keys:
            linked_issues = self._jira.search_issues(
                "project != AITRIAGE AND issue in (%s)" % (",".join(set(linked_issue_keys))),
                maxResults=self._maxResults,
            )
        # remove triaging tickets from the list
        filtered_linked_issues = []
        for i in linked_issues:
            if "Assisted-installer Triage" not in [c.name for c in i.fields.components]:
                filtered_linked_issues.append(i)

        return filtered_linked_issues, issue_keys_count

    def get_selected_issues(self, issues, isEpicTasks=False, onlyMgmtIssues=False):
        if not isEpicTasks:
            return issues

        extra_filter = ""
        if onlyMgmtIssues:
            extra_filter = " and project = MGMT"
        return self._jira.search_issues(
            '"Epic Link" in (%s) %s' % (",".join([i.key for i in issues]), extra_filter), maxResults=self._maxResults
        )

    @staticmethod
    def extract_linked_issue(issue_link):
        try:
            return issue_link.outwardIssue
        except Exception:
            return issue_link.inwardIssue

    def remove_links(self, ticket, to_remove):
        for link in ticket.fields.issuelinks:
            key = self.extract_linked_issue(link).key

            if key == to_remove.key:
                try:
                    logger.info("removing link %s", key)
                    link.delete()
                except Exception:
                    log_exception("Error removing link {}".format(key))

    def get_issues_in_epic(self, key):
        issues = self._jira.search_issues('"Epic Link" in (%s)' % key, maxResults=self._maxResults)
        if len(issues) == 0:
            epic = self._jira.issue(key)
            issues = [self._jira.issue(s.key) for s in epic.fields.subtasks]
        return issues


class buildEpicFilterAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, nargs, **kwargs)

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


def epic_fixup(jtool, epic_list):
    for epic in epic_list:
        if epic.fields.issuetype.name != "Epic":
            logger.debug("Issue %s is not an Epic", epic.key)
            continue
        logger.info("Fixing epic %s", epic.key)

        jtool.add_assignee_as_contributor(epic)

        team = jtool.get_team_component(epic)
        project_labels = jtool.get_project_labels(epic)
        epic_issues = jtool.get_selected_issues([epic], isEpicTasks=True, onlyMgmtIssues=True)

        if team:
            for i in epic_issues:
                if not jtool.get_existing_components(i, NONE_EDGE_COMPONENTS):
                    jtool.add_component(i, team.name)
        else:
            # should remove any Team Component from the epic tasks?
            pass

        if project_labels:
            for i in epic_issues:
                jtool.add_labels(i, project_labels)

        missing_project_labels = [label for label in PROJECT_LABELS if label not in project_labels]
        if missing_project_labels:
            for i in epic_issues:
                jtool.remove_labels(i, missing_project_labels)


def handle_component_update(args, jiraTool, issues):
    if args.add_component is not None:
        for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
            jiraTool.add_component(i, args.add_component)

    if args.remove_component is not None:
        for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
            jiraTool.remove_component(i, args.remove_component)


def handle_labels_update(args, jiraTool, issues):
    if args.add_labels is not None:
        for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
            jiraTool.add_labels(i, args.add_labels)

    if args.remove_labels is not None:
        for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
            jiraTool.remove_labels(i, args.remove_labels)


def handle_remove_comment(args, jiraTool, issues):
    for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
        jiraTool.remove_comment(i, args.remove_comment)


def handle_watchers_update(args, jiraTool, issues):
    if args.add_watchers is not None:
        for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
            jiraTool.add_watchers(i, args.add_watchers)

    if args.remove_watchers is not None:
        for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
            jiraTool.remove_watchers(i, args.remove_watchers)


def handle_link_update(args, jiraTool, issues):
    if args.link_to is not None:
        to_ticket = jiraTool.jira().issue(args.link_to)
        logger.info("Linking search result to %s", to_ticket.key)
        for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
            jiraTool.link_tickets(i, to_ticket)

    if args.remove_link is not None:
        to_remove = jiraTool.jira().issue(args.remove_link)
        logger.info("Removing link to %s from search result to: ", to_remove)
        for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
            jiraTool.remove_links(i, to_remove)


def handle_fix_version_update(args, jiraTool, issues):
    for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
        if len(i.fields.fixVersions) != 1 or args.fix_version != i.fields.fixVersions[0].name:
            if i.fields.status.name in ["Closed"]:
                logger.info("Not changing fixVersion of %s because it is %s", i.key, i.fields.status)
                continue

            logger.info("setting fixVersion %s to issue %s", args.fix_version, i.key)
            i.fields.fixVersions = [{"name": args.fix_version}]
            try:
                jiraTool.update_issue_fields(i, {"fixVersions": i.fields.fixVersions})
            except Exception:
                log_exception("Could not set fixVersion of {}".format(i.key))
        else:
            logger.info("issue %s is already at fixVersion %s", i.key, args.fix_version)


def handle_sprint_update(args, jiraTool, issues):
    for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
        sprint_value = get_sprint_id(i)
        if sprint_value == args.sprint:
            logger.debug("Issue %s is already at sprint %s", i.key, args.sprint)
            continue

        logger.info("setting sprint %s to issue %s", args.sprint, i.key)
        try:
            jiraTool.update_issue_fields(i, {FIELD_SPRINT: args.sprint})
        except Exception:
            log_exception("Could not set sprint of {}".format(i.key))


def main(args):
    j = JiraClientFactory.create(args.jira_access_token)

    max_results = args.max_results
    if args.max_results == MAX_RESULTS and args.linked_issues:
        logger.debug("Increasing the Jira maxResults param to %s", TRIAGE_MAX_RESULTS)
        max_results = TRIAGE_MAX_RESULTS
    jiraTool = JiraTool(j, maxResults=max_results)

    if args.issue is not None:
        issues = [jiraTool.jira().issue(args.issue)]
    elif args.bz_issue is not None:
        issues = jiraTool.jira().search_issues(
            'project = OCPBUGSM AND component = assisted-installer and summary ~ "{}"'.format(args.bz_issue)
        )
    else:
        issues = jiraTool.jira().search_issues(args.search_query, maxResults=args.max_results)

    if args.sprint:
        handle_sprint_update(args, jiraTool, issues)
        sys.exit()

    if args.epic_fixup:
        epic_fixup(jiraTool, jiraTool.get_selected_issues(issues))
        sys.exit()

    if args.update_contributors:
        for i in jiraTool.get_selected_issues(issues, args.epic_tasks):
            jiraTool.add_assignee_as_contributor(i)
        sys.exit()

    if args.add_labels is not None or args.remove_labels is not None:
        handle_labels_update(args, jiraTool, issues)
        sys.exit()

    if args.remove_comment is not None:
        handle_remove_comment(args, jiraTool, issues)

    if args.add_component is not None or args.remove_component is not None:
        handle_component_update(args, jiraTool, issues)
        sys.exit()

    if args.add_watchers is not None or args.remove_watchers is not None:
        handle_watchers_update(args, jiraTool, issues)
        sys.exit()

    if args.link_to is not None or args.remove_link is not None:
        handle_link_update(args, jiraTool, issues)
        sys.exit()

    if args.fix_version is not None:
        handle_fix_version_update(args, jiraTool, issues)
        sys.exit()

    issues_count = None
    if args.linked_issues:
        issues, issues_count = jiraTool.get_selected_linked_issues(issues)
    else:
        issues = jiraTool.get_selected_issues(issues, args.epic_tasks)

    if args.print_raw:
        print_raw(issues)
    if args.print_report:
        return print_report_table(
            filter_issue_status(issues, args.include_status), issues_count=issues_count, print_fields=args.print_field
        )
    elif args.print_markdown_report:
        return print_report_table(
            filter_issue_status(issues, args.include_status),
            isMarkdown=True,
            issues_count=issues_count,
            print_fields=args.print_field,
        )
    elif args.print_json:
        return print_report_json(
            filter_issue_status(issues, args.include_status), issues_count=issues_count, print_fields=args.print_field
        )
    elif args.print_csv_report:
        return print_report_csv(
            filter_issue_status(issues, args.include_status), issues_count=issues_count, print_fields=args.print_field
        )
    return ""


def build_parser():
    VALID_STATUS = ["QE Review", "To Do", "Done", "Obsolete", "Code Review", "In Progress"]
    helpDescription = textwrap.dedent(
        """
    Tool to help perform common operations on Jira tickets
    Use it to select Jirat ticket using one of the selection arguments,
    then perform one of the supported operations on the selected ticket.
    """
    )

    helpEpilog = textwrap.dedent(
        """
    Usage examples:
    \tChange the fixVersion of STOR-1111 to v1.1.1:
    \t\tjira_cmd.py -i STOR-1111 -f v1.1.1

    \tIf STOR-1111 is an Epic, change fixVersion of tickets in the Epic to v1.1.1
    \t\tjira_cmd.py -i STOR-1111 -et -f v1.1.1

    \tPrint all Epics for current relase
    \t\tjira_cmd.py -ce -p

    \tPrint all tickets that belong to Epics for current relase
    \t\tjira_cmd.py -ce -et -p

    """
    )
    parser = argparse.ArgumentParser(
        epilog=helpEpilog, description=helpDescription, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    loginGroup = parser.add_argument_group(title="Jira login options")
    loginArgs = loginGroup.add_mutually_exclusive_group()
    loginArgs.add_argument(
        "--jira-access-token",
        default=os.environ.get("JIRA_ACCESS_TOKEN"),
        required=False,
        help="PAT (personal access token) for accessing Jira",
    )
    selectorsGroup = parser.add_argument_group(title="Issues selection")
    selectors = selectorsGroup.add_mutually_exclusive_group(required=True)
    selectors.add_argument("-s", "--search-query", required=False, help="Search query to use")
    selectors.add_argument("-i", "--issue", required=False, help="Issue key")
    selectors.add_argument("-bz", "--bz-issue", required=False, help="BZ issue key")
    selectors.add_argument(
        "-crepics",
        "--current-release-epics-filter",
        action=buildEpicFilterAction,
        dest="search_query",
        help="Search for Epics matching the given named filter",
    )
    selectors.add_argument(
        "-nf",
        "--named-filter",
        action=buildEpicFilterAction,
        dest="search_query",
        help="Search for Epics matching the given named filter",
    )
    selectors.add_argument(
        "-cre",
        "--current-release-epics",
        action="store_const",
        dest="search_query",
        const='filter in ("AI sprint planning current epics")',
        help="Search for current release epics",
    )
    selectors.add_argument(
        "-eff",
        "--epics-for-fixup",
        action="store_const",
        dest="search_query",
        const='filter = "AI epics for fixup"',
        help="Search for epics for fixup operation",
    )
    selectors.add_argument(
        "-tt",
        "--triaging-tickets",
        action="store_const",
        dest="search_query",
        const='project = AITRIAGE AND component = "Cloud-Triage" ORDER BY key DESC',
        help="Search for Assisted Installer triaging tickets",
    )
    selectors.add_argument(
        "-rtt",
        "--recent-triaging-tickets",
        action="store_const",
        dest="search_query",
        const='project = AITRIAGE AND component = "Cloud-Triage" AND created > -7d',
        help="Search for Assisted Installer triaging tickets",
    )
    selectors.add_argument(
        "-ce",
        "--current-version-epics",
        action="store_const",
        dest="search_query",
        const=SEARCH_QUERY_EPICS + CURRENT_VERSION_FILTER,
        help="Search for Epics planned for current version",
    )
    selectors.add_argument(
        "-ne",
        "--next-version-epics",
        action="store_const",
        dest="search_query",
        const=SEARCH_QUERY_EPICS + NEXT_VERSION_FILTER,
        help="Search for Epics planned for next version",
    )
    parser.add_argument(
        "-li", "--linked-issues", action="store_true", help="Output the issues linked to selected issues"
    )
    parser.add_argument("-m", "--max-results", default=MAX_RESULTS, help="Maximum results to return for search query")
    parser.add_argument("-v", "--verbose", action="store_true", help="Output verbose logging")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Do not update tickets")
    parser.add_argument(
        "-et",
        "--epic-tasks",
        action="store_true",
        help="Operate on tickets that belong to epics in selection, instead of the selected tickets themselves",
    )
    parser.add_argument(
        "-is",
        "--include-status",
        action="append",
        choices=VALID_STATUS,
        help="filter issues based on supplied statuses when printing the issues details",
    )
    parser.add_argument(
        "-pf", "--print-field", action="append", choices=VALID_PRINT_FIELDS, help="Add provided fields to the output"
    )
    opsGroup = parser.add_argument_group(title="Operations to perform on selected issues")
    ops = opsGroup.add_mutually_exclusive_group(required=True)
    ops.add_argument("-p", "--print-report", action="store_true", help="Print issues details")
    ops.add_argument("-pr", "--print-raw", action="store_true", help="Print raw issues details")
    ops.add_argument("-pc", "--print-csv-report", action="store_true", help="Print issues details")
    ops.add_argument("-pj", "--print-json", action="store_true", help="Print issues details")
    ops.add_argument("-pmd", "--print-markdown-report", action="store_true", help="Print issues details")
    ops.add_argument("-al", "--link-to", default=None, help="Link tickets from search result to provided ticket")
    ops.add_argument("-rl", "--remove-link", default=None, help="Remove the provided ticket tickets in search results")
    ops.add_argument(
        "-sp", "--sprint", default=None, type=int, help="Assigne the tickets in search results to the provided sprint"
    )
    ops.add_argument("-aw", "--add-watchers", default=None, nargs="+", help="Add the watcher to the selected tickets")
    ops.add_argument(
        "-rw", "--remove-watchers", default=None, nargs="+", help="Remove the watcher from the selected tickets"
    )
    ops.add_argument("-ac", "--add-component", default=None, help="Add the component to the selected tickets")
    ops.add_argument("-rc", "--remove-component", default=None, help="Remove the component from the selected tickets")
    ops.add_argument("-ala", "--add-labels", default=None, nargs="+", help="Add the label to the selected tickets")
    ops.add_argument(
        "-rla", "--remove-labels", nargs="+", default=None, help="Remove the label from the selected tickets"
    )
    ops.add_argument("--remove-comment", help="Remove comments that have the provided text")
    ops.add_argument("-f", "--fix-version", help="Set the fixVersion of selected tickets")
    ops.add_argument("-uc", "--update-contributors", action="store_true", help="Add assignee to contributors")
    ops.add_argument(
        "-ef",
        "--epic-fixup",
        action="store_true",
        help=textwrap.dedent(
            """
                                                                 Operate on epics. Will perform some common epic related fixups such as:
                                                                 add assignee to the contributor field,
                                                                 add epic's Team component to all tasks.
                                                                 if epic has a project-related label, will add it to all tasks
                                                                 """
        ),
    )
    return parser


if __name__ == "__main__":
    cmdline_args = build_parser().parse_args()

    if cmdline_args.print_json:
        logging.getLogger("__main__").setLevel(logging.WARN)
    if cmdline_args.verbose:
        isVerbose = True
        logging.getLogger("__main__").setLevel(logging.DEBUG)
    if cmdline_args.dry_run:
        isDryRun = True

    print(main(cmdline_args))
