#!/usr/bin/env python
# pylint: disable=invalid-name,bare-except,too-many-arguments,redefined-outer-name

import argparse
import subprocess
import csv
import re
import os
import sys
import logging
import netrc
from urllib.parse import urlparse
from collections import defaultdict
import yaml
import jira
import bugzilla
from tabulate import tabulate


logging.basicConfig(level=logging.WARN, format='%(levelname)-10s %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)

REPO_URL_TEMPLATE = "https://github.com/{}"
ISSUES_REGEX = re.compile(r'((MGMT|OCPBUGSM|BZ)-[0-9]+)')

BZ_REFERENCE_FIELD = "customfield_12316840"
DEFAULT_NETRC_FILE = "~/.netrc"
BZ_SERVER = "https://bugzilla.redhat.com"
JIRA_SERVER = "https://issues.redhat.com/"
REPORT_FORMAT_CSV = "csv_report"
REPORT_FORMAT_MARKDOWN = "markdown_report"
REPORT_FORMAT_STD = "std_report"


def get_credentials_from_netrc(server, netrc_file=DEFAULT_NETRC_FILE):
    cred = netrc.netrc(os.path.expanduser(netrc_file))
    username, _, password = cred.authenticators(server)
    return username, password


def get_jira_client(username, password):
    logger.info("log-in to Jira with username: %s", username)
    return jira.JIRA(JIRA_SERVER, basic_auth=(username, password))


def get_bz_client(username, password):
    logger.info("log-in to bugzilla with username: %s", username)
    if username == "apikey":
        return bugzilla.RHBugzilla3(BZ_SERVER, api_key=password)

    return bugzilla.RHBugzilla3(BZ_SERVER, user=username, password=password)

def create_dir(dirname):
    try:
        os.mkdir(dirname)
    except:
        pass

def clone_repo(repo):
    dirname = "temp/{}".format(os.path.basename(repo))
    if os.path.isdir(dirname):
        subprocess.check_call("git fetch -tf", shell=True, cwd=dirname)
    else:
        repo_url = REPO_URL_TEMPLATE.format(repo)
        subprocess.check_call("git clone {}".format(repo_url), shell=True, cwd="temp")
    return dirname

def get_issues_list_for_repo(repo, from_commit, to_commit):
    create_dir("temp")
    dirname = clone_repo(repo)
    raw_log = subprocess.check_output("git log --pretty=medium {}...{} ".format(from_commit, to_commit),
                                      shell=True, cwd=dirname)
    matches = ISSUES_REGEX.findall(raw_log.decode('utf-8'), re.MULTILINE)
    return [i for i, _ in matches]

def get_manifest_yaml(commit=None):
    if commit:
        out = subprocess.check_output("git show {}:assisted-installer.yaml".format(commit), shell=True)
        return yaml.safe_load(out)

    with open("assisted-installer.yaml") as fin:
        return yaml.safe_load(fin)

def get_commit_from_manifest(manifest, repo):
    return manifest[repo]['revision']

def get_field_by_name(issue, fieldName):
    try:
        return issue.fields.__getattribute__(issue.fields, fieldName)
    except:
        return None

def get_issues_info(jclient, keys):
    issues = jclient.search_issues("issue in ({})".format(",".join(keys)), fields=["key", "summary", "status",
                                                                                   BZ_REFERENCE_FIELD])
    return issues

def get_bz_id_from_jira(issue):
    bz_ref = get_field_by_name(issue, BZ_REFERENCE_FIELD)
    return None if bz_ref is None else bz_ref.bugid

def format_key_for_print(key, isMarkdown):
    if not isMarkdown:
        return key

    return f"[{key}](https://issues.redhat.com/browse/{key})"

def get_data_for_print(issues, issues_in_repos, isMarkdown=False):
    headers = ['key', 'summary', 'status', 'repos']
    table = []
    for i in issues:
        row = {'key': format_key_for_print(i.key, isMarkdown=isMarkdown),
               'summary': i.fields.summary,
               'status': i.fields.status.name,
               'repos': ", ".join(issues_in_repos[i.key])}
        table.append(row)

    return headers, table


def print_report_csv(issues, issues_in_repos):
    headers, data = get_data_for_print(issues, issues_in_repos)
    csvout = csv.DictWriter(sys.stdout, delimiter='|', fieldnames=headers)
    csvout.writeheader()
    for row in data:
        csvout.writerow(row)


def print_report_table(issues, issues_in_repos, isMarkdown=False):
    _, data = get_data_for_print(issues, issues_in_repos, isMarkdown=isMarkdown)
    fmt = "github" if isMarkdown else "psql"
    print(tabulate(data, headers="keys", tablefmt=fmt))


def main(jclient, bzclient, from_commit, to_commit, report_format=None, fix_version=None, specific_issue=None,
         should_update=False, is_dry_run=False, requested_repos=None):
    issue_keys = []
    issues_in_repos = defaultdict(set)
    if specific_issue is not None:
        issue_keys = [specific_issue]
    else:
        from_manifest = get_manifest_yaml(from_commit)
        to_manifest = get_manifest_yaml(to_commit)

        for repo, _ in to_manifest.items():
            if not requested_repos or os.path.basename(repo) in requested_repos:
                repo_to_commit = get_commit_from_manifest(to_manifest, repo)
                repo_from_commit = get_commit_from_manifest(from_manifest, repo)
                keys = get_issues_list_for_repo(repo, repo_from_commit, repo_to_commit)
                issue_keys.extend(keys)
                for k in keys:
                    issues_in_repos[k].add(os.path.basename(repo))

        issue_keys = set(issue_keys)

    if not issue_keys:
        return

    issues = get_issues_info(jclient, issue_keys)
    if report_format is not None:
        if report_format == REPORT_FORMAT_CSV:
            print_report_csv(issues, issues_in_repos)
        elif report_format == REPORT_FORMAT_STD:
            print_report_table(issues, issues_in_repos, isMarkdown=False)
        else:
            print_report_table(issues, issues_in_repos, isMarkdown=True)

    if should_update:
        if fix_version:
            fix_version_to_update = fix_version
        else:
            if not to_commit.startswith(("v", "V")):
                logger.error("Cannot update Bugzilla's 'fixed in' value because no 'fix-version' was supplied, "
                             + " and 'to-version' (%s), does not match the format of versions '[vV]*'",
                             to_commit)
                return
            fix_version_to_update = format_fix_version(to_commit)

        update_fix_versions_for_all_bz_issues(bzclient, issues, fix_version_to_update, is_dry_run=is_dry_run)

def format_fix_version(version):
    return "OCP-Metal-{}".format(version)

def update_fix_versions_for_all_bz_issues(bzclient, issues, fix_version, is_dry_run=False):
    bz_issues = []

    for i in issues:
        bz_ref = get_field_by_name(i, BZ_REFERENCE_FIELD)
        if bz_ref is not None:
            if i.fields.status.name not in ['Done', 'QE Review']:
                logger.debug("Not updating %s since it's status is %s", i.key, i.fields.status.name)
            else:
                bz_issues.append(bz_ref.bugid)

    if len(bz_issues) == 0:
        logger.info("No issues selected for updating")
    else:
        if is_dry_run:
            logger.info("Dry-run: Updating tickets %s with fixed_in %s", str(bz_issues), fix_version)
        else:
            logger.info("Updating tickets %s with fixed_in %s", str(bz_issues), fix_version)
            bu = bzclient.build_update(fixed_in=fix_version)
            bzclient.update_bugs(bz_issues, bu)

def get_login(user_password, server):
    if user_password is None:
        username, password = get_credentials_from_netrc(urlparse(server).hostname, args.netrc)
    else:
        try:
            [username, password] = user_password.split(":", 1)
        except:
            logger.error("Failed to parse user:password")
    return username, password

if __name__ == "__main__":
    VALID_REPOS = ['assisted-installer', 'assisted=service', 'assisted-installer-agent', 'facet']
    parser = argparse.ArgumentParser()
    loginGroup = parser.add_argument_group(title="login options")
    loginArgs = loginGroup.add_mutually_exclusive_group()
    loginArgs.add_argument("--netrc", default="~/.netrc", required=False, help="netrc file")
    loginArgs.add_argument("-jup", "--jira-user-password", required=False, help="Jira username and password in the format of user:pass")
    loginArgs.add_argument("-bup", "--bugzilla-user-password", required=False, help="Bugzilla username and password in the format of user:pass")
    selectionGroup = parser.add_argument_group(title="Issues selection")
    selectionGroup.add_argument("-f", "--from-version", help="From version", type=str, required=False)
    selectionGroup.add_argument("-t", "--to-version",
                                help="To version. If not provided, the current content of the manifest will be used",
                                type=str, required=False)
    selectionGroup.add_argument("-i", "--issue", required=False, help="Issue key")
    parser.add_argument("-v", "--verbose", action="store_true", help="Output verbose logging")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Dry run - do not update Bugzilla")
    parser.add_argument("-r", "--repos", action='append', choices=VALID_REPOS,
                        help="Get tickets for the specified repos")
    actionGroup = parser.add_argument_group(title="Operations to perform on selected issues")
    poptions = actionGroup.add_mutually_exclusive_group(required=False)
    poptions.add_argument("-p", "--print-report", action="store_const", dest='report_format',
                          const=REPORT_FORMAT_STD, help="Print issues details")
    poptions.add_argument("-pc", "--print-csv-report", action="store_const", dest='report_format',
                          const=REPORT_FORMAT_CSV, help="Print issues details in csv format")
    poptions.add_argument("-pmd", "--print-markdown-report", action="store_const", dest='report_format',
                          const=REPORT_FORMAT_MARKDOWN, help="Print issues details in markdown format")
    actionGroup.add_argument("-ubz", "--update-bz-fixed-in", action="store_true", help="Update Bugzilla bug "
                             + "'fixed_in' field, if the but in status 'QE REVIEW' or 'Done'")
    actionGroup.add_argument("-fv", "--fixed-in-value", required=False,
                             help="Value to update the Bugzilla's 'fixed_in' field. Required if 'to_version' is not supplied")
    args = parser.parse_args()
    if args.issue is None:
        if args.from_version is None:
            parser.error("Must provide 'from-version'  parameter, if a specific issue is "
                         + "not selected")
    else:
        if args.to_version is not None or args.from_version is not None:
            parser.error("If a specific issue is selected, 'from-version' and 'to-version' parameters cannot "
                         + "be supplied")
    if args.update_bz_fixed_in and args.to_version is None and args.fixed_in_value is None:
        parser.error("When updating 'fixed_in' and 'to_version' is not provided, 'fixed-in-value' must be supplied")

    if args.report_format is None and not args.update_bz_fixed_in:
        parser.error("An action must be chosen. Must select a report format and/or to update bugzilla")

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    jusername, jpassword = get_login(args.jira_user_password, JIRA_SERVER)
    busername, bpassword = get_login(args.bugzilla_user_password, BZ_SERVER)
    jclient = get_jira_client(jusername, jpassword)
    if not args.update_bz_fixed_in:
        bzclient = None
    else:
        bzclient = get_bz_client(busername, bpassword)

    main(jclient, bzclient, args.from_version, args.to_version, args.report_format, specific_issue=args.issue,
         fix_version=args.fixed_in_value, should_update=args.update_bz_fixed_in, is_dry_run=args.dry_run,
         requested_repos=args.repos)
