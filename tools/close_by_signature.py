import sys
import tempfile
import logging
import argparse
import pprint
import textwrap
import json

from jira.exceptions import JIRAError

from add_triage_signature import (
    config_logger, get_credentials, get_jira_client, get_issues,
    SIGNATURES,
)

logger = logging.getLogger(__name__)


def parse_args():
    desc = textwrap.dedent("""\
        Automatically resolve triage tickets that are linked to known issues by 
        signature type and/or common message in the signature comment body. 
        Root issues can be linked to given signature messages, and if provided they 
        will be linked to the resolved issues on close. 
    """)
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Output verbose logging'
    )

    login_group = parser.add_argument_group(title='Login options')
    login_args = login_group.add_mutually_exclusive_group()
    login_args.add_argument(
        '--netrc',
        default='~/.netrc',
        required=False,
        help='netrc file',
    )
    login_args.add_argument(
        '-up', '--user-password',
        required=False,
        help='Username and password in the format of user:pass',
    )

    selectors_group = parser.add_argument_group(title='Issues selection')
    selectors = selectors_group.add_mutually_exclusive_group(required=True)
    selectors.add_argument(
        '-r', '--recent-issues',
        action='store_true',
        help='Handle recent (30 days) Triaging Tickets',
    )
    selectors.add_argument(
        '-a', '--all-issues',
        action='store_true',
        help='Handle all Triaging Tickets',
    )
    selectors.add_argument(
        '-i', '--issue',
        required=False,
        help='Triage issue key',
    )

    filter_group = parser.add_argument_group(title='Filter by')
    filters = filter_group.add_mutually_exclusive_group(required=True)
    filters.add_argument(
        '-f', '--filter',
        nargs='+',
        help='Filter issues that applied to the format '
             'signature_type:root_issue:message',
    )
    filters.add_argument(
        '--filters-json',
        help='Filter issues that applied to the rules in a given json file '
             'which has the format: '
             '{signature_type: {root_issue: message}}',
    )

    dry_run_group = parser.add_argument_group(title='Dry run options')
    dry_run_args = dry_run_group.add_mutually_exclusive_group()
    dry_run_args.add_argument(
        '-d', '--dry-run',
        action='store_true',
        help='Dry run. Don\'t update tickets. Write output to stdout'
    )
    dry_run_args.add_argument(
        '-t', '--dry-run-temp',
        action='store_true',
        help=f'Dry run. Don\'t update tickets. Write output to a temp file'
    )

    return parser.parse_args()


class Filter:

    def __init__(self, signature, message, root_issue):
        self.signature = signature
        self.message = message
        self.root_issue = root_issue


class IssueData:

    def __init__(self, issue, signature, root_issue, comment):
        self.issue = issue
        self.signature = signature
        self.root_issue = root_issue
        self.comment = comment


def run_using_json(path, username, jira, issues, dry_run_stdout=None):
    logger.debug('Starting issue resolver task using filters json=%s', path)
    filters_json = read_filters_file(path)
    filters = get_filters_from_json(filters_json, jira)
    close_tickets_by_filters(
        username=username,
        jira=jira,
        filters=filters,
        issues=issues,
        dry_run_stdout=dry_run_stdout,
    )


def read_filters_file(path):
    # json format: { signature_type: { root_issue: { message } }
    with open(path) as fp:
        filters_json = json.load(fp)

    logger.debug('Filters file data=%s', pprint.pformat(filters_json))
    return filters_json


def get_filters_from_json(filters_json, jira):
    signature_by_type = dict(map(
        lambda x: (x.__name__.lower(), x(jira)),
        SIGNATURES
    ))

    filters = []
    for sign_type, sign_data in filters_json.items():
        sign_type = sign_type.lower().replace('-', '').replace('_', '')
        signature = signature_by_type.get(sign_type)
        assert signature is not None

        for root_issue_key, message in sign_data.items():
            root_issue = jira.issue(root_issue_key)
            assert root_issue is not None

            filters.append(Filter(signature, message, root_issue))

    return filters


def filter_and_generate_issues(jira, filters, issues):
    for issue in issues:
        if issue.fields.status.name in ('Closed', 'Done', 'Obsolete'):
            continue

        comments = get_issue_comments(jira, issue)
        if not comments:
            continue

        for _filter in filters:
            comment = _filter.signature.find_signature_comment(comments=comments)
            if comment is None:
                continue

            elif not _filter.message or _filter.message in comment.body:
                yield IssueData(
                    issue=issue,
                    signature=_filter.signature,
                    root_issue=_filter.root_issue,
                    comment=comment,
                )
                break


def get_issue_comments(jira, issue):
    if issue is None:
        return None

    try:
        return jira.comments(issue)
    except JIRAError as e:
        if 'Issue Does Not Exist' not in str(e):
            raise

    return None


def get_dry_run_stdout(args):
    if args.dry_run_temp:
        return tempfile.NamedTemporaryFile(mode='w', delete=False)

    elif args.dry_run:
        return sys.stdout


def close_tickets_by_filters(username, jira, filters, issues, dry_run_stdout):
    filtered_issues_generator = filter_and_generate_issues(
        jira=jira,
        filters=filters,
        issues=issues,
    )
    close_and_link_issues(
        username=username,
        jira=jira,
        filtered_issues_generator=filtered_issues_generator,
        dry_run_stdout=dry_run_stdout,
    )


TARGET_TRANSITION_ID = '41'  # '41' - 'Closed', see GET /rest/api/2/issue/{issueIdOrKey}/transitions


def close_and_link_issues(
        username,
        jira,
        filtered_issues_generator,
        dry_run_stdout,
):
    for issue_data in filtered_issues_generator:
        if issue_data.root_issue:
            link_issue_to_root_issue(
                jira=jira,
                issue=issue_data.issue,
                root_issue=issue_data.root_issue,
                dry_run_stdout=dry_run_stdout,
            )

        logger.debug('Closing issue with key=%s signature=%s comment=%s',
                     issue_data.issue.key, type(issue_data.signature),
                     issue_data.comment.body)

        if dry_run_stdout is None:
            jira.transition_issue(issue_data.issue, TARGET_TRANSITION_ID)
            jira.assign_issue(issue_data.issue, username)
        else:
            print(
                f'Closed issue key={issue_data.issue.key} '
                f'signature={type(issue_data.signature)} '
                f'comment={issue_data.comment.body}\n',
                file=dry_run_stdout,
                flush=True,
            )
            print(
                f'Assigned issue key={issue_data.root_issue.key} '
                f'to user={username}\n',
                file=dry_run_stdout,
                flush=True,
            )


def link_issue_to_root_issue(jira, issue, root_issue, dry_run_stdout):
    logger.info('Linking issue key=%s to root issue key=%s', issue.key,
                root_issue.key)

    if dry_run_stdout is None:
        jira.create_issue_link('relates to', issue.key, root_issue.key)
    else:
        print(
            f'Linked issue key={issue.key} to root issue '
            f'key={issue.key}\n',
            file=dry_run_stdout,
            flush=True,
        )


def get_filters_from_args(args, jira):
    signature_by_type = dict(map(
        lambda x: (x.__name__.lower(), x(jira)),
        SIGNATURES
    ))

    filters = []
    for _filter in args.filter:
        assert _filter.count(':') == 2
        sign_type, root_issue_key, message = _filter.split(':')

        sign_type = sign_type.lower().replace('-', '').replace('_', '')
        signature = signature_by_type.get(sign_type)
        assert signature is not None

        root_issue = jira.issue(root_issue_key)
        assert root_issue is not None

        filters.append(Filter(signature, message, root_issue))

    return filters


def run_using_cli(args):
    config_logger(args.verbose)

    logger.debug('Starting issue resolver task using CLI with args=%s',
                 pprint.pformat(args.__dict__))

    username, password = get_credentials(args.user_password, args.netrc)
    jira = get_jira_client(username, password)

    if args.filters_json:
        filters_json = read_filters_file(args.filters_json)
        filters = get_filters_from_json(filters_json, jira)
    else:
        filters = get_filters_from_args(args, jira)

    issues = get_issues(jira, args.issue, only_recent=args.recent_issues)

    dry_run_stdout = get_dry_run_stdout(args)
    try:
        close_tickets_by_filters(
            username=username,
            jira=jira,
            filters=filters,
            issues=issues,
            dry_run_stdout=dry_run_stdout,
        )
    finally:
        if dry_run_stdout:
            dry_run_stdout.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    run_using_cli(parse_args())

