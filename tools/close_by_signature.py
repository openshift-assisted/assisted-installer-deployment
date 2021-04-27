import sys
import tempfile
import logging
import argparse
import pprint
import textwrap

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
    filter_group.add_argument(
        '-st', '--signature-type',
        required=True,
        nargs='+',
        help='Filter issues that belong to any of the given signatures.',
    )
    filter_group.add_argument(
        '-m', '--message',
        nargs='*',
        help='Filter issues if any of the given messages is in the signature '
             'body. A message can be given as a plain text or in the format '
             'of root_issue_key:message. Any root issue that is assigned to a '
             'message will be linked to the issues that will be resolved by it'
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


class IssueData:

    def __init__(self, issue, signature, comment):
        self.issue = issue
        self.signature = signature
        self.comment = comment
        self.root_issue = None


def get_signatures(signature_types, jira):
    return [
        sign(jira) for sign in SIGNATURES
        if sign.__name__.lower() in signature_types
    ]


def issues_by_signature_generator(jira, signatures, issues):
    for issue in issues:
        if issue.fields.status.name in ('Done', 'Obsolete'):
            continue

        comments = jira.comments(issue.key)
        for sign in signatures:
            comment = sign.find_signature_comment(issue.key, comments)
            if comment is None:
                continue

            yield IssueData(issue, sign, comment)
            break


def filter_issues_by_message_generator(jira, issues_data_generator, messages):
    msgs_to_search_for = []
    msgs_to_root_issue = {}
    for msg in messages:
        if ':' not in msg:
            msgs_to_search_for.append(msg)
            continue

        original_msg = msg
        root_issue_key, msg = msg.split(':', 1)
        root_issue = jira.issue(root_issue_key)
        if root_issue is None:
            msgs_to_search_for.append(original_msg)
            continue

        msgs_to_root_issue[msg] = root_issue
        msgs_to_search_for.append(msg)

    for issue_data in issues_data_generator:
        for msg in msgs_to_search_for:
            if msg not in issue_data.comment.body:
                continue

            issue_data.root_issue = msgs_to_root_issue.get(msg)
            yield issue_data
            break

        if not msgs_to_search_for:
            yield issue_data


def get_dry_run_stdout(args):
    if args.dry_run_temp:
        return tempfile.NamedTemporaryFile(mode='w', delete=False)

    elif args.dry_run:
        return sys.stdout


TRANSITION_DONE_ID = '31'   # GET /rest/api/3/issue/{issueIdOrKey}/transitions


def close_and_link_issues(username, jira, issues_data_generator, dry_run_stdout):
    for issue_data in issues_data_generator:
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
            jira.transition_issue(issue_data.issue, TRANSITION_DONE_ID)
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
            f'key={root_issue.key}\n',
            file=dry_run_stdout,
            flush=True,
        )


def run(args):
    config_logger(args.verbose)

    logger.debug('Starting issue resolver task with args=%s',
                 pprint.pformat(args.__dict__))

    username, password = get_credentials(args.user_password, args.netrc)
    jira = get_jira_client(username, password)

    signature_types = list(map(
        lambda x: x.lower().replace('-', '').replace('_', ''),
        args.signature_type,
    ))
    signatures = get_signatures(signature_types, jira)

    issues = get_issues(jira, args.issue, args.recent_issues)

    issues_data_generator = issues_by_signature_generator(
        jira=jira,
        signatures=signatures,
        issues=issues,
    )
    issues_data_generator = filter_issues_by_message_generator(
        jira=jira,
        issues_data_generator=issues_data_generator,
        messages=args.message,
    )

    dry_run_stdout = get_dry_run_stdout(args)
    try:
        close_and_link_issues(
            username=username,
            jira=jira,
            issues_data_generator=issues_data_generator,
            dry_run_stdout=dry_run_stdout,
        )
    finally:
        if dry_run_stdout:
            dry_run_stdout.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    run(parse_args())

