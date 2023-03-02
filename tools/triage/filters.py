import json
import logging

import retry
from jira.exceptions import JIRAError

from tools.jira_client import JiraAPI

from .add_triage_signature import ALL_SIGNATURES

SIGNATURE_BY_TYPE = {signature_class.__name__.lower(): signature_class for signature_class in ALL_SIGNATURES}

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TriageIssue:
    def __init__(self, issue, root_issue, message):
        self.issue = issue
        self.root_issue = root_issue
        self.message = message


class Filter:
    def __init__(self, identifier, root_issue, message):
        self.identifier = identifier
        self.message = message
        self.root_issue = root_issue

    def matches(self, issue):
        return issue.fields.status.name not in ("Closed", "Done", "Obsolete")

    def __str__(self):
        root_issue_str = None
        if self.root_issue is not None:
            root_issue_str = self.root_issue.key
        return f"identifier={self.identifier} root_issue={root_issue_str} message={self.message}"

    def __eq__(self, other):
        return (
            self.identifier == other.identifier
            and self.message == other.message
            and (self.root_issue.key or None) == (other.root_issue.key or None)
        )


class LabelFilter(Filter):
    def matches(self, issue):
        if not super().matches(issue):
            return False
        if self.identifier in issue.fields.labels:
            return True
        return False


class SignatureFilter(Filter):
    def __init__(self, jira_client, identifier, root_issue, message):
        super().__init__(identifier, root_issue, message)
        self._signature_class_name = self._get_signature_class_name(identifier)
        root_issue_key = None
        if root_issue:
            root_issue_key = root_issue.key
        self.signature_instance = self._signature_class_name(jira_client, root_issue_key)
        self.jira_api = JiraAPI(jira_client, logger)

    def _get_signature_class_name(self, signature_class_alias_name):
        signature_class_alias_name = signature_class_alias_name.lower().replace("-", "").replace("_", "")
        return SIGNATURE_BY_TYPE[signature_class_alias_name]

    def matches(self, issue):
        if not super().matches(issue):
            return False

        comments = self.jira_api.get_issue_comments(issue)  # cache this?
        if not comments:
            return False

        comment = self.signature_instance.find_signature_comment(comments=comments)
        if comment is None:
            return False

        if not self.message or self.message in comment.body:
            return True

        return False

    def __eq__(self, other):
        return super().__eq__(other) and self._signature_class_name == other._signature_class_name


class Filters:
    @staticmethod
    @retry.retry(exceptions=JIRAError, tries=3, delay=2)
    def create_filter(jira_client, filter_type, identifier, root_issue_key, message):
        root_issue = jira_client.issue(root_issue_key)

        match filter_type.lower():
            case "labels":
                new_filter = LabelFilter(identifier, root_issue, message)
            case "signatures":
                new_filter = SignatureFilter(jira_client, identifier, root_issue, message)
            case other:
                raise ValueError(f"unknown filter type {other}")
        return new_filter

    @staticmethod
    def from_json_filepath(jira_client, json_filepath):
        with open(json_filepath) as fp:
            filters_json = json.load(fp)
            return Filters.from_json(jira_client, filters_json)

    @staticmethod
    def from_json(jira_client, json):
        """Examples:
        {
          "labels":{"mylabel":{"MGMT-0000":"My message"}},
          "signatures":{"my_signature_name":{"MGMT-00001":"My signature message"}}
        }
        """
        filter_params = []
        for filter_type, items in json.items():
            for identifier, root_issues in items.items():
                for root_issue_key, message in root_issues.items():
                    filter_params.append((filter_type, identifier, root_issue_key, message))
        return Filters._get_filters(jira_client, filter_params)

    @staticmethod
    def from_args(jira_client, args):
        """Examples:
        <type>:<identifier>:<root issue key>:<message>
        signatures:master_failed_to_pull_ignition_signature:MGMT-11089:master nodes failed to pull ignition
        labels:FEATURE_myfeature:MGMT-12345:auto close issues with myfeature
        """
        filter_params = []
        for filter_argument in args.filter:
            assert filter_argument.count(":") in (2, 3)
            filters = filter_argument.split(":")
            # backward compatibility: assume type is signature if 3 elements only
            if filter_argument.count(":") == 2:
                filters.insert(0, "signature")
            filter_params.append(filters)

        return Filters._get_filters(jira_client, filter_params)

    @staticmethod
    def _get_filters(jira_client, filter_params):
        filters = []
        for filter_type, identifier, root_issue_key, message in filter_params:
            filters.append(Filters.create_filter(jira_client, filter_type, identifier, root_issue_key, message))
        return filters

    @staticmethod
    def get_triage_issues(issues, filters):
        for issue in issues:
            for triage_filter in filters:
                logger.debug(f"Applying filter {triage_filter} to issue {issue.key}")
                if triage_filter.matches(issue):
                    logger.debug(f"Filter matched issue {issue.key}:")
                    yield TriageIssue(issue=issue, root_issue=triage_filter.root_issue, message=triage_filter.message)
                    continue

    @staticmethod
    def close_triage_issues(jira_api, triage_issues):
        for issue in triage_issues:
            jira_api.link_and_close_issue(issue.issue, issue.root_issue)

    @staticmethod
    def close_issues_by_filters(jira_api, issues, filters):
        triage_issues = Filters.get_triage_issues(issues, filters)
        Filters.close_triage_issues(jira_api, triage_issues)
