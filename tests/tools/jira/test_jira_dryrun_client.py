import os
from unittest.mock import Mock

import pytest

from tools.jira_client.jira_api import CLOSED_STATUS
from tools.jira_client.jira_dryrun_client import JiraDryRunClient


@pytest.fixture()
def devnull_stream():
    with open(os.devnull, "w") as devnull:
        yield devnull


class MockAttributeErrorJiraClient:
    pass


def test_should_throw_exception_when_calling_undefined_methods_and_real_jira_has_undefined_method_also(devnull_stream):
    mock_jira_client = MockAttributeErrorJiraClient()
    jira_dryrun_client = JiraDryRunClient(jira_client=mock_jira_client, dry_run_stream=devnull_stream)
    with pytest.raises(AttributeError):
        jira_dryrun_client.does_not_exist()


def test_should_proxy_calls_to_real_jira_when_calling_undefined_methods(devnull_stream):
    mock_jira_client = Mock()
    mock_jira_client.search_issues = Mock(return_value=[])
    jira_dryrun_client = JiraDryRunClient(jira_client=mock_jira_client, dry_run_stream=devnull_stream)
    jira_dryrun_client.search_issues(query="foobar")
    mock_jira_client.search_issues.assert_called_once()


def test_should_not_proxy_calls_to_real_jira_client_when_calling_create_issue_link(devnull_stream):
    mock_jira_client = Mock()
    jira_dryrun_client = JiraDryRunClient(jira_client=mock_jira_client, dry_run_stream=devnull_stream)
    jira_dryrun_client.create_issue_link("link_name", "issue", "root_issue")
    mock_jira_client.create_issue_link.assert_not_called()


def test_should_not_proxy_calls_to_real_jira_client_when_calling_transition_issue(devnull_stream):
    mock_jira_client = Mock()
    jira_dryrun_client = JiraDryRunClient(jira_client=mock_jira_client, dry_run_stream=devnull_stream)
    jira_dryrun_client.transition_issue(issue="issue", target_status=CLOSED_STATUS)
    mock_jira_client.transition_issue.assert_not_called()
