from unittest.mock import Mock

import pytest

from tools.jira_client import CLOSED_STATUS, JiraAPI


@pytest.fixture()
def jira_api_provider():
    client = Mock()
    return (JiraAPI(jira_client=client), client)


def test_should_call_underlying_jira_client_to_link_issue_to_root_issue(jira_api_provider):
    jira_api, client = jira_api_provider

    issue = Mock(key="mock_issue")
    root_issue = Mock(key="root_issue")
    jira_api.link_issue_to_root_issue(issue=issue, root_issue=root_issue)
    client.create_issue_link.assert_called_once_with("relates to", "mock_issue", "root_issue")


def test_should_call_underlying_jira_client_to_close_issue(jira_api_provider):
    jira_api, client = jira_api_provider

    issue = Mock(key="mock_issue")
    jira_api.close_issue(issue=issue)
    client.transition_issue.assert_called_once_with("mock_issue", CLOSED_STATUS)


def test_get_comments_should_return_comments_from_jira(jira_api_provider):
    jira_api, client = jira_api_provider

    mock_comments = [{"message": "foobar", "author": "foo"}]
    client.comments = Mock(return_value=mock_comments)
    issue = Mock(key="mock_issue")

    comments = jira_api.get_issue_comments(issue=issue)
    client.comments.assert_called_once_with(issue)
    assert comments == mock_comments


def test_get_comments_should_raise_exception_for_errors(jira_api_provider):
    jira_api, client = jira_api_provider

    client.comments = Mock(side_effect=Exception("random exception"))

    issue = Mock(key="mock_issue")

    with pytest.raises(Exception):
        jira_api.get_issue_comments(issue=issue)


def test_should_link_and_close_if_linked_issue_is_provided(jira_api_provider):
    jira_api, client = jira_api_provider

    issue = Mock(key="mock_issue")
    linked_issue = Mock(key="linked_issue")
    jira_api.link_and_close_issue(issue=issue, linked_issue=linked_issue)
    client.create_issue_link.assert_called_once_with("relates to", "mock_issue", "linked_issue")
    client.transition_issue.assert_called_once_with("mock_issue", CLOSED_STATUS)


def test_should_not_link_but_should_close_issue_if_linked_issue_is_not_provided(jira_api_provider):
    jira_api, client = jira_api_provider

    issue = Mock(key="mock_issue")
    linked_issue = None
    jira_api.link_and_close_issue(issue=issue, linked_issue=linked_issue)
    client.create_issue_link.assert_not_called()
    client.transition_issue.assert_called_once_with("mock_issue", CLOSED_STATUS)
