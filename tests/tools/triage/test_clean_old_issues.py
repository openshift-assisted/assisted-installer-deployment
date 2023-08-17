from typing import Optional
from unittest.mock import MagicMock, call, patch

import pytest

from tools.triage import clean_old_issues


def create_mock_attachment(identifier: int, filename: str) -> MagicMock:
    attachment_mock = MagicMock()
    attachment_mock.id = identifier
    attachment_mock.filename = filename
    return attachment_mock


def create_mock_issue(key: str, attachments: Optional[list[MagicMock]] = None) -> MagicMock:
    issue_mock = MagicMock()
    issue_mock.key = key
    issue_mock.fields.summary = "test summary"
    issue_mock.fields.description = "test description"
    issue_mock.fields.assignee = "test assignee"
    issue_mock.fields.attachment = attachments

    return issue_mock


def create_mock_watcher(name: str) -> MagicMock:
    watcher_mock = MagicMock()
    watcher_mock.name = name
    watcher_mock.email = f"{name}@test.com"
    return watcher_mock


@pytest.fixture(autouse=True)
def jira_client() -> MagicMock:
    with patch("tools.triage.clean_old_issues.JiraClientFactory") as jira_mock:
        yield jira_mock.create()


@pytest.fixture()
def jira_issues() -> list[MagicMock]:
    return [
        create_mock_issue(key="AITRIAGE-1111"),
        create_mock_issue(key="AITRIAGE-2222", attachments=[create_mock_attachment(filename="test filename 2", identifier=2)]),
        create_mock_issue(key="AITRIAGE-3333", attachments=[create_mock_attachment(filename="test filename 3", identifier=3)]),
    ]


@pytest.fixture()
def jira_watchers() -> list[MagicMock]:
    mock_watchers = MagicMock()
    mock_watchers.watchers = [create_mock_watcher("foo"), create_mock_watcher("bar")]
    return mock_watchers


def test_wrong_options():
    with patch(
        "sys.argv",
        [
            "clean_old_tickets_attachments",
            "--days",
            "<days-which-are-not-a-number>",
            "--jira-access-token",
            "<jira-client-token>",
        ],
    ):
        with pytest.raises(SystemExit):
            clean_old_issues.main()


def test_full_flow(
    jira_client: MagicMock,
    jira_issues: list[MagicMock],
    jira_watchers: list[MagicMock],
):  # pylint: disable=W0621
    with patch(
        "sys.argv",
        [
            "clean_old_tickets_attachments",
            "--days",
            "180",
            "--jira-access-token",
            "<jira-client-token>",
        ],
    ):
        jira_client.search_issues.return_value = [issue for issue in jira_issues if issue.fields.attachment]
        jira_client.watchers.side_effect = lambda issue: jira_watchers if issue.key == "AITRIAGE-2222" else MagicMock()
        jira_client.remove_watcher.return_value = MagicMock()
        jira_client.transition_issue.return_value = MagicMock()

        clean_old_issues.main()

        jira_client.search_issues.assert_called_with(
            "project = AITRIAGE AND attachments IS NOT EMPTY AND created <= -180d", maxResults=50
        )
        assert jira_client.watchers.call_args_list[0] == call(jira_issues[1])
        assert jira_client.watchers.call_args_list[1] == call(jira_issues[2])

        assert jira_client.remove_watcher.call_count == 2

        assert jira_client.delete_attachment.call_args_list[0] == call(jira_issues[1].fields.attachment[0].id)
        assert jira_client.delete_attachment.call_args_list[1] == call(jira_issues[2].fields.attachment[0].id)

        assert jira_client.transition_issue.call_count == 2
