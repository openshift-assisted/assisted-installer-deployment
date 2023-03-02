import os
from unittest.mock import Mock, call

import pytest

from tools.triage import Filters, LabelFilter, SignatureFilter, TriageIssue


def get_mock_comment(body):
    comment = Mock(body=body)
    return comment


def get_mock_issue(key="foobar", status="Open", labels=[]):
    issue = Mock()
    issue.key = key
    issue.fields.status.name = status
    issue.fields.labels = labels
    return issue


def test_create_label_filter():
    root_issue_key = "MGMT-0000"
    jira_client = Mock()
    jira_client.issue = Mock(return_value=get_mock_issue(root_issue_key))
    triage_filter = Filters.create_filter(jira_client, "labels", "FEATURE_some_label", root_issue_key, "my message")
    assert isinstance(triage_filter, LabelFilter)
    assert triage_filter.root_issue.key == root_issue_key
    jira_client.issue.assert_called_with(root_issue_key)


def test_create_signature_filter():
    root_issue_key = "MGMT-0000"
    jira_client = Mock()
    jira_client.issue = Mock(return_value=get_mock_issue(root_issue_key))
    triage_filter = Filters.create_filter(jira_client, "signatures", "master_failed_to_pull_ignition_signature", root_issue_key, "my message")
    assert isinstance(triage_filter, SignatureFilter)
    assert triage_filter.root_issue.key == root_issue_key
    jira_client.issue.assert_called_with(root_issue_key)


def test_create_invalid_type_filter():
    root_issue_key = "MGMT-0000"
    jira_client = Mock()
    with pytest.raises(ValueError, match="unknown filter type invalid-type"):
        Filters.create_filter(jira_client, "invalid-type", "whatever", root_issue_key, "my message")


def test_load_simple_filters_from_json_path():
    path = os.path.dirname(__file__) + "/fixtures/example_filters.json"
    jira_client = Mock()
    root_issue_1 = get_mock_issue("MOCKISSUE-12345")
    root_issue_2 = get_mock_issue("MOCKISSUE-00000")

    jira_client.issue.side_effect = [root_issue_1, root_issue_2]
    filters = Filters.from_json_filepath(jira_client, path)
    assert len(filters) == 2
    label_filter = LabelFilter(
        identifier="example_label",
        root_issue=root_issue_2,
        message="this is another example message",
    )
    assert label_filter in filters
    signature_filter = SignatureFilter(
        jira_client=jira_client,
        identifier="master_failed_to_pull_ignition_signature",
        root_issue=root_issue_1,
        message="this is an example message",
    )
    assert signature_filter in filters


def test_load_simple_filters_from_args():
    args = Mock()
    args.filter = [
        "signatures:master_failed_to_pull_ignition_signature:MOCKISSUE-12345:this is an example message",
        "labels:example_label:MOCKISSUE-0000:this is another example message",
    ]

    jira_client = Mock()
    root_issue_1 = get_mock_issue("MOCKISSUE-12345")
    root_issue_2 = get_mock_issue("MOCKISSUE-00000")

    jira_client.issue.side_effect = [root_issue_1, root_issue_2]
    filters = Filters.from_args(jira_client, args)

    assert len(filters) == 2
    label_filter = LabelFilter(
        identifier="example_label",
        root_issue=root_issue_2,
        message="this is another example message",
    )
    assert label_filter in filters
    signature_filter = SignatureFilter(
        jira_client=jira_client,
        identifier="master_failed_to_pull_ignition_signature",
        root_issue=root_issue_1,
        message="this is an example message",
    )
    assert signature_filter in filters


def test_get_triage_issue_filtered_by_labels():
    issues = [
        # to be discarded: already closed
        get_mock_issue("ISSUE-1", "Closed", ["example_label"]),
        # to be selected
        get_mock_issue("ISSUE-2", "Open", ["example_label"]),
        # to be discarded: no matching label
        get_mock_issue("ISSUE-3", "Open", ["some_label"]),
        get_mock_issue("ISSUE-4", "Open", ["some_label", "example_label"]),
    ]

    filters = [
        LabelFilter(
            identifier="example_label",
            root_issue=None,
            message="this is another example message",
        )
    ]
    triage_issues = Filters.get_triage_issues(issues, filters)
    assert len(list(triage_issues)) == 2


def test_get_triage_issue_filtered_by_signature():
    issues = [
        # to be discarded: already closed
        get_mock_issue("ISSUE-1", "Closed", ["example_label"]),
        # the rest of the issues will be queried for comments
        get_mock_issue("ISSUE-2", "Open", ["example_label"]),
        get_mock_issue("ISSUE-3", "Open", ["some_label"]),
        get_mock_issue("ISSUE-4", "Open", ["some_label", "example_label"]),
    ]

    comments = [
        # issue 2
        [],
        # issue 3
        [
            get_mock_comment("comment"),
            get_mock_comment("another comment"),
            get_mock_comment("h1. Master nodes failed to pull ignition"),
            get_mock_comment("more stuff"),
        ],
        # issue 4
        [
            get_mock_comment("comment"),
            get_mock_comment("another comment"),
            get_mock_comment("h1. Master nodes failed to pull ignition\nAnd here some description, lorem ipsum"),
            get_mock_comment("more stuff"),
        ],
    ]
    jira_client = Mock()
    jira_client.comments = Mock(side_effect=comments)
    filters = []
    filters = [
        SignatureFilter(
            jira_client=jira_client,
            identifier="master_failed_to_pull_ignition_signature",
            root_issue=None,
            message="Master nodes failed to pull ignition",
        )
    ]
    triage_issues = Filters.get_triage_issues(issues, filters)
    assert len(list(triage_issues)) == 2
    jira_client.comments.assert_has_calls([
        call(issues[1]),
        call(issues[2]),
        call(issues[3]),
    ])


def test_close_triage_issues():
    triage_issues = [
        TriageIssue(
            issue=get_mock_issue("ISSUE-1"),
            root_issue=get_mock_issue("ROOT-1"),
            message="any message",
        ),
        TriageIssue(
            issue=get_mock_issue("ISSUE-2"),
            root_issue=get_mock_issue("ROOT-1"),
            message="any message",
        ),
        TriageIssue(
            issue=get_mock_issue("ISSUE-3"),
            root_issue=None,
            message="any message",
        ),
    ]
    jira_api = Mock()
    Filters.close_triage_issues(jira_api, triage_issues)
    jira_api.link_and_close_issue.assert_has_calls([
        call(triage_issues[0].issue, triage_issues[0].root_issue),
        call(triage_issues[1].issue, triage_issues[1].root_issue),
        call(triage_issues[2].issue, triage_issues[2].root_issue),
    ])
