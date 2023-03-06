import re
from pathlib import Path
from unittest.mock import Mock, call, patch

import jira
import pytest
from pyfakefs.fake_filesystem import FakeFilesystem

from tools.triage.attach_logs_in_jira import attach_logs_in_jira


@pytest.fixture(autouse=True)
def jira_client():
    with patch("tools.triage.attach_logs_in_jira.JiraClientFactory") as jira_mock:
        yield jira_mock.create()


@pytest.fixture(autouse=True)
def get_or_create_triage_ticket():
    with patch("tools.triage.attach_logs_in_jira.get_or_create_triage_ticket") as tickets_creation_mock:
        yield tickets_creation_mock


def test_storing_artifacts(fs: FakeFilesystem, jira_client: jira.JIRA, get_or_create_triage_ticket):
    source_dir = Path("/var/ai-logs")
    fs.create_dir(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658")
    fs.create_file(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "log.log")
    fs.create_file(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "events.json")

    issue = Mock(spec=jira.Issue, fields=Mock(attachment=[]))
    get_or_create_triage_ticket.return_value = issue

    attach_logs_in_jira(source_dir=source_dir, jira_access_token="")

    jira_client.add_attachment.assert_any_call(
        issue=issue, attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/log.log"
    )
    jira_client.add_attachment.assert_any_call(
        issue=issue, attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/events.json"
    )


def test_archiving_directories(fs: FakeFilesystem, jira_client: jira.JIRA, get_or_create_triage_ticket):
    source_dir = Path("/var/ai-logs")
    fs.create_dir(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658")
    fs.create_dir(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "cluster_files")
    fs.create_file(
        source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "cluster_files" / "events.json"
    )

    issue = Mock(spec=jira.Issue, fields=Mock(attachment=[]))
    get_or_create_triage_ticket.return_value = issue

    attach_logs_in_jira(source_dir=source_dir, jira_access_token="")

    jira_client.add_attachment.assert_any_call(
        issue=issue,
        attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/cluster_files.tar.gz",
    )


def test_archiving_directories_with_suffix(fs: FakeFilesystem, jira_client: jira.JIRA, get_or_create_triage_ticket):
    source_dir = Path("/var/ai-logs")
    fs.create_dir(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658")
    fs.create_dir(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "cluster_files.d")
    fs.create_file(
        source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "cluster_files.d" / "events.json"
    )

    issue = Mock(spec=jira.Issue, fields=Mock(attachment=[]))
    get_or_create_triage_ticket.return_value = issue

    attach_logs_in_jira(source_dir=source_dir, jira_access_token="")

    jira_client.add_attachment.assert_any_call(
        issue=issue,
        attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/cluster_files.d.tar.gz",
    )


def test_skip_archiving_directory_if_already_did(
    fs: FakeFilesystem, jira_client: jira.JIRA, get_or_create_triage_ticket
):
    source_dir = Path("/var/ai-logs")
    fs.create_dir(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658")
    fs.create_dir(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "cluster_files")
    fs.create_file(
        source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "cluster_files" / "events.json"
    )
    fs.create_file(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "cluster_files.tar.gz")

    issue = Mock(spec=jira.Issue, fields=Mock(attachment=[]))
    get_or_create_triage_ticket.return_value = issue

    with patch("tools.triage.attach_logs_in_jira.tarfile.open") as tarfile_mock:
        attach_logs_in_jira(source_dir=source_dir, jira_access_token="")

        tarfile_mock.assert_not_called()

    jira_client.add_attachment.assert_any_call(
        issue=issue,
        attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/cluster_files.tar.gz",
    )


def test_splitting_big_artifacts(fs: FakeFilesystem, jira_client: jira.JIRA, get_or_create_triage_ticket):
    source_dir = Path("/var/ai-logs")
    fs.create_dir(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658")
    fs.create_file(
        source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "short-enough.log",
        contents="a" * 49 * 2**20,
    )
    fs.create_file(
        source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "big.log", contents="a" * 51 * 2**20
    )

    issue = Mock(spec=jira.Issue, fields=Mock(attachment=[]))
    get_or_create_triage_ticket.return_value = issue

    attach_logs_in_jira(source_dir=source_dir, jira_access_token="")

    jira_client.add_attachment.assert_any_call(
        issue=issue, attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/short-enough.log"
    )

    # making sure original big file didn't get attached, but its parts are
    assert (
        call(issue=issue, attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/big.log")
        not in jira_client.add_attachment.call_args_list
    )
    jira_client.add_attachment.assert_any_call(
        issue=issue, attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/big.log-part-0"
    )
    jira_client.add_attachment.assert_any_call(
        issue=issue, attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/big.log-part-1"
    )


def test_skipping_already_attached_files(fs: FakeFilesystem, jira_client: jira.JIRA, get_or_create_triage_ticket):
    source_dir = Path("/var/ai-logs")
    fs.create_dir(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658")
    fs.create_file(
        source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "existing-file.log", st_size=1111
    )
    fs.create_file(
        source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "new-file.log", st_size=2222
    )
    fs.create_file(
        source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "changed-file.log", st_size=3333
    )

    issue = Mock(
        spec=jira.Issue,
        fields=Mock(
            attachment=[Mock(filename="existing-file.log", size=1111), Mock(filename="changed-file.log", size=1122)]
        ),
    )
    get_or_create_triage_ticket.return_value = issue

    attach_logs_in_jira(source_dir=source_dir, jira_access_token="")

    assert (
        call(
            issue=issue,
            attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/existing-file.log",
        )
        not in jira_client.add_attachment.call_args_list
    )
    jira_client.add_attachment.assert_any_call(
        issue=issue, attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/new-file.log"
    )
    jira_client.add_attachment.assert_any_call(
        issue=issue, attachment="/var/ai-logs/2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658/changed-file.log"
    )


def test_retrying_jira_errors(fs: FakeFilesystem, jira_client: jira.JIRA, get_or_create_triage_ticket):
    source_dir = Path("/var/ai-logs")
    fs.create_dir(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658")
    fs.create_file(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "log.log")

    get_or_create_triage_ticket.side_effect = jira.JIRAError("jira error")

    with pytest.raises(ExceptionGroup, match=re.escape("Failed attaching logs for all issues (1 sub-exception)")):
        attach_logs_in_jira(source_dir=source_dir, jira_access_token="")

    assert get_or_create_triage_ticket.call_count == 3


def test_aggregating_errors(fs: FakeFilesystem, jira_client: jira.JIRA, get_or_create_triage_ticket):
    source_dir = Path("/var/ai-logs")
    fs.create_dir(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658")
    fs.create_file(source_dir / "2021-12-29_05:04:07_ff5b2fa7-3d6d-4493-aeee-253c4f29e658" / "log.log")

    fs.create_dir(source_dir / "2022-06-10_18:24:23_b677eb1e-784a-45e1-bee9-e7958b9bcfb2")
    fs.create_file(source_dir / "2022-06-10_18:24:23_b677eb1e-784a-45e1-bee9-e7958b9bcfb2" / "log.log")

    get_or_create_triage_ticket.side_effect = jira.JIRAError("jira error")

    with pytest.raises(ExceptionGroup, match=re.escape("Failed attaching logs for all issues (2 sub-exceptions)")):
        attach_logs_in_jira(source_dir=source_dir, jira_access_token="")

    assert get_or_create_triage_ticket.call_count == 6
