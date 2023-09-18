import io
import tarfile
import textwrap
from unittest.mock import Mock

import pytest

from tools.triage.utils.extraction.jira_attachment_querier.jira_remote_archive_querier import (
    JiraAttachmentsQuerier,
)

JIRA_ISSUE_KEY = "AITRIAGE-99999"


@pytest.fixture
def metadata_attachment() -> Mock:

    metadata_attachment_mock = Mock()
    metadata_attachment_mock.filename = "metadata.json"
    metadata_attachment_mock.get.return_value = textwrap.dedent("""\
        {
            "name": "Foo Bar",
            "age": "30",
            "city": "New York",
        }
    """).encode()

    return metadata_attachment_mock


@pytest.fixture
def cluster_files_attachment() -> Mock:

    tar_buffer = io.BytesIO()

    with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
        file1_content = io.BytesIO(b"Content of file1.txt")
        file2_content = io.BytesIO(b"Content of file2.txt")

        file1_info = tarfile.TarInfo(name='file1.txt')
        file1_info.size = len(file1_content.getvalue())

        file2_info = tarfile.TarInfo(name='file2.txt')
        file2_info.size = len(file2_content.getvalue())

        tar.addfile(file1_info, file1_content)
        tar.addfile(file2_info, file2_content)

    tar_buffer.seek(0)

    cluster_files_attachment_mock = Mock()
    cluster_files_attachment_mock.filename = "cluster_files.tar.gz"
    cluster_files_attachment_mock.get.return_value = tar_buffer.getvalue()

    return cluster_files_attachment_mock


@pytest.fixture
def jira_issue(metadata_attachment: Mock, cluster_files_attachment: Mock) -> Mock:
    return Mock(key=JIRA_ISSUE_KEY, fields=Mock(attachment=[metadata_attachment, cluster_files_attachment]))


@pytest.fixture(autouse=True)
def jira_client(jira_issue: Mock) -> Mock:

    def get_issue(issue_key: str) -> Mock:
        match issue_key:
            case "AITRIAGE-99999":
                return jira_issue
            case _:
                return None

    jira_client_mock = Mock()
    jira_client_mock.issue.side_effect = get_issue
    return jira_client_mock


def test_init_with_existing_issue_should_be_successfull(jira_client):
    querier = JiraAttachmentsQuerier(
        jira_client,
        JIRA_ISSUE_KEY,
        "metadata.json",
        Mock()
    )

    assert querier.downloaded
    assert not querier.extracted


def test_init_with_non_existing_issue_should_be_unsuccessfull(jira_client):
    with pytest.raises(Exception):
        JiraAttachmentsQuerier(
            jira_client,
            "non-existing-issue",
            "metadata.json",
            Mock()
        )


def test_init_download_with_existing_attachment_should_be_successfull(jira_client):
    querier = JiraAttachmentsQuerier(
        jira_client,
        JIRA_ISSUE_KEY,
        "metadata.json",
        Mock()
    )

    assert querier.downloaded
    assert not querier.extracted


def test_init_download_with_non_existing_attachment_should_be_unsuccessfull(jira_client):
    with pytest.raises(Exception):
        JiraAttachmentsQuerier(
            jira_client,
            JIRA_ISSUE_KEY,
            "non_existent_file.json",
            Mock()
        )


def test_init_extraction_with_archive_path_should_be_successfull(jira_client):
    querier = JiraAttachmentsQuerier(
        jira_client,
        JIRA_ISSUE_KEY,
        "cluster_files.tar.gz",
        Mock(),
        True
    )

    assert querier.downloaded
    assert querier.extracted


def test_init_extraction_with_non_archive_path_should_be_unsuccessfull(jira_client):
    querier = JiraAttachmentsQuerier(
        jira_client,
        JIRA_ISSUE_KEY,
        "metadata.json",
        Mock(),
        True
    )

    assert querier.downloaded
    assert not querier.extracted


def test_get_with_non_archive_attachment_should_be_successfull(jira_client, metadata_attachment):
    querier = JiraAttachmentsQuerier(
        jira_client,
        JIRA_ISSUE_KEY,
        "metadata.json",
        Mock()
    )

    content = querier.get()
    expected_content = metadata_attachment.get().decode()
    assert content == expected_content


def test_get_with_existing_pattern_should_be_successfull(jira_client):
    querier = JiraAttachmentsQuerier(
        jira_client,
        JIRA_ISSUE_KEY,
        "cluster_files.tar.gz",
        Mock()
    )

    # text mode
    content = querier.get("file1.txt")
    assert content == "Content of file1.txt"

    # bytes mode
    content = querier.get("file1.txt", mode="rb")
    assert content == b"Content of file1.txt"


def test_get_with_non_existing_pattern_should_be_unsuccessfull(jira_client):
    querier = JiraAttachmentsQuerier(
        jira_client,
        JIRA_ISSUE_KEY,
        "cluster_files.tar.gz",
        Mock()
    )

    with pytest.raises(FileNotFoundError):
        querier.get("non_existent_file.txt")


def test_get_from_extracted_archive_with_existing_pattern_should_be_successfull(jira_client):
    querier = JiraAttachmentsQuerier(
        jira_client,
        JIRA_ISSUE_KEY,
        "cluster_files.tar.gz",
        Mock(),
        True
    )

    # text mode
    content = querier.get("file1.txt", from_extracted_tar=True)
    assert content == "Content of file1.txt"

    # bytes mode
    content = querier.get("file1.txt", mode="rb", from_extracted_tar=True)
    assert content == b"Content of file1.txt"


def test_get_from_extracted_archive_with_non_existing_pattern_should_be_unsuccessfull(jira_client):
    querier = JiraAttachmentsQuerier(
        jira_client,
        JIRA_ISSUE_KEY,
        "cluster_files.tar.gz",
        Mock(),
        True
    )

    with pytest.raises(FileNotFoundError):
        querier.get("non_existent_file.txt", from_extracted_tar=True)
