import logging
import shutil
import tempfile
from pathlib import Path
from typing import Optional, final

import jira
import nestedarchive
from retry import retry

from tools.triage.utils.extraction.jira_attachment_querier.local_nested_archive_extractor import (
    LocalNestedArchiveExtractor,
)


@final
class JiraAttachmentsQuerier:
    """Handles querying and extracting attachment from Jira issue."""

    def __init__(
        self,
        jira_client: jira.JIRA,
        issue_key: str,
        attachment_file_name: str,
        logger: logging.Logger,
        extract_tar: bool = False,
        local_nested_archive_extractor: LocalNestedArchiveExtractor = LocalNestedArchiveExtractor(),
    ) -> None:
        """Initializes the JiraAttachmentsQuerier.

        Args:
            jira_client: Jira client instance.
            issue_key: Key of the Jira issue.
            attachment_file_name: Name of the attachment file.
            logger: Logger instance.
            extract_tar: Whether to extract the tar attachment (in case it is a tar attachment). Default is False.
            local_nested_archive_extractor: Instance for extracting local nested archives.
        """
        self._jira_client = jira_client
        self._local_nested_archive_extractor = local_nested_archive_extractor
        self._logger = logger
        self._temporary_download_directory_path = Path(tempfile.mkdtemp())
        self._extract_tar = extract_tar
        self.extracted = False

        try:
            self._archive_path = self._get_attachment_from_issue(
                issue_key=issue_key,
                attachment_file_name=attachment_file_name,
                target_directory=self._temporary_download_directory_path,
            )

        except jira.JIRAError:
            raise FileNotFoundError

        self.downloaded = True

        # if it is not a tar file, nothing to extract
        if not self._local_nested_archive_extractor.is_tar_file(Path(attachment_file_name)):
            self._is_tar_file = False
            return

        self._is_tar_file = True

        if not extract_tar:
            return

        # extracting the tar
        self.temporary_extracted_archive_path = Path(tempfile.mkdtemp())
        extraction_path = (
            self.temporary_extracted_archive_path
            / self._local_nested_archive_extractor.remove_tar_and_gzip_extensions_if_any(attachment_file_name)
        )

        self._local_nested_archive_extractor.recursive_extraction(
            source=self._archive_path, target=extraction_path, root_tar_path=self._archive_path
        )
        self.extracted = True

    def __del__(self):
        """Destructor. Removes the temporary directories."""
        try:
            shutil.rmtree(self._temporary_download_directory_path)

        except AttributeError:
            pass

        try:
            shutil.rmtree(self.temporary_extracted_archive_path)

        except AttributeError:
            pass

    @staticmethod
    def _download_attachment(attachment, target_directory: Path) -> Path:
        """Downloads a given attachment to the specified directory.

        Args:
            attachment: The attachment object to download.
            target_directory (Path): The directory where the attachment should be saved.

        Returns:
            Path to the downloaded attachment.
        """
        attachment_content = attachment.get()
        new_path = target_directory / str(attachment.filename)

        with open(new_path, "wb") as file:
            file.write(attachment_content)

        return new_path

    @retry(exceptions=jira.JIRAError, tries=3, delay=1)
    def _get_issue(self, issue_key: str) -> jira.Issue:
        """Retrieves a Jira issue by its key.

        Args:
            issue_key: The key of the Jira issue.

        Returns:
            The retrieved Jira issue.
        """
        return self._jira_client.issue(issue_key)

    @staticmethod
    def _get_attachment(issue: jira.Issue, attachment_filename: str):
        """Gets an attachment from a Jira issue by its filename.

        Args:
            issue: The Jira issue object.
            attachment_filename: Filename of the attachment.

        Returns:
            The attachment object.
        """
        found_attachment = None
        for attachment in issue.fields.attachment:
            if attachment.filename == attachment_filename:
                found_attachment = attachment
                break

        if found_attachment is None:
            raise Exception(f"target attachment ({attachment_filename}) was not found in: {issue.key}")

        return found_attachment

    def _get_attachment_from_issue(self, issue_key: str, attachment_file_name: str, target_directory: Path) -> Path:
        """Retrieves and downloads an attachment from a Jira issue.

        Args:
            issue_key: The key of the Jira issue.
            attachment_file_name: Filename of the attachment.
            target_directory: Directory where the attachment should be saved.

        Returns:
            Path to the downloaded attachment.
        """
        issue = self._get_issue(issue_key=issue_key)
        attachment = self._get_attachment(issue=issue, attachment_filename=attachment_file_name)
        return self._download_attachment(attachment=attachment, target_directory=target_directory)

    def get(self, glob_pattern: Optional[str] = None, mode: str = "r", from_extracted_tar: bool = False):
        """Retrieves the item matching the given glob pattern from the downloaded archive. If a non-archive attachment was downloaded, returns its content instead.

        Args:
            glob_pattern: A global command pattern of the target directory/file. Default is None.
            mode: The format in which we would like to get the data. Default is 'r'.
            from_extracted_tar: Whether to retrieve from the extracted tar. Default is False.

        Returns:
            - The content of the file if the pattern matches a file.
            - The path of the directory if the pattern matches a directory.

        Raises:
            FileNotFoundError: If the given pattern doesn't match any file/directory or attachment was not extracted.
        """
        if self.downloaded and not self._is_tar_file:
            return self._local_nested_archive_extractor.get_item(item_path=self._archive_path, mode=mode)

        # if we don't want to get the file from the tar's extraction, or we didn't extract it or the extraction failed,
        # we want to get the file by from the tar, not tar's extraction.
        if not from_extracted_tar or not self._extract_tar or not self.extracted:
            target_virtual_path = self._archive_path / Path(glob_pattern)
            return nestedarchive.get(nested_archive_path=target_virtual_path, mode=mode)

        glob_pattern = self._local_nested_archive_extractor.remove_interior_tar_or_gzip_extensions(glob_pattern)
        self._logger.debug(f"glob_pattern: {glob_pattern}")

        matches = list(self.temporary_extracted_archive_path.rglob(glob_pattern))
        self._logger.debug(f"for pattern ({glob_pattern}) inside {self._archive_path.name} found matches:")

        self._logger.debug("matches:")
        for match in matches:
            self._logger.debug(str(match))

        match len(matches):
            case 0:
                raise FileNotFoundError(
                    f"the given pattern ({glob_pattern}) doesn't match in the nested archive {self._archive_path.name}"
                )
            case _:
                return self._local_nested_archive_extractor.get_item(item_path=matches[0], mode=mode)
