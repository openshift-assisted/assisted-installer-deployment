"""Gzip file extractor module"""
import gzip
import logging
import os

from tools.triage.utils.extraction import ExtractorInterface


class GzipFileExtractor(ExtractorInterface):
    """Responsible for handling the extraction of gzip format files"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def can_handle_file(self, filename: str) -> bool:
        """Overrides ExtractorInterface.can_handle_file()"""
        return super().can_handle_file(filename) and filename.endswith(".gz")

    def extract(self, filename, destination_directory) -> str:
        """Overrides ExtractorInterface.extract()"""
        if not self.can_handle_file(filename):
            message = f"This extractor does not support the file {filename}"
            self.logger.error(message)
            return
        content = self._extract_gzip_content(filename)
        try:
            if not os.path.exists(destination_directory):
                os.mkdir(destination_directory)
            basename = os.path.basename(filename)
            extraction_filename = os.path.join(destination_directory, "extracted_" + basename.replace(".", "_"))
            with open(extraction_filename, "wb") as out:
                out.write(bytes(content, "utf-8"))
            return destination_directory
        except OSError as e:
            message = f"An error was encountered during extraction of {filename} to {destination_directory}, the error was {e}"
            self._handle_error(message, e)

    def _extract_gzip_content(self, filename):
        try:
            file_content = []
            with gzip.open(filename, "rb") as f:
                file_content = f.read()
            return file_content
        except Exception as e:
            self._handle_error(f"Could not extract gzip file {filename} due to error {e}", e)

    def _handle_error(self, message, e: Exception):
        """Handles an error if it occurs"""
        self.logger.error(message)
        raise e
