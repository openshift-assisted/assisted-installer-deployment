"""Shutil file extractor module"""
import logging
import shutil

from tools.triage.utils.extraction import ExtractorInterface


class ShutilExtractor(ExtractorInterface):
    """Responsible for handling the extraction of supported files using shutil"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def can_handle_file(self, filename: str) -> bool:
        """Overrides ExtractorInterface.can_handle_file()"""
        if not super().can_handle_file(filename):
            return False

        # Check to see if shutil supports the file extension
        supported_extensions = []
        for format in shutil.get_unpack_formats():
            supported_extensions.extend(format[1])
        for ext in supported_extensions:
            if filename.endswith(ext):
                return True
        return False

    def extract(self, filename, destination_directory) -> str:
        """Overrides ExtractorInterface.extract()"""
        if not self.can_handle_file(filename):
            message = f"This extractor does not support the file {filename}"
            self.logger.error(message)
            return
        try:
            shutil.unpack_archive(filename, destination_directory)
            return destination_directory
        except Exception as e:
            message = f"An error was encountered during shutil extraction of {filename} to {destination_directory}, the error was {e}"
            self.logger.error(message)
