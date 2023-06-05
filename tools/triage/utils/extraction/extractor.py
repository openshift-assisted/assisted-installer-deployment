import os


class ExtractorInterface:
    """Interface for extrator"""

    def can_handle_file(self, filename: str) -> bool:
        return os.path.exists(filename)

    def extract(self, filename: str, destination_directory: str) -> str:
        return os.path.exists(filename) and os.path.exists(destination_directory)
