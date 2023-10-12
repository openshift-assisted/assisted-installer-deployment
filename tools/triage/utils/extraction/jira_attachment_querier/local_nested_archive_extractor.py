import gzip
import re
import shutil
import tarfile
from datetime import datetime
from pathlib import Path
from typing import final


@final
class LocalNestedArchiveExtractor:
    """Handles the extraction of nested tar archives on a local filesystem."""

    TAR_SUFFIX_PATTERN = re.compile(r"\.tar(\.gz|\.bz2|\.xz)?$")
    TAR_GZIP_SUFFIXES: frozenset[str] = frozenset({".tar", ".gz"})

    def remove_tar_and_gzip_extensions_if_any(self, file_path: str) -> str:
        """Strip tar and gzip extensions from a given file path, if present.

        Args:
            file_path: The file path to process.

        Returns:
            The file path without tar and gzip extensions.
        """
        file_path_ = Path(file_path)
        while file_path_.suffix in self.TAR_GZIP_SUFFIXES:
            file_path_ = Path(file_path_.stem)

        return str(file_path_)

    def is_tar_file(self, file_path: Path) -> bool:
        """Determine if the given path corresponds to a tar file.

        Args:
            file_path: The file path to check.

        Returns:
            True if it's a tar file, False otherwise.
        """
        return self.TAR_SUFFIX_PATTERN.search(file_path.name) is not None

    def get_item(self, item_path: Path, mode: str) -> str | bytes | Path:
        """Retrieve the item's content based on the specified mode, or directory path if it is a dirctory.

        Args:
            item_path: The path to the item.
            mode: Mode in which to fetch the item's content. Acceptable modes are "r" (read as text) or "rb" (read as bytes).

        Returns:
            - The content of the file if the provided path points to a file, based on the mode provided.
            - The path itself if the provided path points to a directory.

        Raises:
            ValueError: If an unsupported mode is provided.
        """
        if item_path.is_dir():
            return item_path

        match mode:
            case "rb":
                return item_path.read_bytes()
            case "r":
                return item_path.read_text()
            case _:
                raise ValueError("given mode must be one of ['r', 'rb']")

    def convert_directory_to_json(self, directory_path: Path) -> str:
        """Convert a directory's metadata into a list of JSON like dictionaries.

        Args:
            directory_path: Path to the directory.

        Returns:
            A JSON representation (as dictionary) of the directory's metadata.
        """
        data = []
        for file in directory_path.iterdir():
            file_info = {
                "name": file.name,
                "type": "directory" if file.is_dir() else "file",
                "mtime": datetime.utcfromtimestamp((file.stat().st_mtime)).strftime("%a, %d %b %Y %H:%M:%S GMT"),
                "size": file.stat().st_size,
            }

            data.append(file_info)

        return data

    def decompress_gzip(self, gzip_path: Path, target_path: Path):
        """Decompress a gzip file to a target path.

        Args:
            gzip_path: Path to the gzip file.
            target_path: Path where the decompressed file will be saved.
        """
        with gzip.open(gzip_path, "rb") as gzip_file:
            with open(target_path, "wb") as target_file:
                shutil.copyfileobj(gzip_file, target_file)

    def recursive_extraction(self, source: Path, target: Path, root_tar_path: Path):
        """Recursively extract archives, including tarballs and gzip files.

        Args:
            source: Source path to begin extraction from.
            target: Target directory where the contents will be extracted.
            root_tar_path: The root tar path to handle nested extractions.
        """

        if source.is_dir():
            for child in source.iterdir():
                if not target.exists():
                    shutil.copytree(src=child, target=target)
                self.recursive_extraction(
                    source=child,
                    target=target / self.remove_tar_and_gzip_extensions_if_any(child.name),
                    root_tar_path=root_tar_path,
                )
            return

        if self.is_tar_file(source):
            target.mkdir(parents=True, exist_ok=True)

            with tarfile.open(source) as archive:
                archive.extractall(target)

            if not source == root_tar_path:
                source.unlink()

            for child in target.iterdir():
                self.recursive_extraction(
                    source=child,
                    target=target / self.remove_tar_and_gzip_extensions_if_any(child.name),
                    root_tar_path=root_tar_path,
                )
            return

        if source.suffix == ".gz":
            decompressed_path = target.with_suffix(target.suffix.replace(".gz", ""))
            self.decompress_gzip(gzip_path=source, target_path=decompressed_path)
            source.unlink()
            self.recursive_extraction(source=decompressed_path, target=target, root_tar_path=root_tar_path)
            return

        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copy2(src=source, dst=target.parent)

    def remove_interior_tar_or_gzip_extensions(self, file: str) -> str:
        """Remove tar and gzip extensions within a file path, excluding the last part of the path.

        Args:
            file: The file path.

        Returns:
            File path with tar and gzip extensions removed.
        """
        file_path = Path(file)
        file_name = file_path.name
        file_parent_path = str(file_path.parent)
        return f"{self.remove_tar_and_gzip_extensions_if_any(file_parent_path)}/{file_name}"
