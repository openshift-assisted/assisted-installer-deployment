import gzip
import os
import tarfile
from io import BytesIO
from pathlib import Path

from tools.triage.utils.extraction.jira_attachment_querier.local_nested_archive_extractor import (
    LocalNestedArchiveExtractor,
)


def create_in_memory_tar(files: dict) -> BytesIO:
    buffer = BytesIO()

    with tarfile.open(fileobj=buffer, mode='w') as tar:
        for name, content in files.items():

            if isinstance(content, (str, bytes)):
                content_bytes = content if isinstance(content, bytes) else content.encode()
                tarinfo = tarfile.TarInfo(name=name)
                tarinfo.size = len(content_bytes)
                tarinfo.mode = 0o644
                tar.addfile(tarinfo, BytesIO(content_bytes))

            elif isinstance(content, dict):
                tarinfo = tarfile.TarInfo(name=name)
                tarinfo.type = tarfile.DIRTYPE
                tarinfo.mode = 0o755
                tar.addfile(tarinfo)

                for sub_name, sub_content in content.items():
                    sub_content_bytes = sub_content if isinstance(sub_content, bytes) else sub_content.encode()
                    tarinfo = tarfile.TarInfo(name=os.path.join(name, sub_name))
                    tarinfo.size = len(sub_content_bytes)
                    tarinfo.mode = 0o644
                    tar.addfile(tarinfo, BytesIO(sub_content_bytes))

    buffer.seek(0)
    return buffer


def create_in_memory_gz(content: str) -> BytesIO:
    buffer = BytesIO()

    with gzip.GzipFile(fileobj=buffer, mode='wb') as gnu_zip:
        gnu_zip.write(content.encode())

    buffer.seek(0)
    return buffer


def create_nested_tar(level: int) -> BytesIO:
    def create_tar_with_file(level):
        return create_in_memory_tar({
            f'file_in_tar_in_dir_level_{level}.txt': f'Content of file in tar in dir at level {level}.'
        })

    if level <= 0:
        return create_in_memory_tar({
            'file_1_base.txt': 'Content of file_1 at base level.',
            'file_2_base.txt': 'Content of file_2 at base level.',
            'file_3_base.txt': 'Content of file_3 at base level.',
            'dir_base': {
                'file_in_dir_base.txt': 'Content in file in base directory.',
                'tar_in_dir_base.tar': create_tar_with_file('base').getvalue()
            }
        })

    nested_tar = create_nested_tar(level - 1)

    if level == 2:
        gz_content = "This is some content for the gzipped file."
        gz_file = create_in_memory_gz(gz_content)

        return create_in_memory_tar({
            f'file_1_level_{level}.txt': f'Content of file_1 at level {level}.',
            f'file_2_level_{level}.txt': f'Content of file_2 at level {level}.',
            f'level_{level}_tar.tar': nested_tar.getvalue(),
            f'dir_level_{level}': {
                f'file_in_dir_level_{level}.txt': f'Content in file in directory at level {level}.',
                f'tar_in_dir_level_{level}.tar': create_tar_with_file(level).getvalue(),
                'sample_file.gz': gz_file.getvalue()
            }
        })

    return create_in_memory_tar({
        f'file_1_level_{level}.txt': f'Content of file_1 at level {level}.',
        f'file_2_level_{level}.txt': f'Content of file_2 at level {level}.',
        f'level_{level}_tar.tar': nested_tar.getvalue(),
        f'dir_level_{level}': {
            f'file_in_dir_level_{level}.txt': f'Content in file in directory at level {level}.',
            f'tar_in_dir_level_{level}.tar': create_tar_with_file(level).getvalue()
        }
    })


def normalize_tree(tree: str) -> str:
    return tree.replace('|──', '├──')


def test_recursive_extraction(tmp_path):
    """expected tree:

        ├── extracted
        │   ├── level_3_tar
        │   │   ├── level_2_tar
        │   │   │   ├── level_1_tar
        │   │   │   │   ├── dir_base
        │   │   │   │   │   ├── tar_in_dir_base
        │   │   │   │   │   │   ├── file_in_tar_in_dir_level_base.txt
        │   │   │   │   │   ├── file_in_dir_base.txt
        │   │   │   │   ├── file_3_base.txt
        │   │   │   │   ├── file_2_base.txt
        │   │   │   │   ├── file_1_base.txt
        │   │   │   ├── dir_level_1
        │   │   │   │   ├── tar_in_dir_level_1
        │   │   │   │   │   ├── file_in_tar_in_dir_level_1.txt
        │   │   │   │   ├── file_in_dir_level_1.txt
        │   │   │   ├── file_2_level_1.txt
        │   │   │   ├── file_1_level_1.txt
        │   │   ├── dir_level_2
        │   │   │   ├── tar_in_dir_level_2
        │   │   │   │   ├── file_in_tar_in_dir_level_2.txt
        │   │   │   ├── sample_file
        │   │   │   ├── file_in_dir_level_2.txt
        │   │   ├── file_2_level_2.txt
        │   │   ├── file_1_level_2.txt
        │   ├── dir_level_3
        │   │   ├── tar_in_dir_level_3
        │   │   │   ├── file_in_tar_in_dir_level_3.txt
        │   │   ├── file_in_dir_level_3.txt
        │   ├── file_2_level_3.txt
        │   ├── file_1_level_3.txt
    """

    nested_tar_buffer = create_nested_tar(3)
    nested_tar_path = tmp_path / "nested.tar"

    with open(nested_tar_path, 'wb') as file:
        file.write(nested_tar_buffer.getvalue())

    target_path: Path = tmp_path / "extracted"
    LocalNestedArchiveExtractor().recursive_extraction(nested_tar_path, target_path, root_tar_path=nested_tar_path)

    assertions: dict[Path, str] = {
        target_path / "file_1_level_3.txt": "Content of file_1 at level 3.",  # files in tars
        target_path / "level_3_tar" / "dir_level_2" / "file_in_dir_level_2.txt": "Content in file in directory at level 2.",  # directories in tars
        target_path / "level_3_tar" / "level_2_tar" / "dir_level_1" / "tar_in_dir_level_1" / "file_in_tar_in_dir_level_1.txt": "Content of file in tar in dir at level 1.",  # tars in directories in tars
        target_path / "level_3_tar" / "dir_level_2" / "sample_file": "This is some content for the gzipped file."
    }

    for file_path, content in assertions.items():
        assert file_path.read_text() == content
