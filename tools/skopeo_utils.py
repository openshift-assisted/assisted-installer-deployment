import json
import re
import subprocess

from retry import retry


class Skopeo:
    @retry(exceptions=subprocess.SubprocessError, tries=3, delay=10)
    def get_image_tags_by_pattern(self, repository: str, pattern: str) -> list[str]:
        """Returns prefixed tags ordered by most recent to least recent"""
        docker_uri = f"docker://{repository}"
        out = subprocess.check_output(["skopeo", "list-tags", docker_uri])
        json_output = out.decode("utf-8")
        response = json.loads(json_output)
        if "Tags" not in response:
            return []
        # tags are returned by skopeo from oldest to newest. Let's reverse the order
        return [tag for tag in response["Tags"] if re.search(pattern, tag) is not None][::-1]

    def tag_image(self, image: str, source_tag: str, target_tag: str) -> None:
        subprocess.check_output(
            [
                "skopeo",
                "copy",
                f"docker://{image}:{source_tag}",
                f"docker://{image}:{target_tag}",
            ]
        )
