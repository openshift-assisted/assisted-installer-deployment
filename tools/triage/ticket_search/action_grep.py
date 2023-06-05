import logging
import re
import subprocess
from subprocess import PIPE


class ActionGrep:
    def __init__(self, pattern, workflow_data):
        self.pattern = pattern
        self.workflow_data = workflow_data
        self.logger = logging.getLogger(__name__)

    def get_id_from_aitriage_path(self, path) -> str:
        result = re.findall(r"(AITRIAGE-\d*)", path)
        if len(result) > 0:
            return result[0]
        return None

    def store_match(self, issue_id, full_path):
        if "matches" not in self.workflow_data:
            self.workflow_data["matches"] = {}
        if issue_id not in self.workflow_data["matches"]:
            self.workflow_data["matches"][issue_id] = {}
        if "files" not in self.workflow_data["matches"][issue_id]:
            self.workflow_data["matches"][issue_id]["files"] = []
        self.workflow_data["matches"][issue_id]["files"] += [full_path]

    def parse_and_store_matches(self, issue_id, matched: list[str]):
        for match in matched:
            self.store_match(issue_id, match)

    def file_action(self, full_path):
        try:
            process = subprocess.Popen(
                [
                    "/bin/grep",
                    "-lir",
                    # Escape any special chars in the search pattern so that bash interprets these correctly
                    re.sub(r"(!|\$|#|&|\"|\'|\(|\)|\||<|>|`|\\\|;)", r"\\\1", self.pattern),
                    full_path,
                ],
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE,
            )
            output, error = process.communicate(timeout=60)
        except Exception as e:
            message = f"Error encountered while attempting to spawn process to grep {full_path} error output is: {e}"
            self._handle_error(message, e)

        if process.returncode == 0:  # Lines were selected.
            self.parse_and_store_matches(self.get_id_from_aitriage_path(full_path), output.decode("utf-8").split("\n"))
            return
        if process.returncode != 1:
            message = f"Unknown returncode {process.returncode} encountered while attempting to grep {full_path} error output is: {error}"
            self._handle_error(message)

    def _handle_error(self, message, e: Exception):
        self.logger.error(message)
        if e is not None:
            raise e
