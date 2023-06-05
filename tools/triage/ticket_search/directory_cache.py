import json
import logging
import os

from tools.triage.ticket_search.issue_cache import IssueCache
from tools.triage.ticket_search.settings import DATA_DIRECTORY
from tools.triage.ticket_search.triage_ticket import TriageTicket


class DirectoryCache(IssueCache):
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def get_cached_issue_ids(self) -> list[str]:
        root_dir = f"{DATA_DIRECTORY}"
        entries = []
        candidates = os.listdir(root_dir)
        for candidate in candidates:
            if os.path.isdir(os.path.join(root_dir, candidate)):
                entries += [candidate]
        return entries

    def load_metadata(self, issue_id: str) -> "TriageTicket":
        try:
            triage_ticket = TriageTicket()
            triage_ticket.key = issue_id
            if not self.exists(triage_ticket.key):
                self.logger.error(f"{triage_ticket.key} was not found in the cache")
                return None
            path = os.path.join(f"{DATA_DIRECTORY}", f"{issue_id}", f"{issue_id}.metadata.json")
            content = []
            with open(path, "rb") as file:
                content = file.read()
            json_content = json.loads(content)
            for key in json_content.keys():
                value = json_content[key]
                if key == "openshift_version":
                    triage_ticket.openshift_version = value
                    break
                if key == "platform_type":
                    triage_ticket.platform_type = value
                    break
                if key == "olm_operators":
                    triage_ticket.olm_operators = value
                    break
                if key == "configured_features":
                    triage_ticket.configured_features = value
                    break
            return triage_ticket
        except OSError as e:
            self.logger.error(f"Unable to load metadata for {triage_ticket.key} due to error {e}")

    def save_metadata(self, triage_ticket: "TriageTicket"):
        try:
            if not self.exists(triage_ticket.key):
                self.logger.error(f"{triage_ticket.key} was not found in the cache, can't save metadata")
                return None
            ticket_metadata = {}
            ticket_metadata["openshift_version"] = triage_ticket.openshift_version
            ticket_metadata["platform_type"] = triage_ticket.platform_type
            ticket_metadata["olm_operators"] = triage_ticket.olm_operators
            ticket_metadata["configured_features"] = triage_ticket.configured_features
            json_output = json.dumps(ticket_metadata)
            destination_path = os.path.join(
                f"{DATA_DIRECTORY}", f"{triage_ticket.key}", f"{triage_ticket.key}.metadata.json"
            )
            with open(destination_path, "wb") as out:
                out.write(bytes(json_output, "utf-8"))
        except OSError as e:
            self.logger.error(f"Unable to save metadata for {triage_ticket.key} due to error {e}")

    def exists(self, issue_id):
        try:
            # If an item is in the cache then we will be able to find the directory for it.
            destination_path = os.path.join(f"{DATA_DIRECTORY}", issue_id)
            exists = os.path.exists(destination_path)
            if exists:
                self.logger.debug(f"{issue_id} was downloaded to the cache already")
            else:
                self.logger.debug(f"{issue_id} as not found in the cache")
            return exists
        except OSError as e:
            message = f"Warning: There was an error while trying to check for cached issue {issue_id} error was {e} - will treat as though no cache exists for item!"
            self.logger.error(message)
