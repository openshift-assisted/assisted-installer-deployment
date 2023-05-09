from tools.triage.ticket_search.triage_ticket import TriageTicket


class IssueCache:
    """Interface for an issue cache"""

    def exists(self, issue_id: str) -> bool:
        raise NotImplementedError

    def save_metadata(self, triage_ticket: "TriageTicket"):
        raise NotImplementedError
