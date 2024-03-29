"""Constants that are common to all triage tools."""
TRIAGE_TICKET_SEARCH_COMPONENT = "Cloud-Triage"
TRIAGE_TICKET_SEARCH_DEFAULT_DAYS = 31
DATA_DIRECTORY = "/data/triage-tools-tickets"
JIRA_SEARCH_FAILURE_RETRIES = 10
PARSE_FAILURE_COUNT_FATALITY_THRESHOLD = 10

__all__ = [
    "TRIAGE_TICKET_SEARCH_COMPONENT",
    "TRIAGE_TICKET_SEARCH_DEFAULT_DAYS",
]
