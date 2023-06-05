"""TicketQuery module"""
import logging

from tools.triage.common import JIRA_PROJECT
from tools.triage.ticket_search import settings


class TicketQuery:
    """Represents a query to Jira for a triage ticket"""

    def __init__(
        self,
        project_filter=JIRA_PROJECT,
        component_filter=settings.TRIAGE_TICKET_SEARCH_COMPONENT,
    ):
        """Constructor"""
        self.logger = logging.getLogger(__name__)
        self.project_filter = project_filter
        self.component_filter = component_filter
        self.queries = []

    @staticmethod
    def create(project_filter="AITRIAGE", component_filter="Cloud-Triage") -> "TicketQuery":
        """Create a TicketQuery"""
        return TicketQuery(project_filter, component_filter).project_filter_query().component_filter_query()

    def days_query(self, number_of_days: int) -> "TicketQuery":
        """Specifies how far back (in days) to look for tickets"""
        self.queries += [f"created >= -{number_of_days}d"]
        return self

    def project_filter_query(self) -> "TicketQuery":
        """Filter by the project filter"""
        self.queries += [f'project = "{self.project_filter}" ']
        return self

    def component_filter_query(self) -> "TicketQuery":
        """Filter by the component filter"""
        self.queries += [f'component = "{self.component_filter}"']
        return self

    def text_like_query(self, term: str) -> "TicketQuery":
        """Filter for text similar to term"""
        self.queries += [f'text ~ "{term}"']
        return self

    def jql_clause(self, clause: str) -> "TicketQuery":
        """Add a raw JQL clause"""
        self.queries += [f"{clause}"]
        return self

    def openshift_version(self, openshift_version: str) -> "TicketQuery":
        search_term = f"OpenShift version: {openshift_version}"
        return self.text_like_query(search_term)

    def build(self) -> str:
        """Build the query string"""
        return "(" + " AND ".join(self.queries) + ") ORDER BY created DESC"
