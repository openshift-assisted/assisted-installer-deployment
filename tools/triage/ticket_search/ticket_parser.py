"""Ticket Parser module"""
import logging
import re

from .jira_attachment_downloader import JiraAttachmentDownloader
from .triage_ticket import TriageTicket


class TicketParser:
    """Responsible for parsing ticket details and log file directory from the jira issue"""

    def __init__(self, jira_attachment_downloader: "JiraAttachmentDownloader"):
        """Constructor"""
        self.jira_attachment_downloader = jira_attachment_downloader
        self.logger = logging.getLogger(__name__)

    def parse_cluster_info_fields(self, ticket: "TriageTicket"):
        description_parts = ticket.description.split("\n")
        ticket.openshift_version = ""
        ticket.platform_type = ""
        ticket.olm_operators = ""
        ticket.configured_features = ""
        searches = {
            "openshift_version": r"(OpenShift version:\*)\s(\S+)$",
            "platform_type": r"(Platform type:\*)\s(\S+)$",
            "olm_operators": r"(Olm Operators:\*)\s(.+)$",
            "configured_features": r"(Configured features:\*)\s(.+)$",
        }
        for description_part in description_parts:
            for key in searches.keys():
                result = re.search(searches[key], description_part)
                if result is not None:
                    value = result[2]
                    match key:
                        case "openshift_version":
                            ticket.openshift_version = value
                        case "platform_type":
                            ticket.platform_type = value
                        case "olm_operators":
                            ticket.olm_operators = value.split(",")
                            ticket.olm_operators = [operator.strip() for operator in ticket.olm_operators]
                        case "configured_features":
                            ticket.configured_features = value.split(",")
                            ticket.configured_features = [
                                configured_feature.strip() for configured_feature in ticket.configured_features
                            ]

    def parse(self, jira_issue) -> "TriageTicket":
        """Parse a Jira issue and return a parsed TriageTicket ready for use"""
        if jira_issue is None:
            self.logger.warn("WARNING: Attempted to parse an empty Jira issue")
            return None
        triage_ticket = TriageTicket(jira_issue)

        if jira_issue.fields.description is not None:
            self.parse_cluster_info_fields(triage_ticket)

        try:
            self.jira_attachment_downloader.download_attachments_for_ticket(jira_issue)
        except Exception as e:
            self._handle_error(
                f"There was a problem while downloading attachments for ticket {jira_issue.key}, exception: {str(e)}", e
            )

        return triage_ticket

    def _handle_error(self, message, e: Exception):
        """Handles an error if it occurs"""
        self.logger.error(message)
        raise e
