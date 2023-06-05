"""Triage ticket module"""
# pylint: disable=too-few-public-methods


class TriageTicket:
    """A class to model a triage ticket retrieved from Jira"""

    def __init__(self, issue=None):
        """Constructor"""

        if issue is not None:
            self.key = issue.key
            self.issue = issue
            self.description = issue.fields.description

        self.openshift_version = None
        self.platform_type = None
        self.olm_operators = []
        self.configured_features = []
