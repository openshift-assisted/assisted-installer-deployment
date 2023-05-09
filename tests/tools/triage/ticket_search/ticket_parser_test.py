from unittest.mock import MagicMock, Mock

import pytest

from tools.triage.ticket_search.ticket_parser import TicketParser
from tools.triage.ticket_search.triage_ticket import TriageTicket


class TestTicketFetcher:
    description = """{color:red}Do not manually edit this description, it will get automatically over-written{color}
    h1. Cluster Info

    *Cluster ID:* [b9087f44-ddd0-4aa1-889b-37a2a0c1b6f6|https://issues.redhat.com/issues/?jql=project%20%3D%20AITRIAGE%20AND%20component%20%3D%20Cloud-Triage%20and%20cf%5B12316349%5D%20~%20"b9087f44-ddd0-4aa1-889b-37a2a0c1b6f6"]
    *OpenShift Cluster ID:* 039a659a-6313-4862-90ca-3b6af51b13a6
    *Username:* [user@domain.com|https://issues.redhat.com/issues/?jql=project%20%3D%20AITRIAGE%20AND%20component%20%3D%20Cloud-Triage%20and%20cf%5B12319044%5D%20~%20"user@domain.com"]
    *Email domain:* [somesite.com|https://issues.redhat.com/issues/?jql=project%20%3D%20AITRIAGE%20AND%20component%20%3D%20Cloud-Triage%20and%20cf%5B12319045%5D%20~%20"somesite.com"]
    *Created_at:* 2023-02-13 15:29:39
    *Installation started at:* 2023-02-14 06:09:26
    *Failed on:* 2023-02-14 07:50:15
    *status:* error
    *status_info:* cluster has hosts in error
    *OpenShift version:* 4.12.1
    *Platform type:* baremetal
    *Olm Operators:* CNV, LSO
    *Configured features:* Additional NTP Source, Cluster Tags, Hyperthreading, OVN network type, Requested hostname, Static Network Config, auto assign role

    *links:*
    * [Cluster on prod - must be logged in as read-only admin|https://console.redhat.com/openshift/assisted-installer/clusters/b9087f44-ddd0-4aa1-889b-37a2a0c1b6f6]
    ** {color:#de350b}*If you find logs on prod that are missing from the Installation logs link below, please upload them as Jira attachments ASAP*{color}
    * [Installation logs - requires VPN|http://assisted-logs-collector.usersys.redhat.com/#/2023-02-14_06-09-26_b9087f44-ddd0-4aa1-889b-37a2a0c1b6f6/]
    * [Kraken - cluster live telemetry|https://kraken.psi.redhat.com/clusters/039a659a-6313-4862-90ca-3b6af51b13a6]
    * [Elastic - installation events|https://kibana-assisted.apps.app-sre-prod-04.i5h0.p1.openshiftapps.com/_dashboards/app/discover?security_tenant=global#/?_g=(filters:!(),query:(language:kuery,query:''),refreshInterval:(pause:!t,value:0),time:(from:now-1M,to:now))&_a=(columns:!(message,cluster.id,cluster.email_domain,cluster.platform.type),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:bd9dadc0-7bfa-11eb-95b8-d13a1970ae4d,key:cluster.id,negate:!f,params:(query:'b9087f44-ddd0-4aa1-889b-37a2a0c1b6f6'),type:phrase),query:(match_phrase:(cluster.id:'b9087f44-ddd0-4aa1-889b-37a2a0c1b6f6')))),index:bd9dadc0-7bfa-11eb-95b8-d13a1970ae4d,interval:auto,query:(language:kuery,query:''),sort:!())]
    * [AWS CloudWatch FAQ - service logs|https://docs.engineering.redhat.com/display/AI/CloudWatch+access]
    """

    def test_can_handle_empty_description(self, ticket_parser, mock_issue):
        ticket_parser.parse(mock_issue)

    def test_parse_issue(self, ticket_parser, mock_issue, jira_attachment_downloader):
        """Tests the deep parse functionality"""
        ticket = ticket_parser.parse(mock_issue)
        jira_attachment_downloader.download_attachments_for_ticket.assert_called_once_with(mock_issue)
        assert ticket.openshift_version == "4.12.1"
        assert ticket.platform_type == "baremetal"
        assert ticket.olm_operators == ["CNV", "LSO"]
        assert ticket.configured_features == ["Additional NTP Source", "Cluster Tags", "Hyperthreading", "OVN network type", "Requested hostname", "Static Network Config", "auto assign role"]

    def test_parse_cluster_info_fields(self, ticket_parser, mock_ticket):
        """Test the parse_cluster_info_fields method"""
        ticket_parser.parse_cluster_info_fields(mock_ticket)
        assert mock_ticket.openshift_version == "4.12.1"
        assert mock_ticket.platform_type == "baremetal"
        assert mock_ticket.olm_operators == ["CNV", "LSO"]
        assert mock_ticket.configured_features == ["Additional NTP Source", "Cluster Tags", "Hyperthreading", "OVN network type", "Requested hostname", "Static Network Config", "auto assign role"]

    def test_parse_failure_for_single_ticket_should_be_fatal(self, ticket_parser, mock_issue, jira_attachment_downloader):
        jira_attachment_downloader.download_attachments_for_ticket = MagicMock(side_effect=Exception("Simulated exception"))
        with pytest.raises(Exception, match="Simulated exception"):
            ticket_parser.parse(mock_issue)

    @pytest.fixture
    def mock_issue(self):
        """Set up a mock issue"""
        issue = Mock()
        issue.key = "MGMT-12345"
        issue.fields = Mock()
        issue.fields.description = self.description
        return issue

    @pytest.fixture
    def jira_attachment_downloader(self):
        return Mock()

    @pytest.fixture
    def ticket_parser(self, jira_attachment_downloader):
        """Set up the ticket parser"""
        return TicketParser(jira_attachment_downloader)

    @pytest.fixture
    def mock_ticket(self, mock_issue):
        """Set up a mock ticket"""
        return TriageTicket(mock_issue)
