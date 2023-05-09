from unittest.mock import MagicMock

import jira
import pytest

from tools.triage.ticket_search.settings import (
    JIRA_SEARCH_FAILURE_RETRIES,
    PARSE_FAILURE_COUNT_FATALITY_THRESHOLD,
)
from tools.triage.ticket_search.ticket_fetcher import TicketFetcher
from tools.triage.ticket_search.triage_ticket import TriageTicket


class TestTicketFetcher:

    def mock_issue(self, issue_id, component):
        """Set up a mock issue"""
        issue = MagicMock()
        issue.key = issue_id
        issue.fields = MagicMock()
        issue.fields.components = [MagicMock()]
        issue.fields.components[0].name = component
        issue.fields.description = f"Description for {issue_id}"
        return issue

    @pytest.fixture
    def mock_valid_triage_issue(self):
        """Set up a mock issue"""
        issue = MagicMock()
        issue.key = "MGMT-12345"
        issue.fields = MagicMock()
        issue.fields.components = [MagicMock()]
        issue.fields.components[0].name = "Cloud-Triage"
        issue.fields.description = "Description for MGMT-12345"
        return issue

    @pytest.fixture
    def mock_non_triage_issue(self):
        """Set up a mock issue"""
        issue = MagicMock()
        issue.key = "MGMT-12346"
        issue.fields = MagicMock()
        issue.fields.components = [MagicMock()]
        issue.fields.components[0].name = "SomeOtherComponent"
        issue.fields.description = "Description for MGMT-12346"
        return issue

    @pytest.fixture
    def jira_client(self):
        return MagicMock()

    @pytest.fixture
    def ticket_parser(self):
        return MagicMock()

    @pytest.fixture
    def cache(self):
        return MagicMock()

    @pytest.fixture
    def ticket_fetcher(self, ticket_parser, jira_client):
        return TicketFetcher(ticket_parser, jira_client)

    @pytest.fixture
    def ticket_query(self):
        query = MagicMock()
        query.build = MagicMock(return_value="Some JQL")
        return query

    def test_ticket_should_be_parsed_if_it_is_a_triage_issue(self,
                                                             jira_client,
                                                             ticket_fetcher,
                                                             ticket_parser,
                                                             mock_valid_triage_issue
                                                             ):
        """If the ticket is a triage issue then we will parse it"""
        jira_client.issue = MagicMock(return_value=mock_valid_triage_issue)
        ticket_fetcher.fetch_single_ticket_by_key(mock_valid_triage_issue.key)
        jira_client.issue.assert_called_once_with(mock_valid_triage_issue.key)
        ticket_parser.parse.assert_called_once_with(mock_valid_triage_issue)

    def test_ticket_should_not_be_parsed_if_it_is_not_a_triage_issue(self,
                                                                     jira_client,
                                                                     ticket_fetcher,
                                                                     ticket_parser,
                                                                     mock_non_triage_issue
                                                                     ):
        """If the ticket is not a triage issue then we will skip it"""
        jira_client.issue = MagicMock(return_value=mock_non_triage_issue)
        ticket_fetcher.fetch_single_ticket_by_key(mock_non_triage_issue.key)
        jira_client.issue.assert_called_once_with(mock_non_triage_issue.key)
        ticket_parser.parse.assert_not_called()

    def test_should_throw_an_exception_if_unable_to_fetch_a_ticket(self,
                                                                   jira_client,
                                                                   ticket_fetcher
                                                                   ):
        jira_client.issue = MagicMock(side_effect=jira.exceptions.JIRAError("Jira error"))
        with pytest.raises(Exception, match="Jira error"):
            ticket_fetcher.fetch_single_ticket_by_key("MGMT-12345")

    def test_fetch_page_by_query(self,
                                 jira_client,
                                 ticket_fetcher,
                                 ticket_parser,
                                 ticket_query,
                                 mock_valid_triage_issue,
                                 mock_non_triage_issue
                                 ):
        """Test fetch by query"""
        jira_client.search_issues = MagicMock()
        jira_client.search_issues.side_effect = [jira.exceptions.JIRAError("Jira error"), [mock_valid_triage_issue, mock_non_triage_issue]]
        ticket_parser.parse = MagicMock()
        ticket_parser.parse.side_effect = [TriageTicket(mock_valid_triage_issue)]
        tickets = ticket_fetcher.fetch_page_by_query(ticket_query, 10, 0)
        ticket_parser.parse.assert_any_call(mock_valid_triage_issue)
        assert ticket_parser.parse.call_count == 1
        assert tickets[0].key == mock_valid_triage_issue.key
        assert tickets[0].description == mock_valid_triage_issue.fields.description

    def test_fetch_page_by_query_jira_errors_below_threshold(self,
                                                             jira_client,
                                                             ticket_query,
                                                             mock_valid_triage_issue,
                                                             ticket_fetcher
                                                             ):
        number_of_simulated_failures = JIRA_SEARCH_FAILURE_RETRIES - 1
        jira_client.search_issues = MagicMock()
        side_effects = []
        for _ in range(0, number_of_simulated_failures):
            side_effects += [jira.exceptions.JIRAError("Ticket fetcher exception")]
        side_effects += [mock_valid_triage_issue]
        jira_client.search_issues.side_effect = side_effects
        ticket_fetcher.fetch_page_by_query(ticket_query, 10, 0)

    def test_fetch_page_by_query_too_many_jira_errors(self,
                                                      jira_client,
                                                      ticket_query,
                                                      ticket_fetcher
                                                      ):
        number_of_simulated_failures = JIRA_SEARCH_FAILURE_RETRIES + 1
        jira_client.search_issues = MagicMock()
        side_effects = []
        for _ in range(0, number_of_simulated_failures):
            side_effects += [jira.exceptions.JIRAError("Ticket fetcher exception")]
        jira_client.search_issues.side_effect = side_effects
        with pytest.raises(Exception, match="Ticket fetcher exception"):
            ticket_fetcher.fetch_page_by_query(ticket_query, 10, 0)

    def test_should_not_fail_when_parse_errors_below_threshold(self,
                                                               jira_client,
                                                               ticket_query,
                                                               ticket_parser,
                                                               mock_valid_triage_issue,
                                                               ticket_fetcher
                                                               ):
        """Test fetch by query"""
        number_of_simulated_failures = PARSE_FAILURE_COUNT_FATALITY_THRESHOLD - 1
        issues = []
        for _ in range(0, number_of_simulated_failures):
            issues += [mock_valid_triage_issue]
        jira_client.search_issues = MagicMock()
        jira_client.search_issues.side_effect = [issues]
        ticket_parser.parse = MagicMock()
        side_effects = []
        for _ in range(0, number_of_simulated_failures):
            side_effects += [Exception("Ticket parser exception")]
        ticket_parser.parse.side_effect = side_effects
        ticket_fetcher.fetch_page_by_query(ticket_query, 10, 0)

    def test_should_fail_on_too_many_parse_errors(self,
                                                  jira_client,
                                                  ticket_query,
                                                  ticket_parser,
                                                  ticket_fetcher,
                                                  mock_valid_triage_issue
                                                  ):
        """Test fetch by query"""
        number_of_simulated_failures = PARSE_FAILURE_COUNT_FATALITY_THRESHOLD + 1
        issues = []
        for _ in range(0, number_of_simulated_failures):
            issues += [mock_valid_triage_issue]
        jira_client.search_issues = MagicMock()
        jira_client.search_issues.side_effect = [issues]
        ticket_parser.parse = MagicMock()
        side_effects = []
        for _ in range(0, number_of_simulated_failures):
            side_effects += [Exception("Ticket parser exception")]
        ticket_parser.parse.side_effect = side_effects
        with pytest.raises(Exception, match="Ticket parser exception"):
            ticket_fetcher.fetch_page_by_query(ticket_query, 10, 0)
