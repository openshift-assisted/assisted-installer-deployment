import sys
import jira
from tools.jira_client import (
   JiraClientFactory,
   JiraDryRunClient
)


def test_should_create_real_jira_client_when_output_stream_is_none():
    # This test does not need to validate credentials as we only care about the type of jira_client.
    jira_client = JiraClientFactory.create("foobar", validate=False)
    assert isinstance(jira_client, jira.client.JIRA)


def test_should_create_fake_jira_client_when_output_stream_is_none():
    # This test does not need to validate credentials as we only care about the type of jira_client.
    jira_client = JiraClientFactory.create("foobar", validate=False, dry_run_stream=sys.stdout)
    assert not isinstance(jira_client, jira.client.JIRA)
    assert isinstance(jira_client, JiraDryRunClient)
