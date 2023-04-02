# pylint: disable=too-few-public-methods
import jira

from tools import consts

from .jira_dryrun_client import JiraDryRunClient


class JiraClientFactory:
    @staticmethod
    def create(jira_access_token, dry_run_stream=None, validate=True):
        client = jira.JIRA(server=consts.JIRA_SERVER, token_auth=jira_access_token, validate=validate, max_retries=0)
        if dry_run_stream is not None:
            client = JiraDryRunClient(client, dry_run_stream)
        return client
