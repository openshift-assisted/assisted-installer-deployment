class JiraDryRunClient:
    def __init__(self, jira_client, dry_run_stream) -> None:
        self._dry_run_stream = dry_run_stream
        self._jira_client = jira_client

    def __getattr__(self, name):
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            return getattr(self._jira_client, name)

    def create_issue_link(self, link_name, issue_key, root_issue_key):
        print(
            f"Linked issue key={issue_key} as {link_name} root issue key={root_issue_key}\n",
            file=self._dry_run_stream,
            flush=True,
        )

    def transition_issue(self, issue_key, target_status):
        print(
            f"Transitioned issue key={issue_key} to {target_status}",
            file=self._dry_run_stream,
            flush=True,
        )
