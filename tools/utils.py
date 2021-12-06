import netrc
from typing import Tuple, Optional
from urllib.parse import urlparse

import jira

JIRA_SERVER = "https://issues.redhat.com"


def get_login_credentials(joined_credentials: str) -> Tuple[Optional[str], Optional[str]]:
    if joined_credentials is None:
        return None, None

    return joined_credentials.split(":", 1)


def get_credentials_from_netrc(*, hostname, netrc_file=None):
    """Fetch username and password stored on netrc file, for accessing a service."""
    credentials = netrc.netrc(file=netrc_file).authenticators(hostname)
    if credentials is None:
        return None, None

    return credentials[0], credentials[2]


def get_jira_client(*, access_token=None, username=None, password=None, netrc_file=None, server=JIRA_SERVER) -> jira.JIRA:
    """Get a jira client object using provided means for credentials.

    Priority between means is:
    * Using PAT (Personal Access Token).
    * Using basic auth with the provided `username` and ``password``.
    * Fetching username and password from the provided netrc path
      (or fetching from the default path '~/.netrc').
    """
    if access_token is not None:
        return jira.JIRA(server, token_auth=access_token)

    if username is None or password is None:
        username, password = get_credentials_from_netrc(
            hostname=urlparse(server).hostname,
            netrc_file=netrc_file,
        )
        if username is None or password is None:
            raise ValueError("No means for authenticating with Jira were given")

    return jira.JIRA(
        server,
        basic_auth=(username, password)
    )
