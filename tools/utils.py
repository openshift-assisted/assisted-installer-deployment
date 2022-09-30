import netrc
import re
from consts import TITLE_NORMALIZATION_REGEX


def get_credentials_from_netrc(*, hostname, netrc_file=None):
    """Fetch username and password stored on netrc file, for accessing a service."""
    credentials = netrc.netrc(file=netrc_file).authenticators(hostname)
    if credentials is None:
        return None, None

    return credentials[0], credentials[2]


def normalize_jira_title(s):
    # We use non-compiled regex as based on the benchmark from StackOverflow
    # (https://stackoverflow.com/a/1277047/1864702) it is one of the fastest methods
    # that also allows for an easy syntax and reuse of the function.
    return re.sub(TITLE_NORMALIZATION_REGEX, '', s)


def normalize_jira_titles(titles):
    map_object = map(normalize_jira_title, list(titles))
    return list(map_object)
