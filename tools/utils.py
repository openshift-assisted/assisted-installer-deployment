import netrc
from datetime import datetime

import dateutil.parser


def days_ago(datestr):
    return (datetime.now() - dateutil.parser.isoparse(datestr)).days


def get_credentials_from_netrc(*, hostname, netrc_file=None):
    """Fetch username and password stored on netrc file, for accessing a service."""
    credentials = netrc.netrc(file=netrc_file).authenticators(hostname)
    if credentials is None:
        return None, None

    return credentials[0], credentials[2]
