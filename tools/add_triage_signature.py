#!/usr/bin/env python3
# pylint: disable=invalid-name,broad-except,missing-function-docstring,too-few-public-methods,missing-class-docstring,missing-module-docstring,line-too-long,too-many-locals,logging-fstring-interpolation
import abc
import argparse
import functools
import json
import logging
import netrc
import os
import re
import sys
import tempfile
from collections import OrderedDict, defaultdict
from datetime import datetime
from urllib.parse import urlparse

import dateutil.parser
import jira
import requests
import tqdm
from tabulate import tabulate

DEFAULT_DAYS_TO_HANDLE = 30

logger = logging.getLogger(__name__)

JIRA_DESCRIPTION = """
{{color:red}}Do not manually edit this description, it will get automatically over-written{{color}}
h1. Cluster Info

*Cluster ID:* [{cluster_id}|https://cloud.redhat.com/openshift/assisted-installer/clusters/{cluster_id}]
*Username:* {username}
*Email domain:* {domain}
*Created_at:* {created_at}
*Installation started at:* {installation_started_at}
*Failed on:* {failed_on}
*status:* {status}
*status_info:* {status_info}
*OpenShift version:* {openshift_version}

*links:*
* [Logs|{logs_url}/]
* [Kraken|https://kraken.psi.redhat.com/clusters/{OCP_cluster_id}]
* [Metrics|https://grafana.app-sre.devshift.net/d/assisted-installer-cluster-overview/cluster-overview?orgId=1&from=now-1h&to=now&var-datasource=app-sre-prod-04-prometheus&var-clusterId={cluster_id}]
* [Kibana|https://kibana-openshift-logging.apps.app-sre-prod-04.i5h0.p1.openshiftapps.com/app/kibana#/discover?_g=(refreshInterval:(pause:!t,value:0),time:(from:now-24h,mode:quick,to:now))&_a=(columns:!(_source),interval:auto,query:'"{cluster_id}"',sort:!('@timestamp',desc))]
* [DM Elastic|http://assisted-elastic.usersys.redhat.com:5601/app/discover#/?_g=(filters:!(),query:(language:kuery,query:''),refreshInterval:(pause:!t,value:0),time:(from:now-2w,to:now))&_a=(columns:!(message,cluster_id),filters:!(),index:'2d6517b0-5432-11eb-8ff7-115676c7222d',interval:auto,query:(language:kuery,query:'cluster_id:%20%22{cluster_id}%22%20'),sort:!())]
* [DM Elastic Dashboard|http://assisted-elastic.usersys.redhat.com:5601/app/dashboards#/view/500e1d40-58d6-11eb-8ff7-115676c7222d?_g=(filters:!(),query:(language:kuery,query:'cluster_id:%20%22{cluster_id}%22'),refreshInterval:(pause:!t,value:0),time:(from:now-2w,to:now))&_a=(description:'',filters:!(),fullScreenMode:!f,options:(hidePanelTitles:!f,useMargins:!t),query:(language:kuery,query:'cluster_id:%20%22{cluster_id}%22%20'),timeRestore:!f,title:'cluster%20overview',viewMode:view)]
"""


def format_description(failure_data):
    return JIRA_DESCRIPTION.format(**failure_data)

def days_ago(datestr):
    try:
        return (datetime.now() - dateutil.parser.isoparse(datestr)).days
    except Exception:
        logger.debug("Cannot parse date: %s", datestr)
        return 9999

@functools.lru_cache(maxsize=1000)
def get_metadata_json(cluster_url):
    res = requests.get("{}/metdata.json".format(cluster_url))
    res.raise_for_status()
    return res.json()

@functools.lru_cache(maxsize=1000)
def get_events_json(cluster_url, cluster_id):
    res = requests.get(f"{cluster_url}/cluster_{cluster_id}_events.json")
    res.raise_for_status()
    return res.json()

############################
# Common functionality
############################
class Signature(abc.ABC):
    dry_run_file = None
    def __init__(self, jira_client, comment_identifying_string, old_comment_string=None):
        self._jclient = jira_client
        self._identifing_string = comment_identifying_string
        self._old_identifing_string = old_comment_string

    def update_ticket(self, url, issue_key, should_update=False):
        try:
            self._update_ticket(url, issue_key, should_update=should_update)
        except Exception:
            logger.exception("error updating ticket %s", issue_key)

    @abc.abstractmethod
    def _update_ticket(self, url, issue_key, should_update=False):
        pass

    def _find_signature_comment(self, key):
        comments = self._jclient.comments(key)
        for comment in comments:
            if self._identifing_string in comment.body:
                return comment

            if self._old_identifing_string and self._old_identifing_string in comment.body:
                return comment
        return None

    def _update_triaging_ticket(self, key, comment, should_update=False):
        report = "\n"
        report += self._identifing_string + "\n"
        report += comment
        jira_comment = self._find_signature_comment(key)
        signature_name = type(self).__name__
        if self.dry_run_file is not None:
            self.dry_run_file.write(report)
            return

        if jira_comment is None:
            logger.info("Adding new '%s' comment to %s", signature_name, key)
            self._jclient.add_comment(key, report)
        elif should_update:
            logger.info("Updating existing '%s' comment of %s", signature_name, key)
            jira_comment.update(body=report)
        else:
            logger.debug("Not updating existing '%s' comment of %s", signature_name, key)

    def _update_description(self, key, new_description):
        i = self._jclient.issue(key)
        i.update(fields={"description": new_description})

    @staticmethod
    def _generate_table_for_report(hosts):
        return tabulate(hosts, headers="keys", tablefmt="jira") + "\n"

    @staticmethod
    def _logs_url_to_api(url):
        '''
        the log server has two formats for the url
        - URL for the UI  - http://assisted-logs-collector.usersys.redhat.com/#/2020-10-15_19:10:06_347ce6e8-bb4d-4751-825f-5e92e24da0d9/
        - URL for the API - http://assisted-logs-collector.usersys.redhat.com/files/2020-10-15_19:10:06_347ce6e8-bb4d-4751-825f-5e92e24da0d9/
        This function will return an API URL, regardless of which URL is supplied
        '''
        return re.sub(r'(http://[^/]*/)#(/.*)', r'\1files\2', url)

    @staticmethod
    def _logs_url_to_ui(url):
        '''
        the log server has two formats for the url
        - URL for the UI  - http://assisted-logs-collector.usersys.redhat.com/#/2020-10-15_19:10:06_347ce6e8-bb4d-4751-825f-5e92e24da0d9/
        - URL for the API - http://assisted-logs-collector.usersys.redhat.com/files/2020-10-15_19:10:06_347ce6e8-bb4d-4751-825f-5e92e24da0d9/
        This function will return an UI URL, regardless of which URL is supplied
        '''
        return re.sub(r'(http://[^/]*/)files(/.*)', r'\1#\2', url)

    @staticmethod
    def _get_hostname(host):
        hostname = host.get('requested_hostname')
        if hostname:
            return  hostname

        inventory = json.loads(host['inventory'])
        return inventory['hostname']


class HostsStatusSignature(Signature):
    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Install status:",
                         old_comment_string="h1. Host details:")

    def _update_ticket(self, url, issue_key, should_update=False):

        url = self._logs_url_to_api(url)
        try:
            md = get_metadata_json(url)
        except Exception as e:
            logger.error("Error getting logs for %s at %s: %s, they may have been deleted", issue_key, url, e)
            return

        cluster = md['cluster']

        hosts = []
        for host in cluster['hosts']:
            info = host['status_info']
            role = host['role']
            if host.get('bootstrap', False):
                role = 'bootstrap'
            hosts.append(OrderedDict(
                id=host['id'],
                hostname=self._get_hostname(host),
                progress=host['progress']['current_stage'],
                status=host['status'],
                role=role,
                status_info=str(info)))

        report = "h2. Cluster Status\n"
        report += "*status:* {}\n".format(cluster['status'])
        report += "*status_info:* {}\n".format(cluster['status_info'])
        report += "h2. Hosts status\n"
        report += self._generate_table_for_report(hosts)
        self._update_triaging_ticket(issue_key, report, should_update=should_update)


class FailureDescription(Signature):
    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="")

    def build_description(self, url, cluster_md):
        cluster_data = {"cluster_id": cluster_md['id'],
                        "logs_url": self._logs_url_to_ui(url),
                        "domain": cluster_md['email_domain'],
                        "openshift_version": cluster_md['openshift_version'],
                        "created_at": format_time(cluster_md['created_at']),
                        "installation_started_at": format_time(cluster_md['install_started_at']),
                        "failed_on": format_time(cluster_md['status_updated_at']),
                        "status": cluster_md['status'],
                        "status_info": cluster_md['status_info'],
                        "OCP_cluster_id": cluster_md['openshift_cluster_id'],
                        "username": cluster_md['user_name']}

        return format_description(cluster_data)

    def _update_ticket(self, url, issue_key, should_update=False):

        if not should_update:
            logger.debug("Not updating description of %s", issue_key)
            return

        url = self._logs_url_to_api(url)
        try:
            md = get_metadata_json(url)
        except Exception as e:
            logger.error("Error getting logs for %s at %s: %s, they may have been deleted", issue_key, url, e)
            return

        cluster = md['cluster']

        description = self.build_description(url, cluster)

        logger.info("Updating description of %s", issue_key)
        self._update_description(issue_key, description)


class HostsExtraDetailSignature(Signature):
    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Host extra details:")

    def _update_ticket(self, url, issue_key, should_update=False):

        url = self._logs_url_to_api(url)
        try:
            md = get_metadata_json(url)
        except Exception as e:
            logger.error("Error getting logs for %s at %s: %s, they may have been deleted", issue_key, url, e)
            return

        cluster = md['cluster']

        hosts = []
        for host in cluster['hosts']:
            inventory = json.loads(host['inventory'])
            hosts.append(OrderedDict(
                id=host['id'],
                hostname=inventory['hostname'],
                requested_hostname=host.get('requested_hostname', ""),
                last_contacted=format_time(host['checked_in_at']),
                installation_disk=host.get('installation_disk_path', ""),
                product_name=inventory['system_vendor'].get('product_name', "Unavailable"),
                manufacturer=inventory['system_vendor'].get('manufacturer', "Unavailable"),
                virtual_host=inventory['system_vendor'].get('virtual', False),
                disks_count=len(inventory['disks'])
            ))

        report = self._generate_table_for_report(hosts)
        self._update_triaging_ticket(issue_key, report, should_update=should_update)


class InstallationDiskFIOSignature(Signature):
    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Host installation disk fio:")

    @staticmethod
    def _get_fio_events(events):
        fio_regex = re.compile(r'\(fdatasync duration:\s(\d+)\sms\)')

        def get_duration(event):
            matches = fio_regex.findall(event["message"])
            if len(matches) == 0:
                return None

            return int(matches[0])

        return (
            (event, get_duration(event))
            for event in events
            if get_duration(event) is not None
        )

    def _update_ticket(self, url, issue_key, should_update=False):

        url = self._logs_url_to_api(url)
        try:
            md = get_metadata_json(url)
        except Exception as e:
            logger.error("Error getting logs for %s at %s: %s, they may have been deleted", issue_key, url, e)
            return

        cluster = md['cluster']

        cluster_id = cluster['id']
        events = get_events_json(cluster_url=url, cluster_id=cluster_id)
        fio_events = self._get_fio_events(events)

        fio_events_by_host = defaultdict(list)
        for event, fio_duration in fio_events:
            fio_events_by_host[event["host_id"]].append((event, fio_duration))

        hosts = []
        for host in cluster['hosts']:
            host_fio_events = fio_events_by_host[host["id"]]
            fio_message = "Under threshold"
            if len(host_fio_events) != 0:
                _events, host_fio_events_durations = zip(*fio_events_by_host[host["id"]])
                fio_message = (
                    "Installation disk is too slow, fio durations: " +
                    ", ".join(f"{duration}ms" for duration in host_fio_events_durations)
                )

            hosts.append(OrderedDict(
                id=host['id'],
                hostname=self._get_hostname(host),
                fio=fio_message,
                installation_disk=host.get('installation_disk_path', ""),
            ))

        report = self._generate_table_for_report(hosts)
        self._update_triaging_ticket(issue_key, report, should_update=should_update)

class StorageDetailSignature(Signature):
    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Host storage details:")

    def _update_ticket(self, url, issue_key, should_update=False):

        url = self._logs_url_to_api(url)
        try:
            md = get_metadata_json(url)
        except Exception as e:
            logger.error("Error getting logs for %s at %s: %s, they may have been deleted", issue_key, url, e)
            return

        cluster = md['cluster']

        hosts = []
        for host in cluster['hosts']:
            inventory = json.loads(host['inventory'])
            disks = inventory['disks']
            disks_details = defaultdict(list)
            for d in disks:
                disks_details['type'].append(d.get('drive_type', ""))
                disks_details['bootable'].append(str(d.get('bootable', "NA")))
                disks_details['name'].append(d.get('name', ""))
                disks_details['path'].append(d.get('path', ""))
                disks_details['by-path'].append(d.get('by_path', ""))
            hosts.append(OrderedDict(
                id=host['id'],
                hostname=self._get_hostname(host),
                disk_name="\n".join(disks_details['name']),
                disk_type="\n".join(disks_details['type']),
                disk_path="\n".join(disks_details['path']),
                disk_bootable="\n".join(disks_details['bootable']),
                disk_by_path="\n".join(disks_details['by-path'])
            ))

        report = self._generate_table_for_report(hosts)
        self._update_triaging_ticket(issue_key, report, should_update=should_update)


class ComponentsVersionSignature(Signature):
    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Components version information:")

    def _update_ticket(self, url, issue_key, should_update=False):

        url = self._logs_url_to_api(url)
        try:
            md = get_metadata_json(url)
        except Exception as e:
            logger.error("Error getting logs for %s at %s: %s, they may have been deleted", issue_key, url, e)
            return

        report = ""
        release_tag = md.get('release_tag')
        if release_tag:
            report = "Release tag: {}\n".format(release_tag)

        versions = md.get('versions')
        if versions:
            report += "assisted-installer: {}\n".format(versions['assisted-installer'])
            report += "assisted-installer-controller: {}\n".format(versions['assisted-installer-controller'])
            report += "assisted-installer-agent: {}\n".format(versions['discovery-agent'])

        if report != "":
            self._update_triaging_ticket(issue_key, report, should_update=should_update)


class LibvirtRebootFlagSignature(Signature):
    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Potential hosts with libvirt _on_reboot_ flag issue (MGMT-2840):")

    def _update_ticket(self, url, issue_key, should_update=False):

        url = self._logs_url_to_api(url)
        try:
            md = get_metadata_json(url)
        except Exception as e:
            logger.error("Error getting logs for %s at %s: %s, they may have been deleted", issue_key, url, e)
            return

        cluster = md['cluster']

        # this signature is relevant only if all hosts, but the bootstrap is in 'Rebooting' stage
        hosts = []
        for host in cluster['hosts']:
            inventory = json.loads(host['inventory'])

            if (len(inventory['disks']) == 1 and "KVM" in inventory['system_vendor']['product_name'] and
                    host['progress']['current_stage'] == 'Rebooting' and host['status'] == 'error'):
                if host['role'] == 'bootstrap':
                    return

                hosts.append(OrderedDict(
                    id=host['id'],
                    hostname=self._get_hostname(host),
                    role=host['role'],
                    progress=host['progress']['current_stage'],
                    status=host['status'],
                    num_disks=len(inventory.get('disks', []))))

        if len(hosts)+1 == len(cluster['hosts']):
            report = self._generate_table_for_report(hosts)
            self._update_triaging_ticket(issue_key, report, should_update=should_update)


############################
# Common functionality
############################
DEFAULT_NETRC_FILE = "~/.netrc"
JIRA_SERVER = "https://issues.redhat.com"
SIGNATURES = [FailureDescription, ComponentsVersionSignature, HostsStatusSignature, HostsExtraDetailSignature,
              StorageDetailSignature, InstallationDiskFIOSignature, LibvirtRebootFlagSignature]

def get_credentials_from_netrc(server, netrc_file=DEFAULT_NETRC_FILE):
    cred = netrc.netrc(os.path.expanduser(netrc_file))
    username, _, password = cred.authenticators(server)
    return username, password


def get_jira_client(username, password):
    logger.info("log-in with username: %s", username)
    return jira.JIRA(JIRA_SERVER, basic_auth=(username, password))

############################
# Signature runner functionality
############################
LOGS_URL_FROM_DESCRIPTION_OLD = re.compile(r".*logs:\* \[(http.*)\]")
LOGS_URL_FROM_DESCRIPTION_NEW = re.compile(r".*\* \[[lL]ogs\|(http.*)\]")

def get_issue(jclient, issue_key):
    issue = None
    try:
        issue = jclient.issue(issue_key)
    except jira.exceptions.JIRAError as e:
        if e.status_code != 404:
            raise
    if issue is None or issue.fields.components[0].name != "Assisted-installer Triage":
        raise Exception("issue {} does not exist or is not a triaging issue".format(issue_key))

    return issue


def get_logs_url_from_issue(issue):
    m = LOGS_URL_FROM_DESCRIPTION_NEW.search(issue.fields.description)
    if m is None:
        logger.debug("Cannot find new format of URL for logs in %s", issue.key)
        m = LOGS_URL_FROM_DESCRIPTION_OLD.search(issue.fields.description)
        if m is None:
            logger.debug("Cannot find old format of URL for logs in %s", issue.key)
            return None
    return m.groups()[0]

def get_all_triage_tickets(jclient, only_recent=False):
    recent_filter = "" if not only_recent else 'and created >= -31d'
    query = 'project = MGMT AND component = "Assisted-installer Triage" {}'.format(recent_filter)

    return jclient.search_issues(query, maxResults=None)

def get_issues(jclient, issue, only_recent):
    if issue is not None:
        logger.info(f"Fetching just {issue}")
        return [get_issue(jclient, issue)]

    logger.info(f"Fetching {'recent' if only_recent else 'all'} issues")
    return get_all_triage_tickets(jclient, only_recent=only_recent)

def process_issues(jclient, issues, update, update_signature):
    logger.info(f"Found {len(issues)} tickets, processing...")
    for issue in tqdm.tqdm(issues):
        url = get_logs_url_from_issue(issue)
        if not url:
            logger.warning("Could not get URL from issue %s. Skipping", issue.key)
        else:
            add_signatures(jclient, url, issue.key, should_update=update,
                           signatures=update_signature)

def get_credentials(user_password, use_netrc):
    if user_password is None:
        username, password = get_credentials_from_netrc(urlparse(JIRA_SERVER).hostname, use_netrc)
    else:
        try:
            [username, password] = user_password.split(":", 1)
        except Exception:
            logger.error("Failed to parse user:password")
            raise

    return username, password

def main(args):
    username, password = get_credentials(args.user_password, args.netrc)

    jclient = get_jira_client(username, password)

    issues = get_issues(jclient, args.issue, args.recent_issues)

    if args.dry_run_temp:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as dry_run_file:
            logger.info(f"Dry run output will be written to {dry_run_file.name}")
            logger.info(f"Run `tail -f {dry_run_file.name}` to view dry run output in real time")
            Signature.dry_run_file = dry_run_file
            process_issues(jclient, issues, args.update, args.update_signature)
            logger.info(f"Dry run output written to {dry_run_file.name}")
        return

    if args.dry_run:
        Signature.dry_run_file = sys.stdout

    process_issues(jclient, issues, args.update, args.update_signature)


def format_time(time_str):
    return  dateutil.parser.isoparse(time_str).strftime("%Y-%m-%d %H:%M:%S")


def add_signatures(jclient, url, issue_key, should_update=False, signatures=None):
    name_to_signature = {s.__name__: s for s in SIGNATURES}
    signatures_to_add = SIGNATURES
    if signatures:
        should_update = True
        signatures_to_add = [v for k, v in name_to_signature.items() if k in signatures]

    for sig in signatures_to_add:
        s = sig(jclient)
        s.update_ticket(url, issue_key, should_update=should_update)


def parse_args():
    description = f"""
This utility updates existing triage tickets with signatures.
Signatures perform automatic analysis of ticket log files to extract
information that is crucial to help kickstart a ticket triage. Each
signature typically outputs its information in the form of a ticket
comment.


Before running this please make sure you have -

1. A jira username and password -
    Username: You can find it in {JIRA_SERVER}/secure/ViewProfile.jspa
    Password: Simply your sso.redhat.com password

2. A RedHat VPN connection - this is required to access ticket log files

3. A Python virtualenv with all the requirements.txt installed
   (you can also install them without a virtualenv if you wish).

You can run this script without affecting the tickets by using the --dry-run flag
""".strip()

    signature_names = [s.__name__ for s in SIGNATURES]
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)

    login_group = parser.add_argument_group(title="Login options")
    login_args = login_group.add_mutually_exclusive_group()
    login_args.add_argument("--netrc", default="~/.netrc", required=False, help="netrc file")
    login_args.add_argument("-up", "--user-password", required=False, help="Username and password in the format of user:pass")

    selectors_group = parser.add_argument_group(title="Issues selection")
    selectors = selectors_group.add_mutually_exclusive_group(required=True)
    selectors.add_argument("-r", "--recent-issues", action='store_true', help="Handle recent (30 days) Triaging Tickets")
    selectors.add_argument("-a", "--all-issues", action='store_true', help="Handle all Triaging Tickets")
    selectors.add_argument("-i", "--issue", required=False, help="Triage issue key")

    parser.add_argument("-u", "--update", action="store_true", help="Update ticket even if signature already exist")
    parser.add_argument("-v", "--verbose", action="store_true", help="Output verbose logging")

    dry_run_group = parser.add_argument_group(title="Dry run options")
    dry_run_args = dry_run_group.add_mutually_exclusive_group()
    dry_run_msg = "Dry run. Don't update tickets. Write output to"
    dry_run_args.add_argument("-d", "--dry-run", action="store_true", help=f"{dry_run_msg} stdout")
    dry_run_args.add_argument("-t", "--dry-run-temp", action="store_true", help=f"{dry_run_msg} a temp file")

    parser.add_argument("-us", "--update-signature", action='append', choices=signature_names,
                        help="Update tickets with only the signatures specified")

    args = parser.parse_args()

    logging.basicConfig(level=logging.WARN, format='%(levelname)-10s %(message)s')
    logging.getLogger("__main__").setLevel(logging.INFO)

    if args.verbose:
        logging.getLogger("__main__").setLevel(logging.DEBUG)

    return args


if __name__ == "__main__":
    main(parse_args())
