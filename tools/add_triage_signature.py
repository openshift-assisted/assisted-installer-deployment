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
from textwrap import dedent
from typing import List
from urllib.parse import urlparse

import colorlog
import dateutil.parser
import jira
import nestedarchive
import requests
import tqdm
from fuzzywuzzy import fuzz
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
* [DM Elastic|http://assisted-elastic.usersys.redhat.com:5601/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-2w,to:now))&_a=(columns:!(_source),filters:!(),index:bd9dadc0-7bfa-11eb-95b8-d13a1970ae4d,interval:auto,query:(language:lucene,query:'cluster.id:%20%22{cluster_id}%22'),sort:!())]
* [DM Elastic Dashboard|http://assisted-elastic.usersys.redhat.com:5601/app/dashboards#/view/500e1d40-58d6-11eb-8ff7-115676c7222d?_g=(filters:!(),query:(language:kuery,query:'cluster_id:%20%22{cluster_id}%22'),refreshInterval:(pause:!t,value:0),time:(from:now-2w,to:now))&_a=(description:'',filters:!(),fullScreenMode:!f,options:(hidePanelTitles:!f,useMargins:!t),query:(language:kuery,query:'cluster_id:%20%22{cluster_id}%22%20'),timeRestore:!f,title:'cluster%20overview',viewMode:view)]
"""


def config_logger(verbose):
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(levelname)-10s %(message)s'))

    logger = logging.getLogger("__main__")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    if verbose:
        logger.setLevel(logging.DEBUG)


def format_description(failure_data):
    return JIRA_DESCRIPTION.format(**failure_data)


def days_ago(datestr):
    try:
        return (datetime.now() - dateutil.parser.isoparse(datestr)).days
    except Exception:
        logger.debug("Cannot parse date: %s", datestr)
        return 9999


class FailedToGetMetadataException(Exception):
    pass


@functools.lru_cache(maxsize=1000)
def get_metadata_json(cluster_url):
    try:
        res = requests.get("{}/metdata.json".format(cluster_url))
        res.raise_for_status()
        return res.json()
    except Exception as e:
        raise FailedToGetMetadataException from e


@functools.lru_cache(maxsize=1000)
def get_events_json(cluster_url, cluster_id):
    res = requests.get(f"{cluster_url}/cluster_{cluster_id}_events.json")
    res.raise_for_status()
    return res.json()


@functools.lru_cache(maxsize=100)
def get_remote_archive(tar_url):
    return nestedarchive.RemoteNestedArchive(tar_url, init_download=True)


class FailedToGetLogsTarException(Exception):
    pass


def get_triage_logs_tar(triage_url, cluster_id):
    try:
        tar_url = f"{triage_url}/cluster_{cluster_id}_logs.tar"
        return get_remote_archive(tar_url)
    except requests.exceptions.HTTPError as e:
        raise FailedToGetLogsTarException from e


def get_host_log_file(triage_logs_tar, host_id, filename):
    # The file is already uniquely determined by the host_id, we can omit the hostname
    hostname = "*"

    return triage_logs_tar.get(f"{hostname}.tar.gz/logs_host_{host_id}/{filename}")


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
        except FailedToGetMetadataException as e:
            browse_url = get_ticket_browse_url(issue_key)
            logger.error(
                f"Error getting metadata for {browse_url} at {url}: {e.__cause__}, it may have been deleted"
            )
        except FailedToGetLogsTarException as e:
            if e.__cause__.response.status_code == 404:
                logger.warning(
                    f"{get_ticket_browse_url(issue_key)} doesn't have a log tar, skipping {type(self).__name__}")
                return
            raise
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
            return hostname

        inventory = json.loads(host['inventory'])
        return inventory['hostname']


class HostsStatusSignature(Signature):
    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Install status:",
                         old_comment_string="h1. Host details:")

    def _update_ticket(self, url, issue_key, should_update=False):

        url = self._logs_url_to_api(url)
        md = get_metadata_json(url)

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
        md = get_metadata_json(url)

        cluster = md['cluster']

        description = self.build_description(url, cluster)

        logger.info("Updating description of %s", issue_key)
        self._update_description(issue_key, description)


class HostsExtraDetailSignature(Signature):
    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Host extra details:")

    def _update_ticket(self, url, issue_key, should_update=False):

        url = self._logs_url_to_api(url)
        md = get_metadata_json(url)

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
        super().__init__(jira_client, comment_identifying_string="h1. Host slow installation disks:")

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
        md = get_metadata_json(url)

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
            if len(host_fio_events) != 0:
                _events, host_fio_events_durations = zip(*fio_events_by_host[host["id"]])
                fio_message = (
                    "{color:red}Installation disk is too slow, fio durations: " +
                    ", ".join(f"{duration}ms" for duration in host_fio_events_durations) +
                    "{color}"
                )

                hosts.append(OrderedDict(
                    id=host['id'],
                    hostname=self._get_hostname(host),
                    fio=fio_message,
                    installation_disk=host.get('installation_disk_path', ""),
                ))

        if len(hosts) > 0:
            report = self._generate_table_for_report(hosts)
            self._update_triaging_ticket(issue_key, report, should_update=should_update)


class StorageDetailSignature(Signature):
    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Host storage details:")

    def _update_ticket(self, url, issue_key, should_update=False):

        url = self._logs_url_to_api(url)
        md = get_metadata_json(url)

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
        md = get_metadata_json(url)

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
        md = get_metadata_json(url)

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


class MediaDisconnectionSignature(Signature):
    '''
    The signature downloads cluster logs, and go over all the hosts logs files searching for a 'dmesg' file
    Then, it looks for i/o errors (disks, media) patterns and groups them per host
    Eventually, the signature will include common i/o errors and the number of times they appeared
    '''

    ERRORS_PATTERNS = [
        'I/O error',
        'disconnect',
    ]

    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Virtual media disconnection")

    def _update_ticket(self, url, issue_key, should_update=False):
        url = self._logs_url_to_api(url)

        md = get_metadata_json(url)

        cluster = md['cluster']
        cluster_id = cluster['id']

        hosts = []

        triage_logs_tar = get_triage_logs_tar(triage_url=url, cluster_id=cluster_id)

        for host in cluster["hosts"]:
            host_id = host["id"]

            try:
                dmesg_file = get_host_log_file(triage_logs_tar, host_id, "dmesg.logs")
            except FileNotFoundError:
                continue

            logs = search_patterns_in_string(dmesg_file, self.ERRORS_PATTERNS)
            logs = [(group[0], len(group)) for group in group_similar_strings(logs, ratio=80)]

            for log in logs:
                hosts.append(OrderedDict(
                    id=host_id,
                    hostname=self._get_hostname(host),
                    log=f"{{color:red}}{log[0]}{{color}}",
                    similar_logs=log[1]))

        if len(hosts) != 0:
            report = dedent("""
            Media disconnection events were found.
            It usually indicates that reading data from media disk cannot be made due to a network problem on PXE setup,
            bad contact with the media disk, or actual hardware disconnection.
            """)
            report += self._generate_table_for_report(hosts)
            self._update_triaging_ticket(issue_key, report, should_update=should_update)


class ConsoleTimeoutSignature(Signature):
    """
    This signature looks for 'waiting for console' error in cluster's status_info.
    If OpenShift version is 4.7 and hosts are VMware vms, outputs a warning.
    Due to: https://bugzilla.redhat.com/1926345
    """

    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Console timeout - VMware hosts / OCP 4.7")

    def _update_ticket(self, url, issue_key, should_update=False):
        url = self._logs_url_to_api(url)

        md = get_metadata_json(url)

        def isVMware(host):
            inventory = json.loads(host['inventory'])
            product_name = inventory['system_vendor'].get('product_name')
            return "VMware" in product_name

        cluster = md['cluster']
        status_info = cluster['status_info']
        openshift_version = cluster['openshift_version']
        report = ""
        if ("waiting for console" in status_info and
                "4.7" in openshift_version and
                any(isVMware(host) for host in cluster['hosts'])):
            # ISO conversion according to https://stackoverflow.com/questions/127803/how-do-i-parse-an-iso-8601-formatted-date#comment94022430_49784038
            if datetime.fromisoformat(cluster['install_started_at'].replace('Z', '')) > datetime(2021, 4, 8):
                report = "\n".join([
                    "h2. Waiting for console timeout -probably due to VMware hosts on OCP 4.7 ([bugzilla|https://bugzilla.redhat.com/1935539])-",
                    "As of April 8th 2021, 4.7.5 was pushed to production. That version contains the supposed fix "
                    "for this bug. This means that the cause for the timeout in this ticket might not "
                    "be due to this known bug - it might be caused by something else. Please investigate."
                ])
            else:
                report = "\n".join([
                    "h2. Waiting for console timeout probably due to VMware hosts on OCP 4.7",
                    "You can mark it as caused by issue [MGMT-4454|https://issues.redhat.com/browse/MGMT-4454]",
                    "Solution will be provided via [bugzilla|https://bugzilla.redhat.com/1935539] ticket",
                ])

        if report != "":
            self._update_triaging_ticket(issue_key, report, should_update=should_update)


class AgentStepFailureSignature(Signature):
    """
    This signature creates a report of all agent step failures that were encountered in the logs
    """

    # This has to be maintained to be the same format as https://github.com/openshift/assisted-installer-agent/blob/aebd94105b4ed6442f21a7a26ab4e40eafd936aa/src/commands/step_processor.go#L81
    # Remember to maintain backwards compatibility if that format ever changes - create
    # PATTERN_NEW and try to match both.
    LOG_PATTERN = re.compile(
        r'time="(?P<time>.+)" level=(?P<severity>[a-z]+) msg="(?P<message>Step execution failed.*)" file=.+'
    )

    MSG_PATTERN = re.compile(
        r'Step execution failed \(exit code (?P<exit_code>\d+)\): <(?P<step_id>[a-z\-0-9]+)>, '
        r'command: <(?P<command>.+?)>, args: <\[(?P<args>.+?)\]>\. '
        r'Output:\\nstdout:\\n(?P<stdout>.*)\\n\\nstderr:\\n(?P<stderr>.*)\\n'
    )

    MAX_FAILURES_PER_HOST = 10
    TRUNCATE_OUTPUT_LENGTH = 1500

    def __init__(self, jira_client):
        super().__init__(jira_client, comment_identifying_string="h1. Agent step failures")

    @classmethod
    def _prepare_output(cls, output):
        if len(output) == 0:
            return output

        if len(output) > cls.TRUNCATE_OUTPUT_LENGTH:
            half = cls.TRUNCATE_OUTPUT_LENGTH // 2
            output = f"{output[:half]} ... **OUTPUT HAS BEEN TRUNCATED** ... {output[-half:]}"

        return "{code:none}%s{code}" % (output.replace("|", "¦"))

    def _update_ticket(self, url, issue_key, should_update=False):
        url = self._logs_url_to_api(url)

        md = get_metadata_json(url)

        cluster = md['cluster']
        cluster_id = cluster['id']

        triage_logs_tar = get_triage_logs_tar(triage_url=url, cluster_id=cluster_id)

        report = ''
        for host in cluster["hosts"]:
            host_id = host["id"]

            try:
                agent_logs = get_host_log_file(triage_logs_tar, host_id, "agent.logs")
            except FileNotFoundError:
                continue

            failures = []
            for _failure_idx, step_failure_log_match in zip(range(self.MAX_FAILURES_PER_HOST),
                                                            self.LOG_PATTERN.finditer(agent_logs)):
                step_failure_log = step_failure_log_match.groupdict()
                step_failure_message_match = self.MSG_PATTERN.match(step_failure_log["message"])

                if step_failure_message_match is None:
                    logger.warning("Step failure signature skipped failure because failure message has unexpected format")
                    continue

                step_failure_message = step_failure_message_match.groupdict()

                failures.append(OrderedDict(
                    time=step_failure_log['time'],
                    exit_code=step_failure_message['exit_code'],
                    step_id=step_failure_message['step_id'],
                    stdout=self._prepare_output(step_failure_message['stdout']),
                    stderr=self._prepare_output(step_failure_message['stderr']),
                ))

            if len(failures) != 0:
                report += dedent(f"""
                h2. Agent step failures for {host_id} ({self._get_hostname(host)})
                {self._generate_table_for_report(failures)}""")

        if len(report) != 0:
            self._update_triaging_ticket(issue_key, report, should_update=should_update)


############################
# Common functionality
############################
DEFAULT_NETRC_FILE = "~/.netrc"
JIRA_SERVER = "https://issues.redhat.com"
SIGNATURES = [FailureDescription, ComponentsVersionSignature, HostsStatusSignature, HostsExtraDetailSignature,
              StorageDetailSignature, InstallationDiskFIOSignature, LibvirtRebootFlagSignature,
              MediaDisconnectionSignature, ConsoleTimeoutSignature, AgentStepFailureSignature]


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


def search_patterns_in_string(string, patterns):
    combined_regex = re.compile(f'({"|".join(r".*%s.*" % pattern for pattern in patterns)})')
    return combined_regex.findall(string)


def group_similar_strings(ls, ratio):
    '''
    Uses Levenshtein Distance Algorithm to calculate the differences between strings
    Then, groups similar strings that matches according to the ratio.
    The higher the ratio -> The more identical strings

    Example:
    input: ['rakesh', 'zakesh', 'goldman LLC', 'oldman LLC', 'bakesh']
    output groups: [['rakesh', 'zakesh', 'bakesh'], ['goldman LLC', 'oldman LLC']]
    '''

    groups = []
    for item in ls:
        for group in groups:
            if all(fuzz.ratio(item, w) > ratio for w in group):
                group.append(item)
                break
        else:
            groups.append([item, ])

    return groups


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
    query = 'project = MGMT AND component = "Assisted-installer Triage" AND labels in (AI_CLOUD_TRIAGE) {}'.format(recent_filter)

    return jclient.search_issues(query, maxResults=None)


def get_issues(jclient, issue, only_recent):
    if issue is not None:
        logger.info(f"Fetching just {issue}")
        return [get_issue(jclient, issue)]

    logger.info(f"Fetching {'recent' if only_recent else 'all'} issues")
    return get_all_triage_tickets(jclient, only_recent=only_recent)


def get_ticket_browse_url(issue_key):
    return f"{JIRA_SERVER}/browse/{issue_key}"


def process_issues(jclient, issues, update, update_signature):
    logger.info(f"Found {len(issues)} tickets, processing...")

    should_progress_bar = sys.stderr.isatty()
    for issue in tqdm.tqdm(issues, disable=not should_progress_bar, file=sys.stderr):
        logger.debug(f"Issue {issue}")
        url = get_logs_url_from_issue(issue)

        if url is None:
            logger.warning(f"Could not get URL from issue {get_ticket_browse_url(issue.key)}. Skipping")
            continue

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
    return dateutil.parser.isoparse(time_str).strftime("%Y-%m-%d %H:%M:%S")


def add_signatures(jclient, url, issue_key, should_update=False, signatures=None):
    name_to_signature = {s.__name__: s for s in SIGNATURES}
    signatures_to_add = SIGNATURES
    if signatures:
        should_update = True
        signatures_to_add = [v for k, v in name_to_signature.items() if k in signatures]

    for sig in signatures_to_add:
        logger.debug(f"Running signature {sig.__name__}")
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

    config_logger(args.verbose)

    return args


if __name__ == "__main__":
    main(parse_args())
