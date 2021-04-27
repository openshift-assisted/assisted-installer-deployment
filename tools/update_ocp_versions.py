import os
import re
import json
import yaml
import time
import copy
import logging
import argparse
import tempfile
import functools
import subprocess

from bs4 import BeautifulSoup
from distutils.version import LooseVersion

import jira
import github
import gitlab
import jenkins
import requests
import ruamel.yaml

logging.basicConfig(level=logging.INFO, format='%(levelname)-10s %(filename)s:%(lineno)d %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)

# Users / branch names / messages
BRANCH_NAME = "{prefix}_update_assisted_service_versions"
DEFAULT_ASSIGN = "oscohen"
DEFAULT_WATCHERS = ["ronniela", "romfreiman", "lgamliel", "oscohen"]
PR_MENTION = ["romfreiman", "ronniel1", "gamli75", "oshercc"]
PR_MESSAGE = "{task}, Bump OCP versions"

OCP_RELEASES = "https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/"
RHCOS_RELEASES = "https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/{minor}"

# RCHOS version
RCHOS_LIVE_ISO_URL = "https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/{minor}/{version}/rhcos-{version}-x86_64-live.x86_64.iso"

RCHOS_VERSION_FROM_ISO_REGEX = re.compile("coreos.liveiso=rhcos-(.*) ")
DOWNLOAD_LIVE_ISO_CMD = "curl {live_iso_url} -o {out_file}"

DEFAULT_VERSIONS_FILES = "default_ocp_versions.json"

# app-interface PR related constants
APP_INTERFACE_CLONE_DIR = "app-interface"
APP_INTERFACE_GITLAB_PROJECT = "app-interface"
APP_INTERFACE_GITLAB_REPO = f"service/{APP_INTERFACE_GITLAB_PROJECT}"
APP_INTERFACE_GITLAB = "gitlab.cee.redhat.com"
APP_INTERFACE_GITLAB_API = f'https://{APP_INTERFACE_GITLAB}'
APP_INTERFACE_SAAS_YAML = f"{APP_INTERFACE_CLONE_DIR}/data/services/assisted-installer/cicd/saas.yaml"
EXCLUDED_ENVIRONMENTS = {"staging", "production"}  # Don't update OPENSHIFT_VERSIONS in these envs

# assisted-service PR related constants
ASSISTED_SERVICE_CLONE_DIR = "assisted-service"
ASSISTED_SERVICE_GITHUB_REPO_ORGANIZATION = "openshift"
ASSISTED_SERVICE_GITHUB_REPO = f"{ASSISTED_SERVICE_GITHUB_REPO_ORGANIZATION}/assisted-service"
ASSISTED_SERVICE_GITHUB_FORK_REPO = "{github_user}/assisted-service"
ASSISTED_SERVICE_FORKED_URL = f"https://github.com/{ASSISTED_SERVICE_GITHUB_FORK_REPO}"
ASSISTED_SERVICE_CLONE_URL = f"https://github.com/{ASSISTED_SERVICE_GITHUB_FORK_REPO}.git"
ASSISTED_SERVICE_UPSTREAM_URL = f"https://github.com/{ASSISTED_SERVICE_GITHUB_REPO}.git"
ASSISTED_SERVICE_MASTER_DEFAULT_OCP_VERSIONS_JSON_URL = \
    f"https://raw.githubusercontent.com/{ASSISTED_SERVICE_GITHUB_REPO}/master/default_ocp_versions.json"
ASSISTED_SERVICE_OPENSHIFT_TEMPLATE_YAML = f"{ASSISTED_SERVICE_CLONE_DIR}/openshift/template.yaml"

OCP_REPLACE_CONTEXT = ['"{version}"', "ocp-release:{version}"]

RHCOS_LIVE_ISO_REGEX = re.compile("https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/.*/(.*)/.*-x86_64-live.x86_64.iso")

# GitLab SSL
REDHAT_CERT_URL = 'https://password.corp.redhat.com/RH-IT-Root-CA.crt'
REDHAT_CERT_LOCATION = "/tmp/redhat.cert"
GIT_SSH_COMMAND_WITH_KEY = "ssh -o StrictHostKeyChecking=accept-new -i '{key}'"

# Jenkins
JENKINS_URL = "http://assisted-jenkins.usersys.redhat.com"
TEST_INFRA_JOB = "assisted-test-infra/master"

# Jira
JIRA_SERVER = "https://issues.redhat.com"
JIRA_BROWSE_TICKET = f"{JIRA_SERVER}/browse/{{ticket_id}}"

script_dir = os.path.dirname(os.path.realpath(__file__))
CUSTOM_OPENSHIFT_IMAGES = os.path.join(script_dir, "custom_openshift_images.json")

TICKET_DESCRIPTION = "Default versions need to be updated"

def parse_args():
    parser = argparse.ArgumentParser()
    # parser.add_argument("-jup",  "--jira-user-password",    help="JIRA Username and password in the format of user:pass", required=True)
    parser.add_argument("-gup",  "--github-user-password",  help="GITHUB Username and password in the format of user:pass", required=True)
    parser.add_argument("--dry-run", action='store_true',   help="test run")
    return parser.parse_args()

def cmd(command, env=None, **kwargs):
    logging.info(f"Running command {command} with env {env} kwargs {kwargs}")

    if env is None:
        env = os.environ
    else:
        env = {**os.environ, **env}

    popen = subprocess.Popen(command, env=env, **kwargs)
    stdout, stderr = popen.communicate()

    if popen.returncode != 0:
        raise subprocess.CalledProcessError(returncode=popen.returncode, cmd=command, output=stdout, stderr=stderr)

    return stdout, stderr

def cmd_with_git_ssh_key(key_file):
    return functools.partial(cmd, env={
        "GIT_SSH_COMMAND": GIT_SSH_COMMAND_WITH_KEY.format(key=key_file)
    })

def get_rchos_version_from_iso(rhcos_latest_release, iso_url):
    live_iso_url = iso_url.format(version=rhcos_latest_release)
    with tempfile.NamedTemporaryFile() as tmp_live_iso_file:
        subprocess.check_output(
            DOWNLOAD_LIVE_ISO_CMD.format(live_iso_url=live_iso_url, out_file=tmp_live_iso_file.name), shell=True)
        try:
            os.remove("/tmp/zipl.prm")
        except FileNotFoundError:
            pass

        subprocess.check_output(f"7z x {tmp_live_iso_file.name} zipl.prm", shell=True, cwd="/tmp")
        with open("/tmp/zipl.prm", 'r') as f:
            zipl_info = f.read()
        result = RCHOS_VERSION_FROM_ISO_REGEX.search(zipl_info)
        rchos_version_from_iso = result.group(1)
        logger.info(f"Found rchos_version_from_iso: {rchos_version_from_iso}")
        import ipdb
        ipdb.set_trace()
    return rchos_version_from_iso

def get_default_release_json():
    res = requests.get(ASSISTED_SERVICE_MASTER_DEFAULT_OCP_VERSIONS_JSON_URL)
    if not res.ok:
        raise RuntimeError(
            f"GET {ASSISTED_SERVICE_MASTER_DEFAULT_OCP_VERSIONS_JSON_URL} failed status {res.status_code}")
    return json.loads(res.text)


def get_login(user_password):
    try:
        username, password = user_password.split(":", 1)
    except ValueError:
        logger.error("Failed to parse user:password")
        raise

    return username, password

def clone_assisted_service(github_user):
    cmd(["rm", "-rf", ASSISTED_SERVICE_CLONE_DIR])

    cmd(["git", "clone", ASSISTED_SERVICE_CLONE_URL.format(github_user=github_user), ASSISTED_SERVICE_CLONE_DIR])

    def git_cmd(*args: str):
        return cmd(("git", "-C", ASSISTED_SERVICE_CLONE_DIR) + args)

    git_cmd("remote", "add", "upstream", ASSISTED_SERVICE_UPSTREAM_URL)
    git_cmd("fetch", "upstream")
    git_cmd("reset", "upstream/master", "--hard")

def verify_latest_config():
    try:
        cmd(["make", "generate-ocp-version"], cwd=ASSISTED_SERVICE_CLONE_DIR)
    except subprocess.CalledProcessError as e:
        if e.returncode == 2:
            # We run the command just for its side-effects, we don't care if it fails
            return
        raise

def get_latest_release_from_minor(minor_release: str, all_releases: list):
    def is_pre_release(release):
        return "-fc" in release or "-rc" in release

    all_relevant_releases = [r for r in all_releases if r.startswith(minor_release) and not is_pre_release(r)]

    if not all_relevant_releases:
        all_relevant_releases = [r for r in all_releases if r.startswith(minor_release)]

    if not all_relevant_releases:
        return None
    return sorted(all_relevant_releases, key=LooseVersion)[-1]

def get_all_releases(path: str):
    res = requests.get(path)
    if not res.ok:
        raise Exception("can\'t get releses")

    page = res.text
    soup = BeautifulSoup(page, 'html.parser')
    return [node.get('href').replace("/", "") for node in soup.find_all('a')]

def get_rchos_release_from_default_version_json(ocp_version_minor, release_json):
    rchos_release_image = release_json[ocp_version_minor]['rhcos_image']
    result = RHCOS_LIVE_ISO_REGEX.search(rchos_release_image)
    rhcos_default_version = result.group(1)
    return rhcos_default_version

def main(args):
    dry_run = args.dry_run
    if dry_run:
        logger.info("Running dry-run")

    default_version_json = get_default_release_json()
    updated_version_json = copy.deepcopy(default_version_json)
    all_ocp_releases = get_all_releases(OCP_RELEASES)

    updates_made = set()

    for release in default_version_json:
        latest_ocp_release = get_latest_release_from_minor(release, all_ocp_releases)
        if not latest_ocp_release:
            continue
        current_default_ocp_release = default_version_json.get(release).get("display_name")

        if current_default_ocp_release != latest_ocp_release or dry_run:
            updates_made.add(release)
            logger.info(f"New latest ocp release available for {release}, {current_default_ocp_release} -> {latest_ocp_release}")
            updated_version_json[release]["display_name"] = latest_ocp_release
            updated_version_json[release]["release_image"] = updated_version_json[release]["release_image"].replace(current_default_ocp_release, latest_ocp_release)

        rhcos_default_release = get_rchos_release_from_default_version_json(release, default_version_json)
        rhcos_latest_of_releases = get_all_releases(RHCOS_RELEASES.format(minor=release))
        rhcos_latest_release = get_latest_release_from_minor(release, rhcos_latest_of_releases)

        if rhcos_default_release != rhcos_latest_release or dry_run:
            updates_made.add(release)
            logger.info(f"New latest rhcos release available, {rhcos_default_release} -> {rhcos_latest_release}")
            updated_version_json[release]["rhcos_image"] = updated_version_json[release]["rhcos_image"].replace(rhcos_default_release, rhcos_latest_release)

            if dry_run:
                rchos_version_from_iso = "8888888"
            else:
                rchos_version_from_iso = get_rchos_version_from_iso(rhcos_latest_release, RCHOS_LIVE_ISO_URL.format(minor=release, version=rhcos_latest_release))
            updated_version_json[release]["rhcos_version"] = rchos_version_from_iso

    if updates_made:
        logger.info(f"changes were made on the fallowing versions: {updates_made}")

        clone_assisted_service(ASSISTED_SERVICE_GITHUB_REPO_ORGANIZATION if dry_run else get_login(args.github_user_password)[0])

        with open(os.path.join(ASSISTED_SERVICE_CLONE_DIR, DEFAULT_VERSIONS_FILES), 'w') as outfile:
            json.dump(updated_version_json, outfile, indent=8)
        verify_latest_config()

        if dry_run:
            return

        with open(ASSISTED_SERVICE_OPENSHIFT_TEMPLATE_YAML) as f:
            openshift_versions_json = next(
                param["value"] for param in yaml.safe_load(f)["parameters"] if param["name"] == "OPENSHIFT_VERSIONS"
            )

        import ipdb
        ipdb.set_trace()

if __name__ == "__main__":
    main(parse_args())
