import os
import re
import json
import yaml
import time
import logging
import argparse
import tempfile
import functools
import subprocess

from packaging import version

import jira
import github
import gitlab
import jenkins
import requests
import ruamel.yaml

####################################################
# Updates OCP version by:
#  * check if new version is available
#  * open OCP version JIRA ticket
#  * create a update branch
#  * open a GitHub PR for the changes
#  * test test-infra
#  * open an app-sre GitLab PR for the changes
#           (integration environment only, for now)
#####################################################

logging.basicConfig(level=logging.INFO, format='%(levelname)-10s %(filename)s:%(lineno)d %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)

# Users / branch names / messages
BRANCH_NAME = "{prefix}_update_ocp_version_to_{version}"
DEFAULT_ASSIGN = "lgamliel"
DEFAULT_WATCHERS = ["ronniela", "romfreiman", "lgamliel", "oscohen"]
PR_MENTION = ["romfreiman", "ronniel1", "gamli75", "oshercc"]
PR_MESSAGE = "{task}, Bump OCP version from {current_version} to {target_version} (auto created)"
# The script scans the following message to look for previous tickets, changing this may break things!
OCP_TICKET_DESCRIPTION = "OCP version update required, Latest version {latest_version}, Current version {current_version}"
RCHOS_TICKET_DESCRIPTION = "RCHOS version update required, Latest version {latest_version}, Current version {current_version}"

# Minor version detection
OCP_LATEST_RELEASE_URL = "https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/latest/release.txt"
OCP_FUTURE_RELEASE_URL = "https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp-dev-preview/{future_version}/release.txt"

# RCHOS version
RCHOS_LATEST_RELEASE_URL = "https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/{version}/latest/sha256sum.txt"
RCHOS_FUTURE_LATEST_RELEASE_URL = "https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/pre-release/latest/sha256sum.txt"
RCHOS_LATEST_LIVE_ISO_URL = "https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/latest/{version}/rhcos-{version}-x86_64-live.x86_64.iso"

RCHOS_VERSION_FROM_ISO_REGEX = re.compile("coreos.liveiso=rhcos-(.*) ")
RCHOS_VERSION_FROM_DEFAULT_REGEX = re.compile("coreos.liveiso=rhcos-(.*) ")
DOWNLOAD_LIVE_ISO_CMD = "curl {live_iso_url} -o {out_file}"

# app-interface PR related constants
APP_INTERFACE_CLONE_DIR = "app-interface"
APP_INTERFACE_GITLAB_PROJECT = "app-interface"
APP_INTERFACE_GITLAB_REPO = f"service/{APP_INTERFACE_GITLAB_PROJECT}"
APP_INTERFACE_GITLAB = "gitlab.cee.redhat.com"
APP_INTERFACE_GITLAB_API = f'https://{APP_INTERFACE_GITLAB}'
APP_INTERFACE_SAAS_YAML = f"{APP_INTERFACE_CLONE_DIR}/data/services/assisted-installer/cicd/saas.yaml"
EXCLUDED_ENVIRONMENTS = {"integration-v3", "staging", "production"}  # Don't update OPENSHIFT_VERSIONS in these envs

# assisted-service PR related constants
ASSISTED_SERVICE_CLONE_DIR = "assisted-service"
ASSISTED_SERVICE_GITHUB_REPO = "openshift/assisted-service"
ASSISTED_SERVICE_GITHUB_FORK_REPO = "{github_user}/assisted-service"
ASSISTED_SERVICE_CLONE_URL = f"https://{{user_login}}@github.com/{ASSISTED_SERVICE_GITHUB_FORK_REPO}.git"
ASSISTED_SERVICE_UPSTREAM_URL = f"https://github.com/{ASSISTED_SERVICE_GITHUB_REPO}.git"
ASSISTED_SERVICE_MASTER_DEFAULT_OCP_VERSIONS_JSON_URL = \
    f"https://raw.githubusercontent.com/{ASSISTED_SERVICE_GITHUB_REPO}/master/default_ocp_versions.json"
UPDATED_FILES = ["default_ocp_versions.json", "config/onprem-iso-fcc.yaml", "onprem-environment"]

OCP_REPLACE_CONTEXT = ['"{version}"', "ocp-release:{version}"]
RCHOS_RELEASE_REPLACE_CONTEXT = ["{version}/rhcos"]
RCHOS_VERSION_REPLACE_CONTEXT = ['"rhcos_version": "{version}",']

OCP_VERSION_REGEX = re.compile(r"quay\.io/openshift-release-dev/ocp-release:(.*)-x86_64")
OPENSHIFT_TEMPLATE_YAML = f"{ASSISTED_SERVICE_CLONE_DIR}/openshift/template.yaml"

RHCOS_LIVE_ISO_REGEX = re.compile("rhcos-(.*)-x86_64-live.x86_64.iso")

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

# Dry run params
DRY_RUN_VERSION = "1.2.3"
DRY_RUN_TASK = "TEAST-TEST"
OCP_DR_TASK = "TEST-OCP-TASK"
OCP_DR_FUTURE_TASK = "TEST-OCP-FUTURE-TASK"
RHCOS_DR_TASK = "TEST-RHCOS-TASK"
RHCOS_DR_FUTURE_TASK = "TEST-FUTURE-RHCOS-TASK"
DRY_RUN_BRANCHES = ["TEST-OCP-TASK_update_ocp_version_to_1.2.3",
                    "TEST-OCP-FUTURE-TASK_update_ocp_version_to_latest",
                    "TEST-RHCOS-TASK_update_ocp_version_to_1.2.3",
                    "TEST-FUTURE-RHCOS-TASK_update_ocp_version_to_1.2.3",
                    ]

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-jup",  "--jira-user-password",    help="JIRA Username and password in the format of user:pass", required=True)
    parser.add_argument("-gup",  "--github-user-password",  help="GITHUB Username and password in the format of user:pass", required=True)
    parser.add_argument("-gkf",  "--gitlab-key-file",       help="GITLAB key file", required=True)
    parser.add_argument("-gt",   "--gitlab-token",          help="GITLAB user token", required=True)
    parser.add_argument("-jkup", "--jenkins-user-password", help="JENKINS Username and password in the format of user:pass", required=True)
    parser.add_argument("--dry-run", action='store_true',   help="test run")
    return parser.parse_args()

def ocp_version_update(args):
    logger.info("Searching and updating OCP version")
    latest_ocp_version = version.parse(get_latest_ocp_version())

    ocp_version_major = "{major}.{minor}".format(major=latest_ocp_version.major, minor=latest_ocp_version.minor, micro=latest_ocp_version.micro)
    current_assisted_service_ocp_version = get_default_ocp_version(ocp_version_major)

    if args.dry_run:
        latest_ocp_version = DRY_RUN_VERSION

    if latest_ocp_version == current_assisted_service_ocp_version:
        logging.info(f"OCP version {latest_ocp_version} is up to date")
        return

    logging.info(
        f"""OCP version mismatch,
    latest version: {latest_ocp_version}
    current version {current_assisted_service_ocp_version}""")

    jira_client, task = create_task(args, OCP_TICKET_DESCRIPTION, current_assisted_service_ocp_version, latest_ocp_version)

    if args.dry_run:
        task = OCP_DR_TASK

    if task is None:
        logging.info("Not creating PR because ticket already exists")
        return

    branch, openshift_versions_json = update_ai_repo_to_new_version(args,
                                                                    current_assisted_service_ocp_version,
                                                                    latest_ocp_version,
                                                                    OCP_REPLACE_CONTEXT,
                                                                    task)

    logging.info(f"Using versions JSON {openshift_versions_json}")

    if args.dry_run:
        return

    github_pr = open_pr(args, current_assisted_service_ocp_version, latest_ocp_version, task)
    test_success = test_changes(args, branch, github_pr)

    if test_success:
        fork = create_app_interface_fork(args)
        app_interface_branch = update_ai_app_sre_repo_to_new_ocp_version(fork, args, latest_ocp_version,
                                                                         openshift_versions_json, task)
        gitlab_pr = open_app_interface_pr(fork, app_interface_branch, current_assisted_service_ocp_version,
                                   latest_ocp_version,
                                   task)

        jira_client.add_comment(task, f"Created a PR in app-interface GitLab {gitlab_pr.web_url}")
        github_pr.create_issue_comment(f"Created a PR in app-interface GitLab {gitlab_pr.web_url}")

def ocp_future_version_update(args):
    logger.info("Searching and updating future OCP version")
    latest_ocp_version = version.parse(get_latest_ocp_version())
    future_version = "{major}.{minor}".format(major=latest_ocp_version.major, minor=latest_ocp_version.minor+1, micro=latest_ocp_version.micro)
    current_assisted_service_ocp_future_version = get_default_ocp_version(future_version)

    current_assisted_service_ocp_future_version_split = current_assisted_service_ocp_future_version.rsplit(".", 1)
    next_version = "{}.{}".format(current_assisted_service_ocp_future_version_split[0], str(int(current_assisted_service_ocp_future_version_split[1]) + 1))

    if args.dry_run:
        next_version = "latest"

    res = requests.get(OCP_FUTURE_RELEASE_URL.format(future_version=next_version))
    if res.ok:
        logger.info("New future ocp version available")
    else:
        logger.info("No new ocp version")
        return

    jira_client, task = create_task(args, OCP_TICKET_DESCRIPTION, current_assisted_service_ocp_future_version, next_version)

    if args.dry_run:
        task = OCP_DR_FUTURE_TASK

    if task is None:
        logging.info("Not creating PR because ticket already exists")
        return

    branch, openshift_versions_json = update_ai_repo_to_new_version(args,
                                                                    current_assisted_service_ocp_future_version,
                                                                    next_version,
                                                                    OCP_REPLACE_CONTEXT,
                                                                    task)

    logging.info(f"Using versions JSON {openshift_versions_json}")

    if args.dry_run:
        return

    github_pr = open_pr(args, current_assisted_service_ocp_future_version, next_version, task)
    unhold_pr(github_pr)

def rhcos_version_update(args):
    logger.info("Searching and updating RHCOS version")
    latest_ocp_version = version.parse(get_latest_ocp_version())

    ocp_version_major = "{major}.{minor}".format(major=latest_ocp_version.major, minor=latest_ocp_version.minor,
                                                 micro=latest_ocp_version.micro)
    release_json = get_default_release_json()
    rhcos_default_release = get_rchos_default_release(ocp_version_major, release_json)
    rhcos_latest_release = get_rchos_latest_release(RCHOS_LATEST_RELEASE_URL.format(version=ocp_version_major))

    if args.dry_run:
        rhcos_latest_release = DRY_RUN_VERSION

    if rhcos_latest_release == rhcos_default_release:
        logging.info(f"RCHOS version {rhcos_latest_release} is up to date")
        return

    jira_client, task = create_task(args, RCHOS_TICKET_DESCRIPTION, rhcos_default_release, rhcos_latest_release)

    if args.dry_run:
        task = RHCOS_DR_TASK
        rhcos_latest_release = rhcos_default_release

    if task is None:
        logging.info("Not creating PR because ticket already exists")
        return

    create_updated_rhcos_pr(args, ocp_version_major, release_json, rhcos_default_release, rhcos_latest_release, task)


def rhcos_future_version_update(args):
    logger.info("Searching and updating RHCOS future version")
    latest_ocp_version = version.parse(get_latest_ocp_version())
    future_version = "{major}.{minor}".format(major=latest_ocp_version.major, minor=latest_ocp_version.minor+1, micro=latest_ocp_version.micro)

    release_json = get_default_release_json()

    rhcos_future_default_release = get_rchos_default_release(future_version, release_json)
    rhcos_future_latest_release = get_rchos_latest_release(RCHOS_FUTURE_LATEST_RELEASE_URL)

    if args.dry_run:
        rhcos_future_latest_release = DRY_RUN_VERSION

    if rhcos_future_default_release == rhcos_future_latest_release:
        logging.info(f"RCHOS version {rhcos_future_latest_release} is up to date")
        return

    jira_client, task = create_task(args, RCHOS_TICKET_DESCRIPTION, rhcos_future_default_release, rhcos_future_latest_release)

    if args.dry_run:
        task = RHCOS_DR_FUTURE_TASK
        rhcos_future_latest_release = rhcos_future_latest_release

    if task is None:
        logging.info("Not creating PR because ticket already exists")
        return

    create_updated_rhcos_pr(args, future_version, release_json, rhcos_future_default_release, rhcos_future_latest_release, task)

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

def create_updated_rhcos_pr(args, ocp_version_major, release_json, rhcos_default_release, rhcos_latest_release, task):

    clone_assisted_service(args.github_user_password)
    change_version_in_files(rhcos_default_release, rhcos_latest_release, RCHOS_RELEASE_REPLACE_CONTEXT)

    if args.dry_run:
        rchos_version_from_iso = "123456"
        rhcos_latest_release = DRY_RUN_VERSION
    else:
        rchos_version_from_iso = get_rchos_version_from_iso(rhcos_latest_release)

    rhcos_version_from_default = release_json[ocp_version_major]['rhcos_version']

    change_version_in_files(rhcos_version_from_default, rchos_version_from_iso, RCHOS_VERSION_REPLACE_CONTEXT)

    cmd(["make", "generate-ocp-version"], cwd=ASSISTED_SERVICE_CLONE_DIR)

    branch = commit_and_push_version_update_changes(rhcos_latest_release, task)

    if args.dry_run:
        return

    github_pr = open_pr(args, rhcos_default_release, rhcos_latest_release, task)
    unhold_pr(github_pr)


def get_rchos_version_from_iso(rhcos_latest_release):
    live_iso_url = RCHOS_LATEST_LIVE_ISO_URL.format(version=rhcos_latest_release)
    with tempfile.NamedTemporaryFile() as tmp_live_iso_file:
        subprocess.check_output(
            DOWNLOAD_LIVE_ISO_CMD.format(live_iso_url=live_iso_url, out_file=tmp_live_iso_file.name), shell=True)
        try:
            os.remove("tmp/zipl.prm")
        except:
            pass
        subprocess.check_output(f"7z x {tmp_live_iso_file.name} zipl.prm", shell=True, cwd="/tmp")
        with open("/tmp/zipl.prm", 'r') as f:
            zipl_info = f.read()
        result = RCHOS_VERSION_FROM_ISO_REGEX.search(zipl_info)
        rchos_version_from_iso = result.group(1)
        logger.info(f"Found rchos_version_from_iso: {rchos_version_from_iso}")
    return rchos_version_from_iso


def get_rchos_default_release(ocp_version_major, release_json):
    rchos_release_image = release_json[ocp_version_major]['rhcos_image']
    result = RHCOS_LIVE_ISO_REGEX.search(rchos_release_image)
    rhcos_default_version = result.group(1)
    return rhcos_default_version


def get_rchos_latest_release(rchos_latest_release_url):
    res = requests.get(rchos_latest_release_url)
    if not res.ok:
        raise RuntimeError(f"GET {rchos_latest_release_url} failed status {res.status_code}")
    result = RHCOS_LIVE_ISO_REGEX.search(res.text)
    rhcos_latest_release = result.group(1)
    return rhcos_latest_release

def test_changes(args, branch, pr):
    logging.info("testing changes")
    succeeded, url = test_test_infra_passes(args, branch)
    if succeeded:
        logging.info("Test-infra test passed, removing hold branch")
        unhold_pr(pr)
        pr.create_issue_comment(f"test-infra test passed, HOLD label removed, see {url}")
    else:
        logging.warning("Test-infra test failed, not removing hold label")
        pr.create_issue_comment(f"test-infra test failed, HOLD label is set, see {url}")

    return succeeded


def test_test_infra_passes(args, branch):
    username, password = get_login(args.jenkins_user_password)
    jenkins_client = jenkins.Jenkins(JENKINS_URL, username=username, password=password)
    next_build_number = jenkins_client.get_job_info(TEST_INFRA_JOB)['nextBuildNumber']
    logger.info("Test-infra build number: {}".format(next_build_number))

    username, *_ = get_login(args.github_user_password)
    jenkins_client.build_job(TEST_INFRA_JOB,
                             parameters={"SERVICE_BRANCH": branch,
                                         "NOTIFY": False,
                                         "JOB_NAME": "Update_ocp_version",
                                         "SERVICE_REPO":ASSISTED_SERVICE_CLONE_URL.format(user_login=args.github_user_password, github_user=username)}
                             )
    time.sleep(10)
    url = jenkins_client.get_build_info(TEST_INFRA_JOB, next_build_number)["url"]
    logger.info("Test-infra build url: {}".format(url))
    while not jenkins_client.get_build_info(TEST_INFRA_JOB, next_build_number)["result"]:
        logging.info(f"Waiting for job {url} to finish")
        time.sleep(30)
    job_info = jenkins_client.get_build_info(TEST_INFRA_JOB, next_build_number)
    result = job_info["result"]
    url = job_info["url"]
    logging.info(f"Job finished with result {result}")
    return result == "SUCCESS", url


def create_task(args, description,  current_assisted_service_ocp_version, latest_ocp_version):
    jira_client = get_jira_client(*get_login(args.jira_user_password))
    task = create_jira_ticket(jira_client, description, latest_ocp_version, current_assisted_service_ocp_version, args.dry_run)
    return jira_client, task


def get_latest_ocp_version():
    res = requests.get(OCP_LATEST_RELEASE_URL)
    if not res.ok:
        raise RuntimeError(f"GET {OCP_LATEST_RELEASE_URL} failed status {res.status_code}")

    _intro_text, version_yaml, *_ = res.text.split("\n---\n")

    ocp_latest_release_data = yaml.load(version_yaml)
    return ocp_latest_release_data['Name']

def get_default_ocp_version(ocp_version_major):

    release_json = get_default_release_json()

    release_image = release_json[ocp_version_major]['release_image']

    result = OCP_VERSION_REGEX.search(release_image)
    ai_latest_ocp_version = result.group(1)
    return ai_latest_ocp_version

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


def create_jira_ticket(jira_client, description, latest_version, current_version, dry_run):
    ticket_text = description.format(latest_version=latest_version, current_version=current_version)

    summaries = get_all_version_ocp_update_tickets_summaries(jira_client)

    try:
        ticket_id = next(ticket_id for ticket_id, ticket_summary in summaries if ticket_summary == ticket_text)
        logger.info(f"Ticket already exists {JIRA_BROWSE_TICKET.format(ticket_id=ticket_id)}")
        return None
    except StopIteration:
        # No ticket found, we can create one
        pass

    if dry_run:
        return DRY_RUN_TASK

    new_task = jira_client.create_issue(project="MGMT",
                                        summary=ticket_text,
                                        priority={'name': 'Blocker'},
                                        components=[{'name': "Assisted-Installer CI"}],
                                        issuetype={'name': 'Task'},
                                        description=ticket_text)
    jira_client.assign_issue(new_task, DEFAULT_ASSIGN)
    logger.info(f"Task created: {new_task} - {JIRA_BROWSE_TICKET.format(ticket_id=new_task)}")
    add_watchers(jira_client, new_task)
    return new_task


def add_watchers(jira_client, issue):
    for w in DEFAULT_WATCHERS:
        jira_client.add_watcher(issue.key, w)


def get_jira_client(username, password):
    logger.info("log-in with username: %s", username)
    return jira.JIRA(JIRA_SERVER, basic_auth=(username, password))


def get_all_version_ocp_update_tickets_summaries(jira_client):
    query = 'component = "Assisted-Installer CI"'
    all_issues = jira_client.search_issues(query, maxResults=False, fields=['summary', 'key'])
    issues = [(issue.key, issue.fields.summary) for issue in all_issues]

    return set(issues)


def clone_assisted_service(user_login):
    username, _password = get_login(user_login)

    cmd(["rm", "-rf", ASSISTED_SERVICE_CLONE_DIR])

    cmd(["git", "clone",
         ASSISTED_SERVICE_CLONE_URL.format(user_login=user_login, github_user=username), ASSISTED_SERVICE_CLONE_DIR])

    def git_cmd(*args: str):
        return cmd(("git", "-C", ASSISTED_SERVICE_CLONE_DIR) + args)

    git_cmd("remote", "add", "upstream", ASSISTED_SERVICE_UPSTREAM_URL)
    git_cmd("fetch", "upstream")
    git_cmd("reset", "upstream/master", "--hard")


def clone_app_interface(gitlab_key_file):
    cmd(["rm", "-rf", APP_INTERFACE_CLONE_DIR])

    cmd_with_git_ssh_key(gitlab_key_file)(
        ["git", "clone", f"git@{APP_INTERFACE_GITLAB}:{APP_INTERFACE_GITLAB_REPO}.git", "--depth=1",
         APP_INTERFACE_CLONE_DIR]
    )


def change_version_in_files(old_version, new_version, replace_context):
    for file in UPDATED_FILES:
        fpath = os.path.join(ASSISTED_SERVICE_CLONE_DIR, file)

        with open(fpath) as f:
            content = f.read()

        for context in replace_context:
            old_version_context = context.format(version=old_version)
            new_version_context = context.format(version=new_version)
            logging.info(f"File {fpath} - replacing {old_version_context} with {new_version_context}")
            content = content.replace(old_version_context, new_version_context)

        with open(fpath, 'w') as f:
            f.write(content)


def add_single_node_fake_4_8_release_image(openshift_versions_json):
    with open(CUSTOM_OPENSHIFT_IMAGES) as f:
        custom_images = json.load(f)

    versions = json.loads(openshift_versions_json)
    versions["4.8"] = custom_images["single-node-alpha"]
    return json.dumps(versions)


def change_version_in_files_app_interface(openshift_versions_json):
    # Use a round trip loader to preserve the file as much as possible
    with open(APP_INTERFACE_SAAS_YAML) as f:
        saas = ruamel.yaml.round_trip_load(f, preserve_quotes=True)

    target_environments = {
        "integration": "/services/assisted-installer/namespaces/assisted-installer-integration.yml",
        "integration-v3": "/services/assisted-installer/namespaces/assisted-installer-integration-v3.yml",
        "staging": "/services/assisted-installer/namespaces/assisted-installer-stage.yml",
        "production": "/services/assisted-installer/namespaces/assisted-installer-production.yml",
    }

    # TODO: This line needs to be removed once 4.8 is actually released
    openshift_versions_json = add_single_node_fake_4_8_release_image(openshift_versions_json)

    # Ref is used to identify the environment inside the JSON
    for environment, ref in target_environments.items():
        if environment in EXCLUDED_ENVIRONMENTS:
            continue

        environment_conf = next(target for target in saas["resourceTemplates"][0]["targets"]
                                if target["namespace"] == {"$ref": ref})

        environment_conf["parameters"]["OPENSHIFT_VERSIONS"] = openshift_versions_json

    with open(APP_INTERFACE_SAAS_YAML, "w") as f:
        # Dump with a round-trip dumper to preserve the file as much as possible.
        # Use arbitrarily high width to prevent diff caused by line wrapping
        ruamel.yaml.round_trip_dump(saas, f, width=2 ** 16)


def commit_and_push_version_update_changes(new_version, message_prefix):
    def git_cmd(*args: str, stdout=None):
        return cmd(("git", "-C", ASSISTED_SERVICE_CLONE_DIR) + args, stdout=stdout)

    git_cmd("commit", "-a", "-m", f"{message_prefix} Updating OCP version to {new_version}")

    branch = BRANCH_NAME.format(prefix=message_prefix, version=new_version)

    verify_latest_config()
    status_stdout, _ = git_cmd("status", "--porcelain", stdout=subprocess.PIPE)
    if len(status_stdout) != 0:
        for line in status_stdout.splitlines():
            logging.info(f"Found on-prem change in file {line}")

        git_cmd("commit", "-a", "-m", f"{message_prefix} Updating OCP latest config to {new_version}")

    git_cmd("push", "origin", f"HEAD:{branch}")
    return branch


def commit_and_push_version_update_changes_app_interface(key_file, fork, new_version, message_prefix):
    branch = BRANCH_NAME.format(prefix=message_prefix, version=new_version)

    def git_cmd(*args: str):
        cmd_with_git_ssh_key(key_file)(("git", "-C", APP_INTERFACE_CLONE_DIR) + args)

    fork_remote_name = "fork"

    git_cmd("fetch", "--unshallow", "origin")
    git_cmd("remote", "add", fork_remote_name, fork.ssh_url_to_repo)
    git_cmd("checkout", "-b", branch)
    git_cmd("commit", "-a", "-m", f'{message_prefix} Updating OCP version to {new_version}')
    git_cmd("push", "--set-upstream", fork_remote_name)

    return branch


def create_app_interface_fork(args):
    with open(REDHAT_CERT_LOCATION, "w") as f:
        f.write(requests.get(REDHAT_CERT_URL).text)

    os.environ["REQUESTS_CA_BUNDLE"] = REDHAT_CERT_LOCATION

    gl = gitlab.Gitlab(APP_INTERFACE_GITLAB_API, private_token=args.gitlab_token)
    gl.auth()

    forks = gl.projects.get(APP_INTERFACE_GITLAB_REPO).forks
    try:
        fork = forks.create({})
    except gitlab.GitlabCreateError as e:
        if e.error_message['name'] != "has already been taken":
            fork = gl.projects.get(f'{gl.user.username}/{APP_INTERFACE_GITLAB_PROJECT}')
        else:
            raise
    return fork

def verify_latest_config():
    try:
        cmd(["make", "generate-ocp-version"], cwd=ASSISTED_SERVICE_CLONE_DIR)
    except subprocess.CalledProcessError as e:
        if e.returncode == 2:
            # We run the command just for its side-effects, we don't care if it fails
            return
        raise

def update_ai_repo_to_new_version(args, old_version, new_version, replace_context, ticket_id):
    clone_assisted_service(args.github_user_password)
    change_version_in_files(old_version, new_version, replace_context)
    cmd(["make", "generate-ocp-version"], cwd=ASSISTED_SERVICE_CLONE_DIR)

    with open(OPENSHIFT_TEMPLATE_YAML) as f:
        openshift_versions_json = next(param["value"] for param in
                                       yaml.safe_load(f)["parameters"] if
                                       param["name"] == "OPENSHIFT_VERSIONS")

    branch = commit_and_push_version_update_changes(new_version, ticket_id)
    return branch, openshift_versions_json


def update_ai_app_sre_repo_to_new_ocp_version(fork, args, new_ocp_version, openshift_versions_json, ticket_id):
    clone_app_interface(args.gitlab_key_file)

    change_version_in_files_app_interface(openshift_versions_json, OCP_REPLACE_CONTEXT)

    return commit_and_push_version_update_changes_app_interface(args.gitlab_key_file, fork, new_ocp_version, ticket_id)


def open_pr(args, current_version, new_version, task):
    branch = BRANCH_NAME.format(prefix=task, version=new_version)

    github_client = github.Github(*get_login(args.github_user_password))
    repo = github_client.get_repo(ASSISTED_SERVICE_GITHUB_REPO)
    body = " ".join([f"@{user}" for user in PR_MENTION])
    pr = repo.create_pull(
        title=PR_MESSAGE.format(current_version=current_version, target_version=new_version, task=task),
        body=body,
        head=f"{github_client.get_user().login}:{branch}",
        base="master"
    )
    hold_pr(pr)
    logging.info(f"new PR opened {pr.url}")
    return pr


def hold_pr(pr):
    pr.create_issue_comment('/hold')


def unhold_pr(pr):
    pr.create_issue_comment('/unhold')


def open_app_interface_pr(fork, branch, current_version, new_version, task):
    body = " ".join([f"@{user}" for user in PR_MENTION])
    body = f"{body}\nSee ticket {JIRA_BROWSE_TICKET.format(ticket_id=task)}"

    pr = fork.mergerequests.create({
        'title': PR_MESSAGE.format(current_version=current_version, target_version=new_version, task=task),
        'description': body,
        'source_branch': branch,
        'target_branch': 'master',
        'target_project_id': fork.forked_from_project["id"],
        'source_project_id': fork.id
    })

    logging.info(f"New PR opened {pr.web_url}")

    return pr

def main(args):

    if args.dry_run:
        delete_test_branches(args)

    ocp_version_update(args)
    ocp_future_version_update(args)
    rhcos_version_update(args)
    rhcos_future_version_update(args)


def delete_test_branches(args):
    clone_assisted_service(args.github_user_password)
    for branch in DRY_RUN_BRANCHES:
        try:
            subprocess.check_output(f"git push origin --delete {branch}", shell=True, cwd=ASSISTED_SERVICE_CLONE_DIR)
        except:
                logger.info(f"Branch {branch} was not deleted on dry run cleanuo")

if __name__ == "__main__":
    main(parse_args())
