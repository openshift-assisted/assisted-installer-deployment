import re
import os
import json
import jira
import time
import yaml
import ruamel.yaml
import jenkins
import logging
import requests
import argparse
import subprocess
from functools import partial
from github import Github
import gitlab

script_dir = os.path.dirname(os.path.realpath(__file__))

##############################################
# Updates OCP version by:
#  * check if new version is available
#  * open OCP version JIRA ticket
#  * create a update branch
#  * open a GitHub PR for the changes
#  * test test-infra
###############################################

logging.basicConfig(level=logging.INFO, format='%(levelname)-10s %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)

ASSISTED_SERVICE_DOCPV = "https://raw.githubusercontent.com/openshift/assisted-service/master/default_ocp_versions.json"
OCP_LATEST_RELEASE_URL = "https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/latest/release.txt"
ASSISTED_SERVICE_CLONE_CMD = "git clone https://{user_password}@github.com/openshift/assisted-service.git --depth=1"
APP_INTERFACE_GITLAB_REPO = "gitlab.cee.redhat.com"
APP_INTERFACE_CLONE_CMD = f"git clone git@{APP_INTERFACE_GITLAB_REPO}:service/app-interface.git --depth=1"
APP_INTERFACE_GITLAB_API = f'https://{APP_INTERFACE_GITLAB_REPO}'
APP_INTERFACE_CLONE_SSH_COMMAND = "ssh -o StrictHostKeyChecking=accept-new -i '{gitlab_key}'"
DELETE_ASSISTED_SERVICE_CLONE_CMD = "rm -rf assisted-service"
DELETE_APP_INTERFACE_CLONE_CMD = "rm -rf app-interface"
UPDATED_FILES = ["default_ocp_versions.json", "config/onprem-iso-fcc.yaml", "onprem-environment"]
OPENSHIFT_TEMPLATE_YAML = "openshift/template.yaml"
APP_INTERFACE_SAAS_YAML = "app-interface/data/services/assisted-installer/cicd/saas.yaml"
OCP_VERSION_REGEX = re.compile("quay.io/openshift-release-dev/ocp-release:(.*)-x86_64")
JENKINS_URL = "http://assisted-jenkins.usersys.redhat.com"
PR_MESSAGE = "{task}, Bump OCP version from {current_version} to {target_version} (auto created)"
BRANCH_NAME = "update_ocp_version_to_{version}"
JIRA_SERVER = "https://issues.redhat.com/"
TEST_INFRA_JOB = "assisted-test-infra/master"
DEFAULT_NETRC_FILE = "~/.netrc"
HOLD_LABEL = "do-not-merge/hold"
DEFAULT_WATCHERS = ["ronniela", "romfreiman", "lgamliel", "oscohen"]
PR_MENTION = ["romfreiman", "ronniel1", "gamli75", "oshercc"]
DEFAULT_ASSIGN = "lgamliel"
REPLACE_CONTEXT = ["\"{ocp_version}\"", "ocp-release:{ocp_version}"]
REDHAT_CERT_URL = 'https://password.corp.redhat.com/RH-IT-Root-CA.crt'
REDHAT_CERT_LOCATION = "/tmp/redhat.cert"
CUSTOM_OPENSHIFT_IMAGES = os.path.join(script_dir, "custom_openshift_images.json")


def main(args):
    latest_ocp_version = get_latest_OCP_version()
    current_assisted_service_ocp_version = get_default_OCP_version(latest_ocp_version)

    if latest_ocp_version != current_assisted_service_ocp_version:
        logging.info("OCP version mismatch, \n\tlatest version: {}\n\tcurrent version {}".format(
            latest_ocp_version,
            current_assisted_service_ocp_version))

        ticket_id = create_task(args, current_assisted_service_ocp_version, latest_ocp_version)

        # task is not created in case task is available
        if ticket_id is not None:
            branch, openshift_versions_json = update_ai_repo_to_new_ocp_version(args, current_assisted_service_ocp_version, latest_ocp_version, ticket_id)
            pr = open_pr(args, current_assisted_service_ocp_version, latest_ocp_version , ticket_id)
            test_success = test_changes(branch, pr)

            if test_success:
                fork = create_app_interface_fork()
                branch = update_ai_app_sre_repo_to_new_ocp_version(fork, args, latest_ocp_version, openshift_versions_json, ticket_id)
                _pr = open_app_interface_pr(fork, branch, current_assisted_service_ocp_version, latest_ocp_version, ticket_id)
        else:
            logging.info("update to version {} already available".format(latest_ocp_version))

    else:
        logging.info("OCP version {} is up to date".format(latest_ocp_version))


def test_changes(branch, pr):
    succeeded, url = test_test_infra_passes(branch)
    if succeeded:
        logging.info("Test-infra test passed, removing hold branch")
        remove_hold_lable(pr)
        pr.create_issue_comment(f"test-infra test passed, HOLD label removed, see {url}")
    else:
        logging.warning("Test-infra test failed, not removing hold label")
        pr.create_issue_comment(f"test-infra test failed, HOLD label is set, see {url}")

    return succeeded


def test_test_infra_passes(branch):
    jkusername, jkpassword = get_login(args.jenkins_user_password)
    j = jenkins.Jenkins(JENKINS_URL, username=jkusername, password=jkpassword)
    next_build_number = j.get_job_info(TEST_INFRA_JOB)['nextBuildNumber']
    j.build_job(TEST_INFRA_JOB, parameters={"SERVICE_BRANCH": branch, "NOTIFY":False, "JOB_NAME": "Update_ocp_version"})
    time.sleep(10)
    while not j.get_build_info(TEST_INFRA_JOB, next_build_number)["result"]:
        logging.info("waiting for job to finish")
        time.sleep(30)
    job_info = j.get_build_info(TEST_INFRA_JOB, next_build_number)
    result = job_info["result"]
    url = job_info["url"]
    logging.info("Job finished with result {}".format(result))
    return result == "SUCCESS", url


def remove_hold_lable(pr):
    pr.remove_from_labels(HOLD_LABEL)


def create_task(args, current_assisted_service_ocp_version, latest_ocp_version):
    jusername, jpassword = get_login(args.jira_user_password)
    jclient = get_jira_client(jusername, jpassword)
    task = create_jira_ticket(jclient, latest_ocp_version, current_assisted_service_ocp_version)
    return task


def get_latest_OCP_version():
    res = requests.get(OCP_LATEST_RELEASE_URL)
    if not res.ok:
        raise "can\'t get OCP version"

    ocp_latest_release_data = yaml.load(res.text.split("\n---\n")[1])
    return ocp_latest_release_data['Name']


def get_default_OCP_version(latest_ocp_version):
    res = requests.get(ASSISTED_SERVICE_DOCPV)
    if not res.ok:
        raise "can\'t get assisted-service makefile"

    ocp_versions = json.loads(res.text)
    ocp_version_major = latest_ocp_version.rsplit('.',1)[0]

    release_image = ocp_versions[ocp_version_major]['release_image']

    result = OCP_VERSION_REGEX.search(release_image)
    ai_latest_ocp_version = result.group(1)
    return ai_latest_ocp_version

def get_credentials_from_netrc(server, netrc_file=DEFAULT_NETRC_FILE):
    cred = netrc.netrc(os.path.expanduser(netrc_file))
    username, _, password = cred.authenticators(server)
    return username, password

def get_login(user_password):
    try:
        [username, password] = user_password.split(":", 1)
    except:
        logger.error("Failed to parse user:password")
    return username, password

def create_jira_ticket(jclient, latestV, currentV):
    summary = "OCP version update required, Latest version {}, Current version {}".format(latestV, currentV)

    existing_tickets = get_all_version_ocp_update_tickets(jclient)
    if summary in existing_tickets:
        logger.info("task found: %s", summary)
        return None

    new_task = jclient.create_issue(project="MGMT",
                                     summary=summary,
                                     priority={'name': 'Blocker'},
                                     components=[{'name': "Assisted-Installer CI"}],
                                     issuetype={'name': 'Task'},
                                     description=summary)
    jclient.assign_issue(new_task, DEFAULT_ASSIGN)
    logger.info("Task created: %s", new_task)
    add_watchers(jclient, new_task)
    return new_task

def add_watchers(jclient, issue):
    for w in DEFAULT_WATCHERS:
        jclient.add_watcher(issue.key, w)

def get_jira_client(username, password):
    logger.info("log-in with username: %s", username)
    return jira.JIRA(JIRA_SERVER, basic_auth=(username, password))


def get_all_version_ocp_update_tickets(jclient):
    query = 'component = "Assisted-Installer CI"'
    idx = 0
    block_size = 100
    issues = []
    while True:
        i = jclient.search_issues(query, maxResults=block_size, startAt=idx, fields=['summary', 'key'])
        if len(i) == 0:
            break
        issues.extend([x.fields.summary for x in i])
        idx += block_size

    return set(issues)

def clone_assisted_service(user_password):
    subprocess.check_output(DELETE_ASSISTED_SERVICE_CLONE_CMD, shell=True)
    cmd = ASSISTED_SERVICE_CLONE_CMD.format(user_password=user_password)
    subprocess.check_output(cmd, shell=True)

def clone_app_interface(gitlab_key):
    logging.info(DELETE_APP_INTERFACE_CLONE_CMD)
    subprocess.check_output(DELETE_APP_INTERFACE_CLONE_CMD, shell=True)
    logging.info(APP_INTERFACE_CLONE_CMD)
    logging.info(APP_INTERFACE_CLONE_SSH_COMMAND.format(gitlab_key=gitlab_key))
    subprocess.check_output(APP_INTERFACE_CLONE_CMD, shell=True,
                            env={**os.environ,
                                 "GIT_SSH_COMMAND": APP_INTERFACE_CLONE_SSH_COMMAND.format(gitlab_key=gitlab_key)
                                 })

def change_version_in_files(old_version ,new_version):
    old_version = old_version.replace(".", "\.")
    for file in UPDATED_FILES:
        for context in REPLACE_CONTEXT:
            old_version_context = context.format(ocp_version=old_version)
            new_version_context = context.format(ocp_version=new_version)
            subprocess.check_output(f"sed -i -e 's|{old_version_context}|{new_version_context}|g' assisted-service/{file}".format(
                old_version=old_version,
                new_version=new_version,
                file=file
            ),shell=True)

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

    # This is used to find the integration target among the targets
    integration_ref = {"$ref": "/services/assisted-installer/namespaces/assisted-installer-integration.yml"}

    # Extract the integration target
    integration = next(target for target in saas["resourceTemplates"][0]["targets"]
                       if target["namespace"] == integration_ref)

    # TODO: This line needs to be removed once 4.8 is actually released
    openshift_versions_json = add_single_node_fake_4_8_release_image(openshift_versions_json)

    integration["parameters"]["OPENSHIFT_VERSIONS"] = openshift_versions_json

    with open(APP_INTERFACE_SAAS_YAML, "w") as f:
        # Dump with a round-trip dumper to preserve the file as much as possible.
        # Use arbitrarily high width to prevent diff caused by line wrapping
        ruamel.yaml.round_trip_dump(saas, f, width=2**16)

def commit_and_push_version_update_changes(new_version, message_prefix):
    subprocess.check_output("git commit -am\'{} Updating OCP version to {}\'".format(message_prefix, new_version), cwd="assisted-service", shell=True)

    branch = BRANCH_NAME.format(version=new_version)

    verify_latest_onprem_config()
    if subprocess.check_output("git status --porcelain", cwd="assisted-service", shell=True):
        subprocess.check_output("git commit -am\'{} Updating OCP latest onprem-config to {}\'".format(message_prefix, new_version),
                                cwd="assisted-service", shell=True)

    subprocess.check_output("git push origin HEAD:{}".format(branch), cwd="assisted-service", shell=True)
    return branch

def commit_and_push_version_update_changes_app_interface(gitlab_key, fork, new_version, message_prefix):
    def cmd(*args, **kwargs):
        logging.info(args)
        subprocess.check_output(*args, **kwargs, env={
            **os.environ,
            "GIT_SSH_COMMAND": APP_INTERFACE_CLONE_SSH_COMMAND.format(gitlab_key=gitlab_key)
        }, cwd="app-interface", shell=True)

    branch = BRANCH_NAME.format(version=new_version)

    cmd("git fetch --unshallow origin")
    cmd(f"git remote add fork {fork.ssh_url_to_repo}")
    cmd(f"git checkout -b {branch}")
    cmd(f"git commit -am \'{message_prefix} Updating OCP version to {new_version}\'")
    cmd("git push --set-upstream fork")

    return branch

def create_app_interface_fork():
    with open(REDHAT_CERT_LOCATION, "w") as f:
        f.write(requests.get(REDHAT_CERT_URL).text)

    os.environ["REQUESTS_CA_BUNDLE"] = REDHAT_CERT_LOCATION

    gl = gitlab.Gitlab(APP_INTERFACE_GITLAB_API, private_token=args.gitlab_token)
    gl.auth()

    forks = gl.projects.get('service/app-interface').forks
    try:
        fork = forks.create({})
    except gitlab.GitlabCreateError as e:
        if e.error_message['name'] != "has already been taken":
            fork = gl.projects.get(f'{gl.user.username}/app-interface')
        else:
            raise

    return fork

def verify_latest_onprem_config():
    try:
        subprocess.check_output("make verify-latest-onprem-config", cwd="assisted-service", shell=True)
    except:
        pass

def update_ai_repo_to_new_ocp_version(args, old_ocp_version, new_ocp_version, ticket_id):
    clone_assisted_service(args.github_user_password)
    change_version_in_files(old_ocp_version, new_ocp_version)
    try:
        subprocess.check_output("make update-ocp-version", shell=True)
    except:
        pass

    with open(OPENSHIFT_TEMPLATE_YAML) as f:
        openshift_versions_json = [param["value"] for param in
                                   yaml.safe_load(f)["parameters"] if
                                   param["name"] == "OPENSHIFT_VERSIONS"]

    branch = commit_and_push_version_update_changes(new_ocp_version, ticket_id)
    return branch, openshift_versions_json

def update_ai_app_sre_repo_to_new_ocp_version(fork, args, new_ocp_version, openshift_versions_json, ticket_id):
    clone_app_interface(args.gitlab_key_file)

    change_version_in_files_app_interface(openshift_versions_json)

    return commit_and_push_version_update_changes_app_interface(args.gitlab_key_file, fork, new_ocp_version, ticket_id)

def open_pr(args, current_version, new_version, task):
    branch = BRANCH_NAME.format(version=new_version)

    gusername, gpassword = get_login(args.git_user_password)
    g = Github(gusername, gpassword)
    repo = g.get_repo("openshift/assisted-service")
    body = " ".join(["@{}".format(user) for user in PR_MENTION])
    pr = repo.create_pull(
        title=PR_MESSAGE.format(current_version=current_version, target_version=new_version, task=task),
        body=body,
        head=branch,
        base="master"
    )
    pr.add_to_labels(HOLD_LABEL)
    logging.info("new PR opened {}".format(pr.url))
    return pr

def open_app_interface_pr(fork, branch, current_version, new_version, task):
    body = " ".join(["@{}".format(user) for user in PR_MENTION])
    pr = fork.mergerequests.create({
        'title': PR_MESSAGE.format(current_version=current_version, target_version=new_version, task=task),
        'description': body,
        'source_branch': branch,
        'target_branch': 'master',
        'target_project_id': fork.forked_from_project["id"],
        'source_project_id': fork.id
    })

    logging.info("New PR opened {}".format(pr.web_url))

    return pr

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-jup", "--jira-user-password", help="JIRA Username and password in the format of user:pass", required=True)
    parser.add_argument("-ghup", "--github-user-password", help="GITHUB Username and password in the format of user:pass", required=True)
    parser.add_argument("-glkf", "--gitlab-key-file", help="GITLAB key file", required=True)
    parser.add_argument("-glto", "--gitlab-token", help="GITLAB user token", required=True)
    parser.add_argument("-jkup", "--jenkins-user-password",help="JENKINS Username and password in the format of user:pass", required=True)
    args = parser.parse_args()

    main(args)
