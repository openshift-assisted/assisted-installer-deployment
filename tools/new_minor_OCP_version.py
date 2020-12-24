import re
import json
import jira
import yaml
import logging
import requests
import argparse
import subprocess
from github import Github

##############################################
# Updates OCP version by:
#  * check if new version is available
#  * open OCP version JIRA ticket
#  * create a update branch
#  * open a GitHub PR for the changes
###############################################

logging.basicConfig(level=logging.WARN, format='%(levelname)-10s %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)

ASSISTED_SERVICE_DOCPV = "https://raw.githubusercontent.com/openshift/assisted-service/master/default_ocp_versions.json"
OCP_LATEST_RELEASE_URL = "https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/latest/release.txt"
ASSISTED_SERVICE_CLONE_CMD = "git clone https://{user_password}@github.com/openshift/assisted-service.git"
UPDATED_FILES = ["default_ocp_versions.json", "config/onprem-iso-fcc.yaml", "onprem-environment"]
OCP_VERSION_REGEX = re.compile("quay.io/openshift-release-dev/ocp-release:(.*)-x86_64")
PR_MESSAGE = "{task}, Update OCP version to {version}"
BRANCH_NAME = "update_ocp_version_to_{version}"
JIRA_SERVER = "https://issues.redhat.com/"
DEFAULT_NETRC_FILE = "~/.netrc"

DEFAULT_WATCHERS = ["ronniela", "romfreiman", "lgamliel", "oscohen"]
PR_MENTION = ["romfreiman", "ronniel1", "gamli75", "oshercc"]
DEFAULT_ASSIGN = "lgamliel"

def main(args):
    latest_ocp_version = get_latest_OCP_version()
    current_assisted_service_ocp_version = get_default_OCP_version(latest_ocp_version)

    if latest_ocp_version != current_assisted_service_ocp_version:
        logging.info("OCP version mismatch, \n\tlatest version: {}\n\tcurrent version {}".format(
            latest_ocp_version,
            current_assisted_service_ocp_version))

        task = create_task(args, current_assisted_service_ocp_version, latest_ocp_version)
        # task is not created in case task is available
        if task:
            update_ai_repo_to_new_ocp_version(args, current_assisted_service_ocp_version, latest_ocp_version, task)
            open_pr(args, latest_ocp_version , task)
        else:
            logging.info("update to version {} already available".format(latest_ocp_version))

    else:
        logging.info("OCP version {} is up to date".format(latest_ocp_version))


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
    cmd = ASSISTED_SERVICE_CLONE_CMD.format(user_password=user_password)
    subprocess.check_output(cmd, shell=True)

def change_version_in_files(old_version ,new_version):
    old_version = old_version.replace(".", "\.")
    for file in UPDATED_FILES:
        subprocess.check_output(f"sed -i -e 's|{old_version}|{new_version}|g' assisted-service/{file}".format(
            old_version=old_version,
            new_version=new_version,
            file=file
        ),shell=True)

def commit_and_push_version_update_changes(new_version, message_prefix):
    subprocess.check_output("git commit -am\'{} Updating OCP version to {}\'".format(message_prefix, new_version), cwd="assisted-service", shell=True)

    branch = BRANCH_NAME.format(version=new_version)

    verify_latest_onprem_config()
    if subprocess.check_output("git status --porcelain", cwd="assisted-service", shell=True):
        subprocess.check_output("git commit -am\'{} Updating OCP latest onprem-config to {}\'".format(message_prefix, new_version),
                                cwd="assisted-service", shell=True)

    subprocess.check_output("git push origin HEAD:{}".format(branch), cwd="assisted-service", shell=True)

def verify_latest_onprem_config():
    try:
        subprocess.check_output("make verify-latest-onprem-config", cwd="assisted-service", shell=True)
    except:
        pass

def update_ai_repo_to_new_ocp_version(args, old_ocp_version, new_ocp_version, ticket_id):
    clone_assisted_service(args.git_user_password)
    change_version_in_files(old_ocp_version, new_ocp_version)
    commit_and_push_version_update_changes(new_ocp_version, ticket_id)

def open_pr(args, new_version, task):
    branch = BRANCH_NAME.format(version=new_version)

    gusername, gpassword = get_login(args.git_user_password)
    g = Github(gusername, gpassword)
    repo = g.get_repo("openshift/assisted-service")
    body = " ".join(["@{}".format(user) for user in PR_MENTION])
    pr = repo.create_pull(title=PR_MESSAGE.format(version=new_version, task=task), body=body,head=branch, base="master")
    logging.info("new PR opend {}".format(pr.url))

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-jup", "--jira-user-password", help="Username and password in the format of user:pass")
    parser.add_argument("-gup", "--git-user-password", help="Username and password in the format of user:pass")
    args = parser.parse_args()

    main(args)
