import re
import json
import jira
import yaml
import logging
import requests
import argparse
import subprocess
from github import Github

logging.basicConfig(level=logging.WARN, format='%(levelname)-10s %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)

OCP_LATEST_RELEASE_URL = "https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/latest/release.txt"
OCP_VERSION_MAKEFILE_REGEX = re.compile("quay.io/openshift-release-dev/ocp-release:(.*)-x86_64")
ASSISTED_SERVICE_MAKEFILE = "https://raw.githubusercontent.com/openshift/assisted-service/master/default_ocp_versions.json"
ASSISTED_SERVICE_CLONE_CMD = "git clone https://{user_password}@github.com/openshift/assisted-service.git"
JIRA_SERVER = "https://issues.redhat.com/"
DEFAULT_NETRC_FILE = "~/.netrc"
DEFAULT_WATCHERS = ["ronniela", "romfreiman", "lgamliel", "oscohen"]
UPDATED_FILES = ["default_ocp_versions.json", "config/onprem-iso-fcc.yaml", "onprem-environment"]
BRANCH_NAME = "update_ocp_version_to_{version}"

def main(args):
    latest_ocp_version = get_latest_OCP_version()
    current_assisted_service_ocp_version = get_makefile_OCP_version(latest_ocp_version)

    if latest_ocp_version != current_assisted_service_ocp_version:
        logging.info("OCP version mismatch, \n\tlatest version: {}\n\tcurrent version {}".format(
            latest_ocp_version,
            current_assisted_service_ocp_version))

        jusername, jpassword = get_login(args.jira_user_password)
        jclient = get_jira_client(jusername, jpassword)
        task = create_jira_ticket(jclient, latest_ocp_version, current_assisted_service_ocp_version)
        if task:
            update_ai_repo_to_new_ocp_version(args, current_assisted_service_ocp_version, latest_ocp_version, task)

    else:
        logging.info("OCP version {} is up to date".format(latest_ocp_version))

def get_latest_OCP_version():
    res = requests.get(OCP_LATEST_RELEASE_URL)
    if not res.ok:
        raise "can\'t get OCP version"

    ocp_latest_release_data = yaml.load(res.text.split("\n---\n")[1])
    return ocp_latest_release_data['Name']


def get_makefile_OCP_version(latest_ocp_version):
    res = requests.get(ASSISTED_SERVICE_MAKEFILE)
    if not res.ok:
        raise "can\'t get assisted-service makefile"

    ocp_versions = json.loads(res.text)
    ocp_version_major = latest_ocp_version.rsplit('.',1)[0]

    release_image = ocp_versions[ocp_version_major]['release_image']

    result = OCP_VERSION_MAKEFILE_REGEX.search(release_image)
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

# def open_OCP_version_update_JIRA_ticket():

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
    subprocess.check_output("git push origin HEAD:{}".format(branch), cwd="assisted-service", shell=True)


def update_ai_repo_to_new_ocp_version(args, old_ocp_version, new_ocp_version, ticket_id):
    clone_assisted_service(args.git_user_password)
    change_version_in_files(old_ocp_version, new_ocp_version)
    commit_and_push_version_update_changes(new_ocp_version, ticket_id)

def open_pr(args, new_version):
    branch = BRANCH_NAME.format(version=new_version)

    gusername, gpassword = get_login(args.git_user_password)
    g = Github(gusername, gpassword)
    repo = g.get_repo("openshift/assisted-service")
    pr = repo.create_pull(title="Update OCP version to {}".format(new_version), body="",head=branch, base="stable")
    logging.info("new PR opend {}".format(pr.url))

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-jup", "--jira-user-password", help="Username and password in the format of user:pass")
    parser.add_argument("-gup", "--git-user-password", help="Username and password in the format of user:pass")
    args = parser.parse_args()

    main(args)
