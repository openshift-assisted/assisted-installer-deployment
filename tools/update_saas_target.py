import argparse
import subprocess
import sys
import os
import logging
from datetime import datetime
from ruamel.yaml import YAML
yaml = YAML()

###########################################################################################
# This will create a branch named <user>/saas_file_update on the forked app-interface repo
# updated with the target described under saas file (default is target_saas.yaml)
###########################################################################################

logging.basicConfig(format='%(asctime)s %(message)s')
logging.getLogger().setLevel(logging.INFO)

APP_INTERFACE_REPO = "https://gitlab.cee.redhat.com/{user}/app-interface.git"
SAAS_FILE_PATH = "app-interface/data/services/assisted-installer/cicd/saas.yaml"
COMMIT_MESSAGE = "Updating saas file"

parser = argparse.ArgumentParser()
parser.add_argument("--saas_file", help="deployment yaml file to update", type=str,
 default=os.path.join(os.path.dirname(__file__), "../target_saas.yaml"))
parser.add_argument("--user", help="Git lab user (used for forked)")
parser.add_argument("--deployment_update", help="Commit and push deployment changes", action='store_true')
parser.add_argument("--update", help="Update changes to app-interface", action='store_true')
args = parser.parse_args()

APP_INTERFACE_REPO = APP_INTERFACE_REPO.format(user=args.user)

def main():
   update_saas_file()
   if args.update:
        udpate_app_interface_saas_file()
   if args.deployment_update:
        deployment_update()

def update_saas_file():
    command = "git clone {}".format(APP_INTERFACE_REPO)
    logging.info("cloneing repo:  {command}".format(command=command))
    subprocess.check_output(command, shell=True)

    with open(args.saas_file, "r") as f:
        updated_source = yaml.load(f)

    with open(SAAS_FILE_PATH, "r") as f:
        updated_target = yaml.load(f)

    updated_target['resourceTemplates'][0]['targets'] = updated_source['targets']

    with open(SAAS_FILE_PATH, "w") as f:
        yaml.dump(updated_target, f)

def udpate_app_interface_saas_file():

    command = "git commit -am\'{}\'".format(COMMIT_MESSAGE)
    logging.info("committing changes:  {command}".format(command=command))
    subprocess.check_output(command, shell=True, cwd="./app-interface")

    command = "git push origin HEAD:{user}/saas_file_update".format(user=args.user)
    logging.info("pushing changes:  {command}".format(command=command))
    subprocess.check_output(command, shell=True, cwd="./app-interface")

def deployment_update():
    command = "git commit -am\'{}\'".format(COMMIT_MESSAGE)
    logging.info("committing changes:  {command}".format(command=command))
    subprocess.check_output(command, shell=True)

    command = "git push origin HEAD:master"
    logging.info("pushing changes:  {command}".format(command=command))
    subprocess.check_output(command, shell=True)

if __name__ == "__main__":
    main()
