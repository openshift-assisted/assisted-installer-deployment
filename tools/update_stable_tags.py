import argparse
import subprocess
import yaml
import logging
from datetime import datetime

logging.basicConfig(format='%(asctime)s %(message)s')
logging.getLogger().setLevel(logging.INFO)

#######################################################################
# This will update the stable (by default) tag to the current revision
# +  A tag <tag>.%d/%m/%Y-%H-%M will mark the commit
# notice: * repo has valid push credentials
#         * working location must be  from in the cloned item
#######################################################################

retagging_commands = [
            "git push --delete origin {tag} || true",
            "git tag -d {tag} || true",
            "git tag -f {tag}",
            "git tag -f {tag}.{date}",
            "git push --tags origin {tag}",
            ]

parser = argparse.ArgumentParser()
parser.add_argument("--tag", help="assisted_installer_tag", type=str,
 default="stable")
args = parser.parse_args()

def main():
    timestamp = datetime.now().strftime("%d/%m/%Y-%H-%M")
    for cmd in retagging_commands:
        logging.info("running: {}".format(cmd))
        subprocess.check_output(cmd.format(tag=args.tag, date=timestamp), shell=True)

if __name__ == "__main__":
    main()
