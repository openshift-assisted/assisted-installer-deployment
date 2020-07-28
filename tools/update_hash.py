import argparse
import time
import subprocess
import yaml
import sys
import os
import re

parser = argparse.ArgumentParser()
parser.add_argument("--repo", help='repo to update', type=str, required=True)
parser.add_argument("--hash", help='hash to update', type=str, required=True)
parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
 default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
args = parser.parse_args()

def main():

    pattern = re.compile(r'\b[0-9a-f]{40}\b')
    match_SHA1 = re.match(pattern, args.hash)
    if not match_SHA1:
        sys.exit("the passed hash {} is not a valid SHA1 hash".format(args.hash))

    with open(args.deployment, "r") as f:
        deployment = yaml.safe_load(f)
    if args.repo not in deployment:
        sys.exit("repo {} is not located in the deployment file".format(args.repo))
    if args.hash == deployment[args.repo]:
        print("repo {} hash is not changed".format(hash))
        return


    deployment[args.repo]["revision"] = args.hash
    with open(args.deployment, "w") as f:
        yaml.dump(deployment, f, default_flow_style=False)
    print("updated {} repo with {} hash".format(args.repo, args.hash))

if __name__ == "__main__":
    main()