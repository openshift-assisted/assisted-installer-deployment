import argparse
import time
import subprocess
import sys
import os
import re
import yamlordereddictloader

import sys
from ruamel.yaml import YAML

yaml = YAML()


def update_hash(deployment_yaml, repo, hash):
    pattern = re.compile(r'\b[0-9a-f]{40}\b')
    match_SHA1 = re.match(pattern, hash)
    if not match_SHA1:
        sys.exit("the passed hash {} is not a valid SHA1 hash".format(hash))

    with open(deployment_yaml, "r") as f:
        deployment = yaml.load(f)
    if repo not in deployment:
        sys.exit("repo {} is not located in the deployment file".format(args.repo))
    if hash == deployment[repo]:
        print("repo {} hash is not changed".format(hash))
        return

    deployment[repo]["revision"] = hash
    with open(deployment_yaml, "w") as f:
        yaml.dump(deployment, f)
    print("updated {} repo with {} hash".format(repo, hash))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", help='repo to update', type=str, required=True)
    parser.add_argument("--hash", help='hash to update', type=str, required=True)
    parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
                        default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
    args = parser.parse_args()

    update_hash(deployment=args.deployment, repo=args.repo, hash=args.hash)


if __name__ == "__main__":
    main()
