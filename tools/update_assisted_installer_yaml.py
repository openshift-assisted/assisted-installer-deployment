import argparse
import subprocess
import yaml
import os
import yamlordereddictloader
import update_hash

parser = argparse.ArgumentParser()
parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
                    default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
parser.add_argument('--full', help='update all hases to master', action='store_true')
args = parser.parse_args()


def main():
    full_release = args.full or os.environ.get("NIGHTLY_RELEASE", "false") == "true"

    with open(args.deployment, "r") as f:
        deployment = yaml.load(f, Loader=yamlordereddictloader.Loader)
    for rep in deployment:
        if full_release:
            hash = subprocess.check_output("git ls-remote https://github.com/{}.git HEAD | cut -f 1".format(rep), shell=True)[:-1]
            hash = hash.decode("utf-8")
        else:
            hase = os.environ.get(rep, None)
            if not hase:
                continue
        update_hash.update_hash(deployment_yaml=args.deployment, repo=rep, hash=hash)


if __name__ == "__main__":
    main()
