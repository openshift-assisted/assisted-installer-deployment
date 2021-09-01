import argparse
import logging
import os
import subprocess

import yaml
from retry import retry

parser = argparse.ArgumentParser()
parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
                    default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
args = parser.parse_args()

logging.basicConfig(level=logging.INFO, format='%(levelname)-10s %(filename)s:%(lineno)d %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)

DEFAULT_REGISTRY = "quay.io/ocpmetal"


@retry(exceptions=subprocess.SubprocessError, tries=3, delay=10)
def does_image_exist(pull_spec: str) -> bool:
    return subprocess.call(f"skopeo inspect --config docker://{pull_spec}", stdout=subprocess.DEVNULL, shell=True) == 0


def main():
    with open(args.deployment, "r") as f:
        deployment = yaml.safe_load(f)

    for _, val in deployment.items():
        hash = val["revision"]
        for image in val["images"]:
            pull_spec = f"{DEFAULT_REGISTRY}/{image}:{hash}"

            if not does_image_exist(pull_spec):
                raise ValueError(f"Image {pull_spec} couldn't be found.")

            logger.info(f"Image {pull_spec} was found")


if __name__ == "__main__":
    main()
