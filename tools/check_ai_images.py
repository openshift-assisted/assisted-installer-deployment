#!/usr/bin/env python3
import argparse
import logging
import pathlib
import subprocess

import yaml
from retry import retry

logging.basicConfig(level=logging.INFO, format="%(levelname)-10s %(filename)s:%(lineno)d %(message)s")
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)

DEFAULT_REGISTRY = "quay.io/edge-infrastructure"


@retry(exceptions=subprocess.SubprocessError, tries=3, delay=10)
def does_image_exist(pull_spec: str) -> bool:
    cmd = ["skopeo", "inspect", "--config", f"docker://{pull_spec}"]
    return subprocess.call(cmd, stdout=subprocess.DEVNULL) == 0


def validate_deployment_file(path):
    with open(path, "r") as snapshot_file:
        deployment = yaml.safe_load(snapshot_file)

    for val in deployment.values():
        revision_hash = val["revision"]
        for image in val["images"]:
            if image.startswith("quay.io/ocpmetal/"):
                pull_spec = f"{image}:{revision_hash}"
            elif image.startswith("quay.io/edge-infrastructure"):
                pull_spec = f"{image}:latest-{revision_hash}"
            else:
                raise ValueError(f"Unknown repository of image {image}")

            if not does_image_exist(pull_spec):
                raise ValueError(f"Image {pull_spec} couldn't be found")

            logger.info("Image %s was found", pull_spec)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--deployment",
        default=pathlib.Path(__file__).parent.parent / "assisted-installer.yaml",
        help="deployment yaml file to update",
        type=str,
    )
    args = parser.parse_args()

    validate_deployment_file(args.deployment)


if __name__ == "__main__":
    main()
