#!/usr/bin/env python3
import argparse
import logging
import os
import subprocess
from datetime import datetime

import yaml

logging.basicConfig(format='%(asctime)s %(message)s')
logging.getLogger().setLevel(logging.INFO)

IMAGE_FORMAT = "quay.io/ocpmetal/{image_name}:{tag}"

#######################################################################################################
# This will promote assisted-installer after testing
# Actions: - tag assisted-installer-deployment git repo  with passed <tag> & <tag>.%d/%m/%Y-%H-%M
#          - tag all images described under assisted-installer.yaml with <tag> & <tag>.%d.%m.%Y-%H.%M
# notice:  - repo has valid push credentials
#          - working location must be  from in the cloned item
#          - context has to be logged in to quay.io
#######################################################################################################

parser = argparse.ArgumentParser()
parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
                    default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
parser.add_argument("--tag", help="image tagging", type=str)
parser.add_argument("--version-tag", help="promote to a version based tag. Will not add tag with date", action='store_true')
args = parser.parse_args()

timestamped_tag = f'{args.tag}.{datetime.now().strftime("%d.%m.%Y-%H.%M")}'


def main():
    tags = [args.tag]
    if not args.version_tag:
        tags.append(timestamped_tag)

    tag_manifest_images(tags)
    tag_repo(tags)


def tag_manifest_images(tags):
    with open(args.deployment, "r") as f:
        deployment = yaml.safe_load(f)

    for component in deployment.values():
        if "backend" not in component["categories"]:
            continue

        for image in component["images"]:
            revision = component["revision"]

            pull_spec = f"{image}:latest-{revision}"

            try:
                tag_image(pull_spec, tags)
            except Exception as ex:
                logging.exception("Failed to tag %s, reason: %s", image, ex)


def tag_image(image, tags):
    for tag in tags:
        logging.info(f"Tagging image {image} to {tag}")
        tagged_image = f'{image.rsplit(":")[0]}:{tag}'
        subprocess.check_output(f"skopeo copy docker://{image} docker://{tagged_image}", shell=True)


def tag_repo(tags):
    for tag in tags:
        logging.info(f"Tagging repo with {tag}")
        subprocess.check_call(["git", "tag", tag, "-f"])
        subprocess.check_call(["git", "push", "origin", tag, "-f"])


if __name__ == "__main__":
    main()
