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

timestamped_tag = "{tag}.{timestamp}".format(
    tag=args.tag, timestamp=datetime.now().strftime("%d.%m.%Y-%H.%M"))


def main():
    tags = [args.tag]
    if not args.version_tag:
        tags.append(timestamped_tag)

    tag_manifest_images(tags)
    tag_repo(tags)


def tag_manifest_images(tags):
    with open(args.deployment, "r") as f:
        deployment = yaml.load(f)
    for rep, rep_data in deployment.items():
        for image in rep_data["images"]:
            image_full_name = IMAGE_FORMAT.format(image_name=image, tag=rep_data["revision"])
            try:
                tag_image(image_full_name, tags)
            except Exception as ex:
                logging("Failed to tag {image}, reason: {exception}".format(image=image, exception=ex))


def tag_image(image, tags):
    for t in tags:
        logging.info("Tagging image {image} to {tag}".format(
            image=image, tag=t))
        tagged_image = "{image}:{tag}".format(image=image.rsplit(":")[0], tag=t)
        subprocess.check_output("skopeo copy docker://{} docker://{}".format(image, tagged_image), shell=True)


def tag_repo(tags):
    for t in tags:
        logging.info("Tagging repo with {tag}".format(tag=t))
        subprocess.check_output("git tag {tag} -f".format(tag=t), shell=True)
        subprocess.check_output("git push origin {tag} -f".format(tag=t), shell=True)


if __name__ == "__main__":
    main()
