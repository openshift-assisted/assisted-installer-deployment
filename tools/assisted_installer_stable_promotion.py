import argparse
import subprocess
import yaml
import sys
import os
import logging
from datetime import datetime
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
args = parser.parse_args()

timestamped_tag = "{tag}.{timestamp}".format(
    tag=args.tag, timestamp=datetime.now().strftime("%d.%m.%Y-%H.%M"))

def main():
    tag_manifest_images()
    tag_repo(args.tag)
    tag_repo(timestamped_tag)

def tag_manifest_images():
    with open(args.deployment, "r") as f:
        deployment = yaml.load(f)
    for rep, rep_data in deployment.items():
        for image in rep_data["images"]:
            image_full_name = IMAGE_FORMAT.format(image_name=image, tag=rep_data["revision"])
            try:
                tag_image(image_full_name)
            except Exception as ex:
                logging("Failed to tag {image}, reason: {exception}".format(image=image, exception=ex))

def tag_image(image):
    logging.info("Tagging image {image} to {tag} & {timestamped_tag}".format(
        image=image, tag=args.tag, timestamped_tag=timestamped_tag))

    subprocess.check_output("podman pull {}".format(image), shell=True)

    # seting images names & tags
    tagged_image = "{image}:{tag}".format(image=image.rsplit(":")[0], tag=args.tag)
    timestamp_tagged_image = "{image}:{tag}".format(image=image.rsplit(":")[0], tag=timestamped_tag)

    # Tagging images
    subprocess.check_output("podman tag {} {}".format(image, tagged_image), shell=True)
    subprocess.check_output("podman tag {} {}".format(image, timestamp_tagged_image), shell=True)

    # Pushing images
    subprocess.check_output("podman push {}".format(tagged_image), shell=True)
    subprocess.check_output("podman push {}".format(timestamp_tagged_image), shell=True)

def tag_repo(tag):
    logging.info("Tagging repo with {tag}".format(tag=tag))
    subprocess.check_output("git tag {tag} -f".format(tag=tag), shell=True)
    subprocess.check_output("git push origin {tag} -f".format(tag=tag), shell=True)


if __name__ == "__main__":
    main()
