import argparse
import time
import subprocess
import yaml
import sys
import os
import re
# import yamlordereddictloader
import update_hash

IMAGE_FORMAT = "pull quay.io/ocpmetal/{image_name}:{tag}"

parser = argparse.ArgumentParser()
parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
 default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
parser.add_argument("--tag", help="image tagging", type=str,
 default="latest")
args = parser.parse_args()

def main():
    # TODO log in to quay.io
    # TODO add logsz
    with open(args.deployment, "r") as f:
        deployment = yaml.load(f)
    for rep, rep_data in deployment.items():
        project, repo = rep.split("/")
        if project != "openshift":
            continue
        for image in rep_data["images"]:
            image_full_name = IMAGE_FORMAT.format(image_name=image, tag=rep_data["revision"])
            tag_image(image_full_name)

def tag_image(image):
    subprocess.check_output("docker pull {}".format(image))
    tagged_image = image.rsplit(":")[0] + args.tag
    subprocess.check_output("docker tag {} {}".format(image, tagged_image))
    subprocess.check_output("docker push {}".format(tagged_image))


if __name__ == "__main__":
    main()
