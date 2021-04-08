import argparse
import time
import subprocess
import yaml
import sys
import os
import re
import update_hash

parser = argparse.ArgumentParser()
parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
 default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
args = parser.parse_args()

def image_dose_not_exist(image, tag):
    cmd = f"docker manifest inspect quay.io/ocpmetal/{image}:{tag}"
    image_inspect_output = subprocess.check_output(cmd, shell=True)
    image_inspect_output = subprocess.check_output("echo $?", shell=True)
    return int(image_inspect_output)

def main():

    with open(args.deployment, "r") as f:
        deployment = yaml.load(f)
    for rep, val in deployment.items():
        hash = val["revision"]
        for image in val["images"]:
            if image_dose_not_exist(image, hash):
                print(f"image {image}:{hash} doesn't exist in registry")
                raise Exception(f"image {image}:{hash} doesn't exist in registry")
            else:
                print(f"image {image}:{hash} is located")


if __name__ == "__main__":
    main()

