import os
import re
import sys
import yaml
import time
import argparse
import subprocess
import update_hash

parser = argparse.ArgumentParser()
parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
 default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
args = parser.parse_args()

def image_dose_not_exist(image, tag):
    cmd = f"docker manifest inspect quay.io/ocpmetal/{image}:{tag}"
    try:
        image_inspect_output = subprocess.check_output(cmd, shell=True)
        image_inspect_output = subprocess.check_output("echo $?", shell=True)
    except subprocess.SubprocessError:
            image_inspect_output = "-1"
    return int(image_inspect_output)

def image_dose_not_exist_with_retry(image, tag):
    for retry in range(3):
        get_image_result = image_dose_not_exist(image, tag)
        if not get_image_result:
            return  get_image_result
        print(f"Failed to get image at {retry} retry")
        time.sleep(5*60)

    print("Failed to get image information after 3 retries")
    return get_image_result

def main():
    with open(args.deployment, "r") as f:
        deployment = yaml.load(f)
    for rep, val in deployment.items():
        hash = val["revision"]
        for image in val["images"]:
            if image_dose_not_exist_with_retry(image, hash):
                print(f"image {image}:{hash} doesn't exist in registry")
                raise Exception(f"image {image}:{hash} doesn't exist in registry")
            else:
                print(f"image {image}:{hash} is located")


if __name__ == "__main__":
    main()

