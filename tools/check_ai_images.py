import os
import yaml
import time
import argparse
import logging
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
 default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
args = parser.parse_args()

logging.basicConfig(level=logging.INFO, format='%(levelname)-10s %(filename)s:%(lineno)d %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)


def image_does_not_exist(image, tag):
    cmd = f"docker manifest inspect quay.io/ocpmetal/{image}:{tag}"
    try:
        image_inspect_output = subprocess.check_output(cmd, shell=True)
        image_inspect_output = subprocess.check_output("echo $?", shell=True)
    except subprocess.SubprocessError:
        image_inspect_output = "-1"

    return int(image_inspect_output)


def image_exist_with_retry(image, tag):
    for retry in range(3):
        get_image_result = image_does_not_exist(image, tag)
        if not get_image_result:
            return True
        logger.warning(f"Failed to get image at {retry} retry")
        time.sleep(10*60)

    logger.error(f"Failed to get image at {retry} retry")
    return not get_image_result


def main():
    with open(args.deployment, "r") as f:
        deployment = yaml.safe_load(f)
    for rep, val in deployment.items():
        hash = val["revision"]
        for image in val["images"]:
            if image_exist_with_retry(image, hash):
                logger.info(f"image {image}:{hash} is located")
            else:
                logger.error(f"image {image}:{hash} doesn't exist in registry")
                raise Exception(f"image {image}:{hash} doesn't exist in registry")


if __name__ == "__main__":
    main()

