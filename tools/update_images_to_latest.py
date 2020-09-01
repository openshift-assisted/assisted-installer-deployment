import argparse
import subprocess
import yaml
import sys
import os
import logging
logging.basicConfig(format='%(asctime)s %(message)s')
logging.getLogger().setLevel(logging.INFO)

IMAGE_FORMAT = "quay.io/ocpmetal/{image_name}:{tag}"
QUAY_USERNAME = "QUAY_USERNAME"
QUAY_PASS = "QUAY_PASS"

#####################################################################################
# This will iterate over the different images described under assisted-installer.yaml
# and create a tagged instance in quay with the passed tag,
# user must pass quay credentials QUAY_USERNAME/QUAY_PASS
#####################################################################################

parser = argparse.ArgumentParser()
parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
 default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
parser.add_argument("--tag", help="image tagging", type=str,
 default="latest_stable")
args = parser.parse_args()

def main():
    login_to_quayio()
    with open(args.deployment, "r") as f:
        deployment = yaml.load(f)
    for rep, rep_data in deployment.items():
        project, repo = rep.split("/")
        if project != "openshift":
            continue
        for image in rep_data["images"]:
            image_full_name = IMAGE_FORMAT.format(image_name=image, tag=rep_data["revision"])
            try:
                tag_image(image_full_name)
            except Exception as ex:
                logging("Failed to tag {image}\nreason: {exception}".format(image=image, exception=ex))

def tag_image(image):
    logging.info("Tagging image {} to {}".format(image, args.tag))
    subprocess.check_output("docker pull {}".format(image), shell=True)
    tagged_image = "{image}:{tag}".format(image=image.rsplit(":")[0], tag=args.tag)
    subprocess.check_output("docker tag {} {}".format(image, tagged_image), shell=True)
    subprocess.check_output("docker push {}".format(tagged_image), shell=True)

def login_to_quayio():
    logging.info("Logging in to quay.io")
    user = os.environ.get(QUAY_USERNAME, None)
    password = os.environ.get(QUAY_PASS, None)
    if not user or not password:
        raise "quay user and/or password where not passed"
    cmd = "docker login quay.io -u {user} -p {password}".format(user=user, password=password)
    subprocess.check_output(cmd, shell=True)

if __name__ == "__main__":
    main()
