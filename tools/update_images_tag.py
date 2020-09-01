import argparse
import subprocess
import yaml
import os

IMAGE_FORMAT = "quay.io/ocpmetal/{image_name}:{tag}"

parser = argparse.ArgumentParser()
parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
 default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
parser.add_argument("--tag", help="image tagging", type=str,
 default="stable_candidate")
args = parser.parse_args()

def main():
    with open(args.deployment, "r") as f:
        deployment = yaml.load(f)
    for rep, rep_data in deployment.items():
        for image in rep_data["images"]:
            image_full_name = IMAGE_FORMAT.format(image_name=image, tag=rep_data["revision"])
            tag_image(image_full_name)


def exec(cmd):
    print(cmd)
    subprocess.check_output(cmd, shell=True)


def tag_image(image):
    exec("docker pull {}".format(image))
    tagged_image = image.rsplit(":")[0] + f":{args.tag}"
    exec("docker tag {} {}".format(image, tagged_image))
    exec("docker push {}".format(tagged_image))


if __name__ == "__main__":
    main()
