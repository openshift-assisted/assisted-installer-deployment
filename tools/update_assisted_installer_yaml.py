import argparse
import yaml
import os
import github

import update_hash
import skopeo_utils

parser = argparse.ArgumentParser()
parser.add_argument("--deployment", help="deployment yaml file to update", type=str,
                    default=os.path.join(os.path.dirname(__file__), "../assisted-installer.yaml"))
parser.add_argument('--full', help='update all hashes to master', action='store_true')
args = parser.parse_args()


def find_first_common_element(lists: list[str]) -> str:
    if len(lists) < 1:
        raise ValueError("No lists provided. Cannot find common element")

    for el in lists[0]:
        if all(el in list for list in lists[1:]):
            return el

    return None


def get_ref_by_docker_image(images):
    tag_pattern = "^latest-[a-f0-9]{40}$"
    tag_prefix = "latest-"
    skopeo_client = skopeo_utils.Skopeo()
    image_tags = [skopeo_client.get_image_tags_by_pattern(image, tag_pattern)
                  for image in images]

    if len(image_tags) == 0:
        raise IndexError(f"Could not find any tags matching pattern `{tag_pattern}` for images `{images}`")

    tag = find_first_common_element(image_tags)
    if tag is None:
        raise ValueError(f"Could not find common tag for images {images}")

    return tag.removeprefix(tag_prefix)


def main():
    full_release = args.full or os.environ.get("NIGHTLY_RELEASE", "false") == "true"

    with open(args.deployment, "r") as f:
        deployment = yaml.safe_load(f)

    for rep in deployment:
        if rep == "openshift-assisted/assisted-ui":
            # for UI we're only updating when new releases are being published
            github_client = github.Github()
            ui_repo = github_client.get_repo(rep)
            latest_release = ui_repo.get_latest_release()
            hash = ui_repo.get_commit(latest_release.tag_name).sha

        elif full_release:
            hash = get_ref_by_docker_image(deployment[rep]['images'])

        else:
            hash = os.environ.get(rep, None)

        if not hash:
            continue
        update_hash.update_hash(deployment_yaml=args.deployment, repo=rep, hash=hash)


if __name__ == "__main__":
    main()
