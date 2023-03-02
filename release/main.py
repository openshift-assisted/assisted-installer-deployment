#!/usr/bin/python3

import argparse
import logging
import sys

import requests
import yaml

from release import gittools

IMAGE_TAGS_URL_TEMPLATE = "https://quay.io/v1/repositories/ocpmetal/{}/tags"


def get_logger():
    logging.getLogger("requests").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    log = logging.getLogger('')
    log.setLevel(logging.DEBUG)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    log.addHandler(stream_handler)
    return log


def tag_all(manifest, tag, delete_if_exists=False):
    '''Read the manifest file and create a tag for each entry'''
    logger = get_logger()
    with open(manifest, 'r') as manifest_file:
        manifest_content = yaml.safe_load(manifest_file)
    logger.info("Creating %s tag for all backend repos", tag)
    gtools = gittools.GitApiUtils()
    repos_with_tag = []
    for repo, component_data in manifest_content.items():
        if "backend" not in component_data["categories"]:
            continue

        if gtools.tag_exists(repo, tag):
            repos_with_tag.append(repo)
    if repos_with_tag:
        if delete_if_exists:
            for repo in repos_with_tag:
                gtools.delete_tag(repo, tag)
        else:
            raise ValueError(f"{tag} tag already exists in these repositories {repos_with_tag}")

    for repo, component_data in manifest_content.items():
        if "backend" not in component_data["categories"]:
            continue

        logger.info("Creating %s tag in repo: %s, revision: %s", tag, repo, component_data['revision'])
        gtools.create_tag(repo, component_data['revision'], tag)

    logger.info("Done")


def untag_all(manifest, tag):
    '''Read the manifest file and delete the tag for each entry'''
    logger = get_logger()
    with open(manifest, 'r') as manifest_file:
        manifest_contnet = yaml.safe_load(manifest_file)
    logger.info("Deleting %s tag from all repos", tag)
    gtools = gittools.GitApiUtils()
    repos_with_tag = []
    for repo in manifest_contnet.keys():
        if gtools.tag_exists(repo, tag):
            repos_with_tag.append(repo)
    if repos_with_tag:
        for repo in repos_with_tag:
            logger.info("Deleting %s tag from %s", tag, repo)
            gtools.delete_tag(repo, tag)


def check_images_exists(manifest, tag):
    '''Read the manifest file and check for each repository if all images exists with the given tag
    Raise exception in case one or more images are missing
    '''
    logger = get_logger()
    with open(manifest, 'r') as manifest_file:
        manifest_contnet = yaml.safe_load(manifest_file)
    logger.info("Checking images with %s tag exists for all repos", tag)
    missing_images = []
    for repo, repo_info in manifest_contnet.items():
        for image in repo_info["images"]:
            required_sha = repo_info["revision"]
            if not image_exists(image, tag, required_sha):
                logger.warning("Missing image %s from repo: %s", image, repo)
                missing_images.append(image)

    if missing_images:
        raise RuntimeError(f"Missing images {missing_images}")


def image_exists(image_name, tag, required_sha):
    '''Get the image tags list and find another tag matching the required sha with the same image id'''
    url = IMAGE_TAGS_URL_TEMPLATE.format(image_name)
    # get the image tags
    response = requests.get(url=url, timeout=60)
    # if list tags failed return False
    if not response.ok:
        return False
    tag_to_image_id_map = response.json()
    # get the image_id for the required tag
    required_image_id = tag_to_image_id_map.get(tag)
    # if the required tag isn't in the tag list, return False
    if not required_image_id:
        return False
    for image_tag, image_id in tag_to_image_id_map.items():
        # find a an image with the required_image_id
        if image_id == required_image_id:
            # if the image_tag match the required_sha - return True
            if image_tag == required_sha:
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description='Tag all assisted installer repositories')
    parser.add_argument('-t', '--tag', help='The tag to create', type=str, required=True)
    tag_options = parser.add_mutually_exclusive_group()
    tag_options.add_argument('-d', '--delete', help='Delete the tag from all repos', action="store_true")
    tag_options.add_argument('-f', '--force', help='Override the tag if previously exists', action="store_true")
    tag_options.add_argument('-c', '--check', help='Check if the repository images with the given tag exists', action="store_true")
    parser.add_argument('-m', '--manifest', help='Path to manifest file', type=str, default="./assisted-installer.yaml")
    args = parser.parse_args()
    if args.delete:
        untag_all(args.manifest, args.tag)
    elif args.check:
        check_images_exists(args.manifest, args.tag)
    else:
        tag_all(args.manifest, args.tag, args.force)


if __name__ == "__main__":
    main()
