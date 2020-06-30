#!/usr/bin/python3

import argparse
import logging
import sys
import yaml
from release import gittools


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
        manifest_contnet = yaml.safe_load(manifest_file)
    logger.info("Creating %s tag for all repos", tag)
    gtools = gittools.GitApiUtils()
    repos_with_tag = []
    for repo in manifest_contnet.keys():
        if gtools.tag_exists(repo, tag):
            repos_with_tag.append(repo)
    if repos_with_tag:
        if delete_if_exists:
            for repo in repos_with_tag:
                gtools.delete_tag(repo, tag)
        else:
            raise ValueError("%s tag already exists in these repositories %s" % (tag, repos_with_tag))
    for repo, repo_info in manifest_contnet.items():
        logger.info("Creating %s tag in repo: %s, revision: %s", tag, repo, repo_info['revision'])
        gtools.create_tag(repo, repo_info['revision'], tag)
    logger.info("Done")


def main():
    parser = argparse.ArgumentParser(description='Tag all assisted installer repositories')
    parser.add_argument('-t', '--tag', help='The tag to create', type=str, required=True)
    parser.add_argument('-f', '--force', help='Delete tag if oreviosly exists', action="store_true")
    parser.add_argument('-m', '--manifest', help='Path to manifest file', type=str, default="./assisted-installer.yaml")
    args = parser.parse_args()
    tag_all(args.manifest, args.tag, args.force)


if __name__ == "__main__":
    main()
