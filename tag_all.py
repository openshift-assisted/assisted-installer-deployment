#!/usr/bin/python3

import argparse
import gittools
import yaml
import logging
import sys

def get_logger():
    logging.getLogger("requests").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    log = logging.getLogger('')
    log.setLevel(logging.DEBUG)
    format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(format)
    log.addHandler(ch)
    return log


def main(manifest, tag):
    '''Read the manifest file and create a tag for each entry'''
    logger = get_logger()
    with open(manifest, 'r') as manifest_file:
        manifest_contnet = yaml.safe_load(manifest_file)
    logger.info("Creating %s tag for all repos", tag)
    gtools = gittools.GitApiUtils()
    for repo, revision in manifest_contnet.items():
        logger.info("Creating %s tag in repo: %s, revision: %s", tag, repo, revision)
        gtools.create_tag(repo, revision, tag)
    logger.info("Done")
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Tag all assisted installer repositories')
    parser.add_argument('-t', '--tag', help='The tag to create', type=str, required=True)
    parser.add_argument('-m', '--manifest', help='Path to manifest file',type=str, default="./assisted-installer.yaml")
    args = parser.parse_args()
    main(args.manifest, args.tag)
