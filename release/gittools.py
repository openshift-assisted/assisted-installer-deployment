import logging
import netrc
import os

import requests


class GitApiUtils:
    GIT_API_PREFIX = "https://api.github.com"
    GIT_API_REPOS = f"{GIT_API_PREFIX}/repos"
    GIT_REPO_TREES_URI_PREFIX = "/git/trees"
    GIT_REQUEST_TIMEOUT = 120

    def __init__(self):
        self._github_user = os.getenv("GITHUB_USER", None)
        self._github_password = os.getenv("GITHUB_PASS", None)
        if self._github_user and self._github_password:
            self._credentials = (self._github_user, self._github_password)
        else:
            self._credentials = self._get_credentials_from_netrc()

    def create_tag(self, repo, revision, tag):
        """Create a tag for a specific revision

        :param str repo: repository name
        :param str revision:  branch name or commit sha in the repository
        :param str tag: The tag to create (e.g. 'v1.0.0')

        :return str: tag url
        """
        logging.info("Creating tag %s for repository: %s, revision: %s", tag, repo, revision)
        data = {
            "tag": tag,
            "object": revision,
            "message": f"release {tag}",
            "type": "commit",
        }
        url = f"{self.GIT_API_REPOS}/{repo}/git/tags"
        response = requests.post(url, auth=self._credentials, json=data, timeout=self.GIT_REQUEST_TIMEOUT)
        response.raise_for_status()
        tag_obj = response.json()
        ref_data = {"ref": f"refs/tags/{tag}", "sha": tag_obj.get("sha")}
        ref_url = f"{self.GIT_API_REPOS}/{repo}/git/refs"
        response = requests.post(ref_url, auth=self._credentials, json=ref_data, timeout=self.GIT_REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json().get("url")

    def delete_tag(self, repo, tag):
        """Delete a tag from a repository

        :param str repo: repository name
        :param str tag: The tag to delete (e.g. 'v1.0.0')
        """
        logging.info("Deleting tag %s in repository %s", tag, repo)
        ref_url = f"{self.GIT_API_REPOS}/{repo}/git/refs/tags/{tag}"
        response = requests.delete(ref_url, auth=self._credentials, timeout=self.GIT_REQUEST_TIMEOUT)
        response.raise_for_status()

    def list_tags(self, repo):
        """Get the list of tags from a repository

        :param str repo: repository name

        :return list: List of tags
        """
        logging.info("Listing tags in repository: %s", repo)
        ref_url = f"{self.GIT_API_REPOS}/{repo}/git/refs/tags"
        response = requests.get(ref_url, auth=self._credentials, timeout=self.GIT_REQUEST_TIMEOUT)
        response.raise_for_status()
        return [i.get("ref").split("/", 2)[-1] for i in response.json()]

    def tag_exists(self, repo, tag):
        """Check if a tag exists in a repository

        :param str repo: repository name
        :param str tag: The tag to delete (e.g. 'v1.0.0')

        :return bool: True if tag exists else false
        """
        return tag in self.list_tags(repo)

    @staticmethod
    def _get_credentials_from_netrc(netrc_path=None):
        """Get the user credentials from .netrc file"""
        ncfile = netrc.netrc(netrc_path or os.path.expanduser("~/.netrc"))
        credentials = ncfile.authenticators("github.com")

        if credentials is None:
            raise RuntimeError("No credentials for 'github.com' has been found under ~/.netrc")

        return credentials[0], credentials[2]
