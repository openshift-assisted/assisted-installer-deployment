#!/usr/bin/env python3
from datetime import datetime
import statistics
import argparse

from github import Github, GithubException

from utils import get_credentials_from_netrc


def add_pr_duration(pr):
    created = pr.created_at
    end = pr.merged_at
    state = pr.state
    user = pr.user.login

    if state == "open":
        end = datetime.now()
    if state == "closed":
        end = pr.closed_at

    createDate = created
    endDate = end
    duration = (endDate - createDate).days * 3600 * 24 + (endDate - createDate).seconds
    return user, duration


def main(args):
    username, password = get_credentials_from_netrc(
        hostname="github.com",
        netrc_file=args.netrc,
    )
    gclient = Github(username, password)

    try:
        repo = gclient.get_repo(args.repo)
    except GithubException:
        print("Error: cannot find repository: {}".format(args.repo))
        return

    prs = repo.get_pulls(state=args.status)
    print("number of PRs: {}".format(prs.totalCount))

    stats = {}
    for pr in prs:
        user, duration = add_pr_duration(pr)
        if user in stats:
            stats[user].append(duration)
        else:
            stats[user] = [duration]

    print_stats(stats, args.hours_resolution)


def print_stats(stats, hours_resolution=False):
    print("")
    print(
        "|------------------------|----------------|----------------|----------------|----------------|----------------|"
    )
    print(
        "|                   user |    average (h) |     median (h) |        max (h) |        min (h) |      PRs count |"
    )
    print(
        "|------------------------|----------------|----------------|----------------|----------------|----------------|"
    )

    resolution = 60.0 * 60.0 * 24.0
    if hours_resolution:
        resolution = 60.0 * 60.0

    for user in stats:
        pr_open_durations = stats[user]
        pr_count = len(pr_open_durations)
        average_duration_seconds = sum(pr_open_durations) / pr_count
        average_duration = average_duration_seconds / resolution

        max_duration = max(pr_open_durations) / resolution
        min_duration = min(pr_open_durations) / resolution
        median_duration = statistics.median(pr_open_durations) / resolution

        print(
            "| %22s | %14.4f | %14.4f | %14.4f | %14.4f | %14d |"
            % (user, average_duration, median_duration, max_duration, min_duration, pr_count)
        )
    print(
        "|------------------------|----------------|----------------|----------------|----------------|----------------|"
    )


if __name__ == "__main__":
    valid_status = ["closed", "open"]
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--repo", required=True, help="repo name. For example 'openshift/assisted-service'")
    parser.add_argument("-s", "--status", default="open", choices=valid_status, help="PR status to filter")
    parser.add_argument("--netrc", required=False, help="netrc file")
    parser.add_argument("-H", "--hours-resolution", action="store_true", help="Output stats in resolution of hours")
    args = parser.parse_args()

    main(args)
