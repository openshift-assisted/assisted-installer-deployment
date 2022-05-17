#!/usr/bin/env python3
from datetime import datetime
import statistics
import argparse

from github import Github

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
    duration = (endDate - createDate).days*3600*24 + (endDate - createDate).seconds
    return user, duration


def main(repos, status, netrc, hours_resolution):
    username, password = get_credentials_from_netrc(
        hostname="github.com",
        netrc_file=netrc,
    )
    gclient = Github(username, password)

    repos = [gclient.get_repo(repo) for repo in repos]

    prs = [pr for repo in repos for pr in repo.get_pulls(state=status) if pr.merged_at is not None]
    print(f"number of PRs: {len(prs)}")

    stats = {}
    for pr in prs:
        user, duration = add_pr_duration(pr)
        if user in stats:
            stats[user].append(duration)
        else:
            stats[user] = [duration]

    print_stats(stats, hours_resolution)


def print_stats(stats, hours_resolution=False):
    print("")
    print("|------------------------|----------------|----------------|----------------|----------------|----------------|")
    print("|                   user |    average (h) |     median (h) |        max (h) |        min (h) |      PRs count |")
    print("|------------------------|----------------|----------------|----------------|----------------|----------------|")

    resolution = 60.0 * 60.0 * 24.0
    if hours_resolution:
        resolution = 60.0 * 60.0

    stats = dict(sorted(stats.items(), key=lambda item: len(item[1])))

    for user in stats:
        pr_open_durations = stats[user]
        pr_count = len(pr_open_durations)
        average_duration_seconds = sum(pr_open_durations) / pr_count
        average_duration = average_duration_seconds / resolution

        max_duration = max(pr_open_durations) / resolution
        min_duration = min(pr_open_durations) / resolution
        median_duration = statistics.median(pr_open_durations) / resolution

        print("| %22s | %14.4f | %14.4f | %14.4f | %14.4f | %14d |" %
              (user, average_duration, median_duration, max_duration, min_duration, pr_count))

    print("|------------------------|----------------|----------------|----------------|----------------|----------------|")


if __name__ == "__main__":
    valid_status = ['closed', 'open', 'merged']
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--repos", required=True, help="repo names, separated by commas. For example 'openshift/assisted-service'")
    parser.add_argument("-s", "--status", default="open", choices=valid_status, help="PR status to filter")
    parser.add_argument("--netrc", required=False, help="netrc file")
    parser.add_argument("-H", "--hours-resolution", action="store_true", help="Output stats in resolution of hours")
    args = parser.parse_args()

    main(repos=args.repos.split(","), status=args.status, netrc=args.netrc, hours_resolution=args.hours_resolution)
