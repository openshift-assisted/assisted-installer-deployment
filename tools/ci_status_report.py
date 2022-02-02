#!/usr/bin/env python3
import os
import enum
import argparse
import collections
import datetime
import dataclasses
import itertools
import typing

import requests
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator


PROW_JOBS_STATUSES = "https://prow.ci.openshift.org/prowjobs.js?omit=annotations,labels,decoration_config,pod_spec"
SLACK_FILES_UPLOAD = "https://slack.com/api/files.upload"
TRACKED_REPOSITORIES = list(itertools.chain(
    itertools.product(
        ("openshift",), (
            "assisted-test-infra",
            "assisted-service",
            "assisted-image-service",
            "assisted-installer",
            "assisted-installer-agent",
            "cluster-api-provider-agent",
        )),
    itertools.product(
        ("openshift-assisted",), (
            "assisted-installer-deployment",
            "assisted-events-scrape",
        )),
))


class JobState(enum.Enum):
    TRIGGERED = "triggered"  # job created but not yet scheduled
    PENDING = "pending"  # job is currently running
    SUCCESS = "success"  # job completed without any error
    FAILURE = "failure"  # job completed with errors
    ABORTED = "aborted"  # prow killed the job early (new commit pushed, perhaps)
    ERROR = "error"  # job could not schedule (bad config, perhaps)


class JobType(enum.Enum):
    PRESUBMIT = "presubmit"
    POSTSUBMIT = "postsubmit"
    PERIODIC = "periodic"
    BATCH = "batch"


STATE_TO_COLOR = {
    JobState.SUCCESS: "#06D6A0",
    JobState.ABORTED: "#118AB2",
    JobState.PENDING: "#FFD166",
    JobState.ERROR: "pink",
    JobState.FAILURE: "#EF476F",
}


@dataclasses.dataclass
class Job:
    type: JobType
    name: str
    organization: str
    repository: str
    base_ref: str
    state: JobState
    url: str
    start_time: datetime.datetime
    completion_time: typing.Optional[datetime.datetime]


def filter_jobs(response: requests.Response) -> typing.Iterator[Job]:
    """Going over all jobs the last 24 hours and filtering only ones relevant to our repos."""
    for document in response.json()["items"]:
        spec = document.get("spec", {})
        all_refs = spec.get("extra_refs", [])

        refs = spec.get("refs")
        if refs is not None:
            all_refs.append(refs)

        for ref in all_refs:
            organization = ref["org"]
            repository = ref["repo"]
            base_ref = ref["base_ref"]
            if (organization, repository) in TRACKED_REPOSITORIES:
                break

        else:
            continue

        status = document["status"]
        job = Job(
            type=JobType(spec["type"]),
            name=spec["job"].replace("pull-ci-openshift-", ""),
            organization=organization,
            repository=repository,
            base_ref=base_ref,
            state=JobState(status["state"]),
            url=status["url"],
            start_time=status["startTime"],
            completion_time=status.get("completionTime"),
        )

        if job.type != JobType.PERIODIC and not job.name.startswith("rehearse"):
            yield job


def get_jobs_statistics() -> typing.Dict[str, collections.Counter]:
    """Query prow's service to gather statistics about all relevant jobs."""
    response = requests.get(PROW_JOBS_STATUSES)
    response.raise_for_status()

    status_counters = collections.defaultdict(collections.Counter)
    for job in filter_jobs(response):
        status_counters[job.name].update([job.state])

    # removing jobs that have no problems
    for job, counters in list(status_counters.items()):
        if counters[JobState.ERROR] == 0 and counters[JobState.FAILURE] == 0:
            del status_counters[job]

    return status_counters


def print_statistics(status_counters: typing.Dict[str, collections.Counter]) -> None:
    """Print statistics for each job."""
    for job, states in status_counters.items():
        print(f"{job}:")
        print("\t", end="")
        for state, count in states.items():
            print(f"{state}: {count}", end="\t")

        print()


def draw_figure(status_counters: typing.Dict[str, collections.Counter]):
    """Draw graph of all jobs and their state segmentation."""
    fig, ax = plt.subplots(figsize=(18, 10))
    ax.set_title("States count by job")
    ax.set_xlabel("Count")
    ax.set_ylabel("Job")

    # this allows us to stack bars one on top of the other
    stacked_sum = np.zeros(len(list(status_counters.keys())))

    for state, color in STATE_TO_COLOR.items():
        data = [counters[state] for counters in status_counters.values()]
        ax.barh(
            list(status_counters.keys()),
            data,
            label=state,
            color=color,
            left=stacked_sum,
        )

        stacked_sum += data

    ax.legend()
    plt.subplots_adjust(left=0.6)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    fig.tight_layout()


def ci_status_report(channel: str, auth_bearer: str) -> None:
    """Grab job statistics from past 24 hours, and either display it or send to slack."""
    status_counters = get_jobs_statistics()

    print_statistics(status_counters)

    draw_figure(status_counters)
    plt.savefig("/tmp/jobs.png")

    if channel is None:
        plt.show()
    else:
        with open("/tmp/jobs.png", "rb") as image:
            response = requests.post(
                SLACK_FILES_UPLOAD,
                headers={"Authorization": f"Bearer {auth_bearer}"},
                files={
                    "file": (image.name, image),
                    "initial_comment": (None, "Daily jobs status"),
                    "channels": (None, channel),
                }
            )
            response.raise_for_status()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel", default=os.environ.get("SLACK_CHANNEL"),
                        help="Slack channel for posting the information. Not specifying implies dry-run")
    parser.add_argument("--auth-bearer", default=os.environ.get("SLACK_AUTH_BEARER"),
                        help="Slack OAuth token of the bot/user.")
    args = parser.parse_args()

    ci_status_report(args.channel, args.auth_bearer)


if __name__ == "__main__":
    main()
