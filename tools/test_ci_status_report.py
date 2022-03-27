import os
import json
from ci_status_report import filter_jobs
from unittest.mock import Mock

FIXTURE_PROW_JOB_STATUSES_RESPONSE_PATH = "fixtures/prow_job_statuses.json"
FIXTURE_PROW_JOB_STATUSES_RESPONSE_N_ITEMS = 826


class TestCiStatusReport:
    def test_filter_jobs(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        response = Mock()

        with open(f"{dir_path}/{FIXTURE_PROW_JOB_STATUSES_RESPONSE_PATH}", "r") as fixture_file:
            json_text = json.load(fixture_file)

            response.json.side_effect = [json_text]
            jobs = filter_jobs(response)
            assert(
                len(list(jobs))
                ==
                FIXTURE_PROW_JOB_STATUSES_RESPONSE_N_ITEMS)
