#!/usr/bin/env python
# pylint: disable=invalid-name,bare-except

# Script to output table with the count of triage related tickets, grouped by week for the past 3 weeks

import json
import tabulate
import jira_cmd


class TriageStats:
    def __init__(self):
        parser = jira_cmd.build_parser()

        def my_exit(msg):
            pass
        parser.error = my_exit
        self.args = parser.parse_args([])
        self.args.print_json = True
        self.args.linked_issues = True
        self.stats = {}

    def add_past_week(self, past_week_num):
        self.args.search_query = (
            f'project = MGMT AND component = "Assisted-installer Triage AND '
            f'labels in (AI_CLOUD_TRIAGE) AND created < -{past_week_num - 1}w AND created >= -{past_week_num}w')
        if past_week_num == 1:
            self.args.search_query = (
                'project = MGMT AND component = "Assisted-installer Triage" AND '
                'labels in (AI_CLOUD_TRIAGE) AND created >= -1w')

        j = jira_cmd.main(self.args)
        data = json.loads(j)
        for i in data:
            if i['key'] not in self.stats:
                self.stats[i['key']] = dict(key=i['key'], summary=i['summary'], status=i['status'])
            self.stats[i['key']]['week -{}'.format(past_week_num)] = i['count']


if __name__ == "__main__":
    a = TriageStats()
    a.add_past_week(1)
    a.add_past_week(2)
    a.add_past_week(3)

    values = [x for x in a.stats.values()]
    print(tabulate.tabulate(values, headers="keys", tablefmt="github"))
