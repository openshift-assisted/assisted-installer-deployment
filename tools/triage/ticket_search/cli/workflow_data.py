import logging


class WorkflowData(dict):
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def map_field_to_ticket(self, issue_id: str, field_name, field_value: str):
        if "issue_ids" not in self:
            self["issue_ids"] = {}
        if issue_id not in self["issue_ids"]:
            self["issue_ids"] = {}
        self["issue_ids"][issue_id][field_name] = field_value

    def increment_count(self, label: str, stage: str, key: str):
        if f"{label}_counts_{stage}" not in self:
            self[f"{label}_counts_{stage}"] = {}
        if key not in self[f"{label}_counts_{stage}"]:
            self[f"{label}_counts_{stage}"][key] = 1
        else:
            self[f"{label}_counts_{stage}"][key] += 1
