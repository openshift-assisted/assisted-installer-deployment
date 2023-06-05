from .workflow_data import WorkflowData


class Command:
    def run(self, workflow_data: WorkflowData):
        NotImplemented

    COMMAND_KEY = NotImplemented
    FRIENDLY_NAME = NotImplemented
