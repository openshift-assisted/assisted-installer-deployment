import datetime


class Timer:
    def __init__(self):
        self.cumulative_duration = 0
        self.reset_and_start()

    def reset_and_start(self):
        self.start_time = datetime.datetime.now()

    def end(self) -> int:
        self.end_time = datetime.datetime.now()
        duration_interval = self.end_time - self.start_time
        self.duration = duration_interval.total_seconds()
        self.cumulative_duration += self.duration
        return self.duration

    def get_start_time(self):
        return self.start_time

    def get_end_time(self):
        return self.end_time

    def get_duration(self):
        return self.duration

    def get_cumulative_duration(self):
        return self.cumulative_duration

    def summarise(self) -> str:
        return f"Start time: {self.start_time}, End time: {self.end_time}, Duration (seconds): {self.duration}"
