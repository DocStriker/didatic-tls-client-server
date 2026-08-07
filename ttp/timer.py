import time

class TTPTimer:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self.started_at = None

    def start(self):
        self.started_at = time.monotonic()

    def stop(self):
        self.started_at = None

    @property
    def running(self):
        return self.started_at is not None

    @property
    def expired(self):
        if not self.running:
            return False

        return (time.monotonic() - self.started_at) >= self.timeout