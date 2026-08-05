from ttp.timer import TTPTimer

class RetransmissionManager:

    def __init__(
        self,
        timeout: float = 1.0,
        max_retries: int = 5,
    ):

        self.timer = TTPTimer(timeout)

        self.max_retries = max_retries

        self.timeout = timeout

        self.retries = 0

    def start(self):
        self.retries = 0
        self.timer.start()

    def restart(self):
        self.retries += 1
        self.timer.start()

    def stop(self):
        self.timer.stop()

    @property
    def expired(self):
        return self.timer.expired

    @property
    def exhausted(self):
        return self.retries >= self.max_retries