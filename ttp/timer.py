# =============================================================================
# ttp/timer.py
# -----------------------------------------------------------------------------
# A tiny, single-purpose stopwatch. It does not run any thread or callback
# by itself -- callers are expected to poll `.expired` in their own loop
# (see TTPConnection._flush_window / wait_for_acks). This "polling timer"
# style keeps the whole TTP implementation single-threaded and easy to
# reason about (aside from the one background receive thread).
# =============================================================================

import time

class TTPTimer:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self.started_at = None  # None means "not currently running"

    def start(self):
        # time.monotonic() is used instead of time.time() because it can
        # never go backwards (immune to system clock adjustments), which
        # matters for reliable timeout measurement.
        self.started_at = time.monotonic()

    def stop(self):
        self.started_at = None

    @property
    def running(self):
        return self.started_at is not None

    @property
    def expired(self):
        # A timer that was never started can never be "expired".
        if not self.running:
            return False

        return (time.monotonic() - self.started_at) >= self.timeout
