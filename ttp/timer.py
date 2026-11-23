# =============================================================================
# ttp/timer.py
# -----------------------------------------------------------------------------
# A tiny, single-purpose stopwatch. It does not run any thread or callback
# by itself -- the connection's internal loop polls `.expired` on every tick
# (see TTPConnection._on_tick).
# =============================================================================

import time


class TTPTimer:
    def __init__(self, timeout: float = 1.0, clock=time.monotonic):
        self.timeout = timeout
        self.started_at = None  # None means "not currently running"
        self._clock = clock

    def start(self, timeout: float | None = None):
        # time.monotonic() is used instead of time.time() because it can
        # never go backwards (immune to system clock adjustments), which
        # matters for reliable timeout measurement.
        if timeout is not None:
            self.timeout = timeout

        self.started_at = self._clock()

    def stop(self):
        self.started_at = None

    @property
    def running(self):
        return self.started_at is not None

    @property
    def elapsed(self) -> float:
        if not self.running:
            return 0.0

        return self._clock() - self.started_at

    @property
    def remaining(self) -> float:
        if not self.running:
            return float("inf")

        return max(0.0, self.timeout - self.elapsed)

    @property
    def expired(self):
        # A timer that was never started can never be "expired".
        if not self.running:
            return False

        return self.elapsed >= self.timeout
