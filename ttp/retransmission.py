# =============================================================================
# ttp/retransmission.py
# -----------------------------------------------------------------------------
# RetransmissionManager combines a TTPTimer with a retry counter, giving
# TTPConnection a simple "has this packet been waiting too long, and have
# we already tried resending it too many times?" utility. This is the
# didactic equivalent of TCP's retransmission timeout (RTO) + retry-limit
# behaviour, using a fixed timeout instead of TCP's adaptive RTT-based one.
# =============================================================================

from ttp.timer import TTPTimer

class RetransmissionManager:
    def __init__(self, timeout: float = 1.0, max_retries: int =5):
        self.timer = TTPTimer(timeout)
        self.max_retries = max_retries
        self.timeout = timeout
        self.retries = 0

    def start(self):
        # Called when we begin waiting for an ACK on a *fresh* packet:
        # resets the retry counter and (re)starts the timer.
        self.retries = 0
        self.timer.start()

    def restart(self):
        # Called after a retransmission: keeps counting retries (so we can
        # eventually give up) while resetting the timer for another round.
        self.retries += 1
        self.timer.start()

    def stop(self):
        # Called once the awaited ACK finally arrives.
        self.timer.stop()

    @property
    def expired(self):
        return self.timer.expired

    @property
    def running(self):
        return self.timer.running

    @property
    def exhausted(self):
        # True once we've retried max_retries times without success --
        # signals the caller to give up (e.g. treat the connection as dead).
        return self.retries >= self.max_retries
