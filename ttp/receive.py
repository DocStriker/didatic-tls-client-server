# =============================================================================
# ttp/receive.py
# -----------------------------------------------------------------------------
# ReceiveBuffer is a small thread-safe FIFO queue used to hand data from the
# TTPConnection's background receive thread (see connection._receive_loop)
# over to whatever application thread calls connection.recv(). It decouples
# "packets are arriving on the network" from "the application asked for
# data", which is exactly the role a socket's kernel receive buffer plays
# for real TCP/UDP sockets.
# =============================================================================

from collections import deque
import threading
import time

class ReceiveBuffer:
    def __init__(self):
        self._buffer = deque()
        self._lock = threading.Lock()  # protects _buffer from concurrent access

    def push(self, data: bytes):
        # Called by the receive thread whenever a new in-order DATA
        # payload has been accepted.
        with self._lock:
            self._buffer.append(data)

    def pop(self) -> bytes:
        # Called by the application thread (connection.recv()). Busy-waits
        # (poll + short sleep) until data is available -- simple, but not
        # as efficient as a condition variable; acceptable for a didactic
        # implementation with low traffic volume.
        while True:
            with self._lock:
                if self._buffer:
                    return self._buffer.popleft()

            time.sleep(0.01)

    @property
    def empty(self):
        with self._lock:
            return len(self._buffer) == 0

    def clear(self):
        with self._lock:
            self._buffer.clear()

    def __len__(self):
        with self._lock:
            return len(self._buffer)
