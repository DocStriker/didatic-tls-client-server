from collections import deque
import threading
import time

class ReceiveBuffer:
    def __init__(self):
        self._buffer = deque()
        self._lock = threading.Lock()

    def push(self, data: bytes):
        with self._lock:
            self._buffer.append(data)

    def pop(self) -> bytes:
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