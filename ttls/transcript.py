import hashlib

class HandshakeTranscript:
    def __init__(self):
        self._messages = []

    def add(self, message: bytes) -> None:
        self._messages.append(message)

    def digest(self) -> bytes:
        data = b"".join(self._messages)

        return hashlib.sha256(data).digest()

    def hexdigest(self) -> str:
        return self.digest().hex()