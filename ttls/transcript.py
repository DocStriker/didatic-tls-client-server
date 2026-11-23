import hashlib


class HandshakeTranscript:
    """Acumula as mensagens de handshake (já serializadas) e tira o hash delas.

    O hash do transcript amarra as chaves e os Finished a TUDO que foi
    negociado: se alguém alterou qualquer byte de um Hello, os dois lados
    passam a ter hashes diferentes e o Finished não confere.
    """

    def __init__(self):
        self._messages = []

    def add(self, message: bytes) -> None:
        self._messages.append(message)

    def digest(self) -> bytes:
        return hashlib.sha256(b"".join(self._messages)).digest()

    def hexdigest(self) -> str:
        return self.digest().hex()
