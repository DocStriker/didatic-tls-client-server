# =============================================================================
# ttls/alert.py
# -----------------------------------------------------------------------------
# Alertas TTLS (análogo aos alertas do TLS): a forma ORDENADA de dizer ao par
# "vou fechar" (close_notify) ou "deu erro fatal, abortando".
#
# close_notify existe por um motivo de segurança: sem ele, quem só vê o TCP/TTP
# fechar (FIN) não distingue "o par terminou" de "um atacante injetou um FIN
# para TRUNCAR a conversa" (ataque de truncamento).
#
# Formato (2 bytes):  | level (1) | description (1) |
# =============================================================================

import struct
from enum import IntEnum


class AlertLevel(IntEnum):
    WARNING = 1
    FATAL = 2


class AlertDescription(IntEnum):
    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    BAD_RECORD_MAC = 20
    RECORD_OVERFLOW = 22
    HANDSHAKE_FAILURE = 40
    ILLEGAL_PARAMETER = 47
    DECODE_ERROR = 50
    DECRYPT_ERROR = 51
    PROTOCOL_VERSION = 70
    INTERNAL_ERROR = 80


class TTLSError(Exception):
    """Erro do protocolo TTLS."""


class TTLSAlertError(TTLSError):
    """O par enviou um alerta fatal (ou nós detectamos um erro fatal)."""

    def __init__(self, description: AlertDescription, message: str = ""):
        self.description = description
        super().__init__(message or description.name)


class TTLSClosed(TTLSError):
    """O par encerrou ordenadamente (recebemos close_notify)."""


class TTLSTruncated(TTLSError):
    """O transporte acabou SEM close_notify: possível truncamento."""


class Alert:
    FORMAT = "!BB"
    SIZE = struct.calcsize(FORMAT)

    def __init__(self, level: AlertLevel, description: AlertDescription):
        self.level = AlertLevel(level)
        self.description = AlertDescription(description)

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT, self.level, self.description)

    @classmethod
    def unpack(cls, data: bytes) -> "Alert":
        if len(data) != cls.SIZE:
            raise ValueError("Alerta inválido.")

        level, description = struct.unpack(cls.FORMAT, data)

        return cls(level, description)
