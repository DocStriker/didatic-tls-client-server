# =============================================================================
# ttls/handshake.py
# -----------------------------------------------------------------------------
# Mensagens do handshake TTLS v2. Fluxo (inspirado no TLS 1.3):
#
#   Cliente                                           Servidor
#   ClientHello  (random, suites, X25519 pública) ─────────►
#                ◄───────── ServerHello (random, suite, X25519 pública)
#                ◄───────── ServerAuth  (chave Ed25519 + assinatura)
#   Finished (HMAC do transcript) ─────────────────────────►
#                ◄───────── Finished (HMAC do transcript)
#   ═══════════ dados de aplicação cifrados (AES-256-GCM) ═══════════
#
# Os handshakes ficam em CLARO de propósito: assim o sniffer didático ainda
# consegue mostrar cada mensagem.
# =============================================================================

import struct
from enum import IntEnum


class HandshakeType(IntEnum):
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    FINISHED = 0x03
    SERVER_AUTH = 0x04


class CipherSuite(IntEnum):
    TTLS_NULL = 0x0000                # sem proteção: NUNCA aceita
    TTLS_AES_256_GCM = 0x0001         # X25519 + HKDF-SHA256 + AES-256-GCM
    TTLS_KYBER_AES_256_GCM = 0x0002   # RESERVADA (híbrido pós-quântico): ainda não implementada


SUPPORTED_CIPHER_SUITES = (CipherSuite.TTLS_AES_256_GCM,)


class HandshakeMessage:
    HEADER_FORMAT = "!BI"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, message_type: HandshakeType, payload: bytes):
        self.message_type = HandshakeType(message_type)
        self.payload = payload

    def pack(self) -> bytes:
        return struct.pack(self.HEADER_FORMAT, self.message_type, len(self.payload)) + self.payload

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Handshake message incompleta.")

        message_type, length = struct.unpack(cls.HEADER_FORMAT, data[: cls.HEADER_SIZE])
        payload = data[cls.HEADER_SIZE :]

        if len(payload) != length:
            raise ValueError("Payload da handshake inválido.")

        return cls(HandshakeType(message_type), payload)


class ClientHello:
    """version(1) | random(32) | n_suites(1) | suites(2*n) | key_share(32)"""

    VERSION = 2

    def __init__(self, random: bytes, cipher_suites: list[CipherSuite], key_share: bytes):
        if len(random) != 32 or len(key_share) != 32:
            raise ValueError("random e key_share devem ter 32 bytes.")

        self.version = self.VERSION
        self.random = random
        self.cipher_suites = [CipherSuite(s) for s in cipher_suites]
        self.key_share = key_share

    def pack(self) -> bytes:
        suites = b"".join(struct.pack("!H", s) for s in self.cipher_suites)

        return struct.pack("!B", self.version) + self.random + struct.pack("!B", len(self.cipher_suites)) + suites + self.key_share

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < 1 + 32 + 1 + 32:
            raise ValueError("ClientHello inválido.")

        version = data[0]

        if version != cls.VERSION:
            raise ValueError(f"Versão TTLS não suportada: {version}")

        random = data[1:33]
        count = data[33]
        expected = 1 + 32 + 1 + 2 * count + 32

        if count == 0 or len(data) != expected:
            raise ValueError("ClientHello inválido.")

        offered = struct.unpack(f"!{count}H", data[34 : 34 + 2 * count])
        suites = []

        for value in offered:
            try:
                suites.append(CipherSuite(value))
            except ValueError:
                pass  # suite desconhecida: ignora (negociação)

        return cls(random, suites, data[-32:])


class ServerHello:
    """version(1) | random(32) | cipher_suite(2) | key_share(32)"""

    FORMAT = "!B32sH32s"
    SIZE = struct.calcsize(FORMAT)
    VERSION = 2

    def __init__(self, random: bytes, cipher_suite: CipherSuite, key_share: bytes):
        if len(random) != 32 or len(key_share) != 32:
            raise ValueError("random e key_share devem ter 32 bytes.")

        self.version = self.VERSION
        self.random = random
        self.cipher_suite = CipherSuite(cipher_suite)
        self.key_share = key_share

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT, self.version, self.random, self.cipher_suite, self.key_share)

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) != cls.SIZE:
            raise ValueError("ServerHello inválido.")

        version, random, suite, key_share = struct.unpack(cls.FORMAT, data)

        if version != cls.VERSION:
            raise ValueError(f"Versão TTLS não suportada: {version}")

        return cls(random, CipherSuite(suite), key_share)


class ServerAuth:
    """
    Prova de identidade do servidor: chave pública Ed25519 (32) + assinatura
    (64) sobre H(ClientHello||ServerHello). Vazia = servidor anônimo.
    """

    SIZE = 32 + 64

    def __init__(self, public_key: bytes = b"", signature: bytes = b""):
        self.public_key = public_key
        self.signature = signature

    @property
    def anonymous(self) -> bool:
        return not self.public_key

    def pack(self) -> bytes:
        return self.public_key + self.signature

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) == 0:
            return cls()

        if len(data) != cls.SIZE:
            raise ValueError("ServerAuth inválido.")

        return cls(data[:32], data[32:])


class Finished:
    VERIFY_DATA_SIZE = 32

    def __init__(self, verify_data: bytes):
        if len(verify_data) != self.VERIFY_DATA_SIZE:
            raise ValueError("Verify data deve possuir 32 bytes.")

        self.verify_data = verify_data

    def pack(self) -> bytes:
        return self.verify_data

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) != cls.VERIFY_DATA_SIZE:
            raise ValueError("Finished inválido.")

        return cls(data)


def select_cipher_suite(offered: list[CipherSuite]) -> CipherSuite:
    """Escolhe a primeira suite OFERECIDA que também SUPORTAMOS (lista do cliente manda)."""
    for suite in offered:
        if suite in SUPPORTED_CIPHER_SUITES:
            return suite

    raise ValueError("Nenhuma cipher suite em comum.")
