import struct
from enum import IntEnum

class HandshakeType(IntEnum):
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    FINISHED = 0x03

class CipherSuite(IntEnum):
    TTLS_NULL = 0x0000
    TTLS_KYBER = 0x0001

class ClientHello:

    FORMAT = "!BH"
    SIZE = struct.calcsize(FORMAT)

    VERSION = 1

    def __init__(self, cipher_suite: CipherSuite):
        self.version = self.VERSION
        self.cipher_suite = CipherSuite(cipher_suite)

    def pack(self) -> bytes:
        return struct.pack(
            self.FORMAT,
            self.version,
            self.cipher_suite,
        )

    @classmethod
    def unpack(cls, data: bytes):

        if len(data) != cls.SIZE:
            raise ValueError(
                "ClientHello inválido."
            )

        version, cipher_suite = struct.unpack(
            cls.FORMAT,
            data,
        )

        if version != cls.VERSION:
            raise ValueError(
                f"Versão TTLS não suportada: {version}"
            )

        return cls(
            CipherSuite(cipher_suite)
        )

class ServerHello:

    FORMAT = "!BH"
    SIZE = struct.calcsize(FORMAT)
    

    VERSION = 1

    def __init__(self, cipher_suite: CipherSuite):
        self.version = self.VERSION
        self.cipher_suite = CipherSuite(cipher_suite)

    def pack(self) -> bytes:
        return struct.pack(
            self.FORMAT,
            self.version,
            self.cipher_suite,
        )

    @classmethod
    def unpack(cls, data: bytes):

        if len(data) != cls.SIZE:
            raise ValueError(
                "ServerHello inválido."
            )

        version, cipher_suite = struct.unpack(
            cls.FORMAT,
            data,
        )

        if version != cls.VERSION:
            raise ValueError(
                f"Versão TTLS não suportada: {version}"
            )

        return cls(
            CipherSuite(cipher_suite)
        )
    
class Finished:

    FORMAT = "!B"
    SIZE = struct.calcsize(FORMAT)

    VALUE = 0x01

    def pack(self) -> bytes:
        return struct.pack(
            self.FORMAT,
            self.VALUE
        )

    @classmethod
    def unpack(cls, data: bytes):

        if len(data) != cls.SIZE:
            raise ValueError(
                "Finished inválido."
            )

        value, = struct.unpack(
            cls.FORMAT,
            data
        )

        if value != cls.VALUE:
            raise ValueError(
                "Finished inválido."
            )

        return cls()

def select_cipher_suite(offered: CipherSuite) -> CipherSuite:
        SUPPORTED_CIPHER_SUITES = {
            CipherSuite.TTLS_KYBER,
        }

        if offered not in SUPPORTED_CIPHER_SUITES:
            raise ValueError(
                f"Cipher suite não suportada: {offered}"
            )

        return offered