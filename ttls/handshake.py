import struct
from enum import IntEnum

class HandshakeType(IntEnum):
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    FINISHED = 0x03

class CipherSuite(IntEnum):
    TTLS_NULL = 0x0000
    TTLS_AES_256_GCM = 0x0001
    TTLS_KYBER_AES_256_GCM = 0x0002

class HandshakeMessage:
    HEADER_FORMAT = "!BI"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, message_type: HandshakeType, payload: bytes):
        self.message_type = HandshakeType(message_type)
        self.payload = payload

    def pack(self) -> bytes:
        header = struct.pack(
            self.HEADER_FORMAT,
            self.message_type,
            len(self.payload),
        )

        return header + self.payload

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Handshake message incompleta.")

        message_type, length = struct.unpack(
            cls.HEADER_FORMAT,
            data[:cls.HEADER_SIZE],
        )

        payload = data[cls.HEADER_SIZE:]

        if len(payload) != length:
            raise ValueError("Payload da handshake inválido.")

        return cls(
            HandshakeType(message_type),
            payload,
        )

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
            raise ValueError("ClientHello inválido.")

        version, cipher_suite = struct.unpack(
            cls.FORMAT,
            data,
        )

        if version != cls.VERSION:
            raise ValueError(f"Versão TTLS não suportada: {version}")

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
            raise ValueError("ServerHello inválido.")

        version, cipher_suite = struct.unpack(
            cls.FORMAT,
            data,
        )

        if version != cls.VERSION:
            raise ValueError(f"Versão TTLS não suportada: {version}")

        return cls(
            CipherSuite(cipher_suite)
        )
    
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

def select_cipher_suite(offered: CipherSuite) -> CipherSuite:
        SUPPORTED_CIPHER_SUITES = {CipherSuite.TTLS_AES_256_GCM, CipherSuite.TTLS_KYBER_AES_256_GCM}

        if offered not in SUPPORTED_CIPHER_SUITES:
            raise ValueError(f"Cipher suite não suportada: {offered}")

        return offered