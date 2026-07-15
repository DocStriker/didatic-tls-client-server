import struct
from enum import IntEnum


class RecordType(IntEnum):
    APPLICATION_DATA = 0x01
    HANDSHAKE = 0x02
    ALERT = 0x03
    HEARTBEAT = 0x04


class TRPRecord:
    """
    Tarek Record Protocol (TRP) v1

    Header:

    +--------+------------+
    | Type   | Length     |
    | 1 byte | 4 bytes    |
    +--------+------------+

    Payload

    +----------------------+
    | N bytes              |
    +----------------------+
    """

    HEADER_FORMAT = "!BI"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, record_type: RecordType, payload: bytes):
        self.record_type = RecordType(record_type)
        self.payload = payload

    def pack(self) -> bytes:
        header = struct.pack(
            self.HEADER_FORMAT,
            self.record_type,
            len(self.payload)
        )
        return header + self.payload

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("TRP Header incompleto.")

        record_type, length = struct.unpack(
            cls.HEADER_FORMAT,
            data[:cls.HEADER_SIZE]
        )

        payload = data[cls.HEADER_SIZE:]

        if len(payload) != length:
            raise ValueError(
                f"Payload inválido. Esperado {length} bytes, recebido {len(payload)}."
            )

        return cls(RecordType(record_type), payload)


class TRPSocket:

    @staticmethod
    def recv_exact(sock, size: int) -> bytes:
        """
        Lê exatamente 'size' bytes do socket.
        """

        buffer = bytearray()

        while len(buffer) < size:

            chunk = sock.recv(size - len(buffer))

            if not chunk:
                raise ConnectionError("Conexão encerrada.")

            buffer.extend(chunk)

        return bytes(buffer)

    @classmethod
    def send_record(cls, sock, record: TRPRecord):

        sock.sendall(record.pack())

    @classmethod
    def recv_record(cls, sock) -> TRPRecord:

        header = cls.recv_exact(
            sock,
            TRPRecord.HEADER_SIZE
        )

        record_type, payload_size = struct.unpack(
            TRPRecord.HEADER_FORMAT,
            header
        )

        payload = cls.recv_exact(
            sock,
            payload_size
        )

        return TRPRecord(
            RecordType(record_type),
            payload
        )