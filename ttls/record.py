# =============================================================================
# ttls/record.py
# -----------------------------------------------------------------------------
# "Tarek Transport Layer Security" (TTLS) v1 -- a minimal, didactic record-framing
# layer loosely inspired by the TLS Record Protocol. Its purpose is to show
# how a real protocol like TLS avoids the "where does one message end and
# the next begin?" problem over a byte-stream transport (like TCP): every
# record is prefixed with a small, fixed-size header carrying its type and
# exact payload length, so the receiver always knows how many bytes to read.
#
# Wire format of a single record:
#
#   +--------+------------+----------------------+
#   | Type   | Length     | Payload (N bytes)     |
#   | 1 byte | 4 bytes    |                        |
#   +--------+------------+----------------------+
# =============================================================================

import struct
from enum import IntEnum


class RecordType(IntEnum):
    # Mirrors (in spirit) the four main TLS record content types.
    APPLICATION_DATA = 0x01
    HANDSHAKE = 0x02
    ALERT = 0x03
    HEARTBEAT = 0x04


class TTLSRecord:
    """
    Tarek Transport Layer Security (TTLS) v1

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

    # "!BI" = network byte order, 1 unsigned byte (type) + 4-byte unsigned
    # int (payload length). struct.calcsize gives us the header size (5).
    HEADER_FORMAT = "!BI"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, record_type: RecordType, payload: bytes):
        self.record_type = RecordType(record_type)
        self.payload = payload

    def pack(self) -> bytes:
        # Serializes header + payload into the exact bytes to put on the wire.
        header = struct.pack(
            self.HEADER_FORMAT,
            self.record_type,
            len(self.payload)
        )
        return header + self.payload

    @classmethod
    def unpack(cls, data: bytes):
        # Rebuilds a TRPRecord from raw bytes that already contain a
        # complete header + payload (used mainly for testing / in-memory
        # parsing; recv_record() below is the streaming-safe version).
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