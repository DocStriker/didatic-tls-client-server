import struct
from enum import IntFlag, IntEnum

class TTPState(IntEnum):

    CLOSED = 0

    SYN_SENT = 1

    SYN_RECEIVED = 2

    ESTABLISHED = 3

class TTPFlags(IntFlag):

    NONE = 0x00
    
    SYN = 0x01
    ACK = 0x02
    FIN = 0x04
    RST = 0x08
    DATA = 0x10
    SYN_ACK = 0x09

class TTPPacket:

    HEADER_FORMAT = "!HHIIBHH"

    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(
        self,
        source_port: int,
        destination_port: int,
        sequence_number: int,
        acknowledgment_number: int,
        flags: TTPFlags,
        window_size: int,
        payload: bytes = b"",
        checksum: int = 0,
    ):

        self.source_port = source_port
        self.destination_port = destination_port

        self.sequence_number = sequence_number
        self.acknowledgment_number = acknowledgment_number

        self.flags = flags
        self.window_size = window_size

        self.payload = payload
        self.checksum = checksum

    def pack(self) -> bytes:

        header = struct.pack(
            self.HEADER_FORMAT,

            self.source_port,
            self.destination_port,

            self.sequence_number,
            self.acknowledgment_number,

            self.flags,

            self.window_size,
            self.checksum,
        )

        return header + self.payload

    @classmethod
    def unpack(cls, data: bytes):

        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Pacote TTP menor que o cabeçalho.")

        header = data[:cls.HEADER_SIZE]

        (
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            flags,
            window_size,
            checksum,
        ) = struct.unpack(
            cls.HEADER_FORMAT,
            header
        )

        payload = data[cls.HEADER_SIZE:]

        return cls(
            source_port=source_port,
            destination_port=destination_port,

            sequence_number=sequence_number,
            acknowledgment_number=acknowledgment_number,

            flags=TTPFlags(flags),

            window_size=window_size,
            payload=payload,
            checksum=checksum,
        )