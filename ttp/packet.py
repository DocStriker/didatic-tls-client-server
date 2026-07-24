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

class TTPPacket:

    HEADER_FORMAT = "!HHIIBBHHHI"

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
        self.header_length = self.HEADER_SIZE
        self.reserved = 0

        self.window = window_size

        self.payload = payload
        self.checksum = checksum

    def pack(self) -> bytes:
        if self.payload_length > 0xFFFF:
            raise ValueError(
                "Payload excede o tamanho máximo suportado (65535 bytes)."
            )

        header = struct.pack(
            self.HEADER_FORMAT,

            self.source_port,
            self.destination_port,

            self.sequence_number,
            self.acknowledgment_number,

            self.flags,
            self.header_length,
            self.reserved,

            self.window,
            self.payload_length,
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
            header_length,
            reserved,
            window_size,
            payload_length,
            checksum,

        ) = struct.unpack(
            cls.HEADER_FORMAT,
            header
        )

        expected_size = header_length + payload_length

        if len(data) < expected_size:
            raise ValueError(
                "Pacote TTP incompleto."
            )

        payload = data[
            header_length:
            expected_size
        ]

        packet = cls(
            source_port=source_port,
            destination_port=destination_port,
            sequence_number=sequence_number,
            acknowledgment_number=acknowledgment_number,
            flags=TTPFlags(flags),
            window_size=window_size,
            payload=payload,
            checksum=checksum,
        )

        packet.header_length = header_length
        packet.reserved = reserved

        return packet
    
    @property
    def payload_length(self) -> int:
        return len(self.payload)
    
    @property
    def segment_size(self) -> int:
        return self.HEADER_SIZE + self.payload_length
    
    @property
    def is_syn(self):
        return bool(self.flags & TTPFlags.SYN)
    
    @property
    def is_ack(self):
        return bool(self.flags & TTPFlags.ACK)
    
    @property
    def is_fin(self):
        return bool(self.flags & TTPFlags.FIN)

    @property
    def is_rst(self):
        return bool(self.flags & TTPFlags.RST)

    @property
    def is_data(self):
        return bool(self.flags & TTPFlags.DATA)

    @property
    def sequence_space(self) -> int:
        """
        Quantidade de números de sequência consumidos por este pacote.
        """

        size = len(self.payload)

        if self.is_syn:
            size += 1

        if self.is_fin:
            size += 1

        return size

    def __repr__(self):
        return (
            f"TTPPacket("
            f"{self.source_port} -> "
            f"{self.destination_port}, "
            f"SEQ={self.sequence_number}, "
            f"ACK={self.acknowledgment_number}, "
            f"FLAGS={self.flags}, "
            f"PAYLOAD={self.payload_length} bytes, "
            f"RESERVED={self.reserved}, "
            f"HEADER_LENGHT={self.header_length} bytes)"
        )
    
    def copy(self):
        return TTPPacket(
            source_port=self.source_port,
            destination_port=self.destination_port,
            sequence_number=self.sequence_number,
            acknowledgment_number=self.acknowledgment_number,
            flags=self.flags,
            window_size=self.window,
            payload=self.payload,
            checksum=self.checksum,
        )