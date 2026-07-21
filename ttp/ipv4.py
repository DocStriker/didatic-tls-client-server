import socket
import struct

from ttp.checksums import checksum
from ttp.constants import TTP_PROTOCOL


class IPv4Packet:

    HEADER_FORMAT = "!BBHHHBBH4s4s"

    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(
        self,
        source_ip: str,
        destination_ip: str,
        payload: bytes,
        protocol: int = TTP_PROTOCOL,
        ttl: int = 64,
        identification: int = 54321,
    ):

        self.version = 4
        self.ihl = 5

        self.tos = 0

        self.protocol = protocol

        self.ttl = ttl

        self.identification = identification

        self.flags_fragment_offset = 0

        self.source_ip = source_ip
        self.destination_ip = destination_ip

        self.payload = payload

    @property
    def header_length(self) -> int:

        return self.ihl * 4

    @property
    def total_length(self) -> int:

        return self.header_length + len(self.payload)

    def build_header(self) -> bytes:

        version_ihl = ((self.version << 4) | self.ihl)

        source_address = socket.inet_aton(self.source_ip)

        destination_address = socket.inet_aton(self.destination_ip)

        header = struct.pack(
            self.HEADER_FORMAT,

            version_ihl,

            self.tos,

            self.total_length,

            self.identification,

            self.flags_fragment_offset,

            self.ttl,

            self.protocol,

            0,

            source_address,

            destination_address,
        )

        header_checksum = checksum(header)

        return struct.pack(
            self.HEADER_FORMAT,

            version_ihl,

            self.tos,

            self.total_length,

            self.identification,

            self.flags_fragment_offset,

            self.ttl,

            self.protocol,

            header_checksum,

            source_address,

            destination_address,
        )

    def pack(self) -> bytes:
        return (self.build_header() + self.payload)

    @classmethod
    def unpack(cls, raw_packet: bytes):

        if len(raw_packet) < cls.HEADER_SIZE:
            raise ValueError("Pacote IPv4 muito pequeno.")

        version_ihl = raw_packet[0]

        version = version_ihl >> 4

        ihl = version_ihl & 0x0F

        if version != 4:
            raise ValueError(f"Versão IPv4 inválida ({version})")

        header_size = ihl * 4

        if len(raw_packet) < header_size:
            raise ValueError("Cabeçalho IPv4 incompleto.")

        (
            _,
            tos,
            total_length,
            identification,
            flags_fragment_offset,
            ttl,
            protocol,
            header_checksum,
            source_address,
            destination_address,
        ) = struct.unpack(cls.HEADER_FORMAT, raw_packet[:20])

        payload = raw_packet[header_size:total_length]

        packet = cls(source_ip = socket.inet_ntoa(source_address),
                    destination_ip = socket.inet_ntoa(destination_address),

            payload=payload,

            protocol=protocol,

            ttl=ttl,

            identification=identification,
        )

        packet.version = version
        packet.ihl = ihl
        packet.tos = tos
        packet.flags_fragment_offset = (flags_fragment_offset)

        packet.header_checksum = (header_checksum)

        return packet
    
    def is_ttp(self):
        return (self.protocol == TTP_PROTOCOL)
    
    def __repr__(self):
        return (
            f"IPv4Packet("
            f"{self.source_ip} -> "
            f"{self.destination_ip}, "
            f"protocol={self.protocol}, "
            f"payload={len(self.payload)} bytes)"
        )