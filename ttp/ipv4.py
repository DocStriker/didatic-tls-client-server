# =============================================================================
# ttp/ipv4.py
# -----------------------------------------------------------------------------
# Minimal hand-rolled IPv4 header builder/parser. Because TTP does not exist
# in the kernel, we cannot rely on the OS to wrap our segments in an IP
# datagram the way it does for TCP/UDP -- we have to build (and parse) the
# 20-byte IPv4 header ourselves and send it through a raw socket with
# IP_HDRINCL set (see ttp/socket.py).
# =============================================================================

import socket
import struct

from ttp.checksums import checksum
from ttp.constants import TTP_PROTOCOL, HEADER_FORMAT_IPV4

class IPv4Packet:
    # Fixed 20-byte header (no IP options supported), matching a standard
    # IPv4 header with IHL = 5 (5 * 4 = 20 bytes).
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT_IPV4)

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
        self.ihl = 5  # Internet Header Length, in 32-bit words (5 = 20 bytes, no options)
        self.tos = 0  # Type of Service / DSCP, unused here
        self.protocol = protocol
        self.ttl = ttl
        self.identification = identification
        self.flags_fragment_offset = 0  # No fragmentation handled by this demo
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.payload = payload

    @property
    def header_length(self) -> int:
        # IHL is expressed in 32-bit (4-byte) words per the IPv4 spec.
        return self.ihl * 4

    @property
    def total_length(self) -> int:
        # "Total Length" field: header + payload, both in bytes.
        return self.header_length + len(self.payload)

    def build_header(self) -> bytes:
        # Packs the version+IHL nibbles into a single byte, as required by
        # the IPv4 spec (high nibble = version, low nibble = IHL).
        version_ihl = ((self.version << 4) | self.ihl)

        # inet_aton converts a dotted-quad string ("127.0.0.1") into its
        # 4-byte network-order binary representation.
        source_address = socket.inet_aton(self.source_ip)

        destination_address = socket.inet_aton(self.destination_ip)

        # First pass: build the header with checksum = 0, exactly like real
        # IPv4 implementations do, because the checksum field itself must
        # be zero while it is being calculated over the header.
        header = struct.pack(
            HEADER_FORMAT_IPV4,
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

        # Second pass: rebuild the header, this time with the real checksum
        # filled in.
        return struct.pack(
            HEADER_FORMAT_IPV4,
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
        # Final raw datagram: 20-byte IP header followed by whatever
        # payload it is carrying (a full TTP segment, in this project).
        return (self.build_header() + self.payload)

    @classmethod
    def unpack(cls, raw_packet: bytes):
        # Parses a raw IPv4 datagram as received from a SOCK_RAW socket.
        if len(raw_packet) < cls.HEADER_SIZE:
            raise ValueError("Pacote IPv4 muito pequeno.")

        # First byte packs version (high nibble) and IHL (low nibble).
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
        ) = struct.unpack(HEADER_FORMAT_IPV4, raw_packet[:20])

        # Payload runs from the end of the header up to total_length,
        # which correctly drops any trailing bytes the OS/driver may have
        # appended (e.g. Ethernet padding on the loopback interface).
        payload = raw_packet[header_size:total_length]

        packet = cls(
            source_ip = socket.inet_ntoa(source_address),
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
        # Convenience check used by TTPSocket to make sure a datagram
        # actually carries our custom protocol number before trying to
        # parse its payload as a TTPPacket.
        return (self.protocol == TTP_PROTOCOL)

    def __repr__(self):
        return (
            f"IPv4Packet("
            f"{self.source_ip} -> "
            f"{self.destination_ip}, "
            f"protocol={self.protocol}, "
            f"payload={len(self.payload)} bytes)"
        )
