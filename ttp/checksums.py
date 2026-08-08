# =============================================================================
# ttp/checksums.py
# -----------------------------------------------------------------------------
# Implements the classic "Internet checksum" algorithm (RFC 1071), the same
# one's-complement-sum-of-16-bit-words checksum used by IPv4, TCP, UDP and
# ICMP. TTP reuses this algorithm together with a TCP/UDP-style "pseudo
# header" so corrupted segments (or segments delivered to/from the wrong
# IP addresses) can be detected and rejected.
# =============================================================================

import socket
import struct

from ttp.packet import TTPPacket
from ttp.constants import TTP_PROTOCOL

def checksum(data: bytes) -> int:
    # Internet checksum: sum all 16-bit words in one's-complement
    # arithmetic, then take the one's complement of the result.
    if len(data) % 2 != 0:
        # Odd-length buffers are padded with a zero byte before summing,
        # per RFC 1071.
        data += b"\x00"

    total = 0

    for i in range(0, len(data), 2):
        # Combine each pair of bytes into a 16-bit big-endian word.
        word = (data[i] << 8) | data[i + 1]

        total += word

        # Fold any carry out of bit 16 back into the low 16 bits
        # (this is what makes it "one's complement" addition).
        total = (total & 0xFFFF) + (total >> 16)

    # Final one's complement, masked back down to 16 bits.
    return (~total) & 0xFFFF

def build_ttp_checksum_data(source_ip: str, destination_ip: str, ttp_data: bytes) -> bytes:
    # Builds a "pseudo header": a temporary, virtual header that is never
    # actually transmitted, but is included in the checksum calculation so
    # that the checksum also protects against segments being misrouted
    # between the wrong source/destination IP pair (exactly like TCP/UDP
    # pseudo headers do). Layout: src IP (4) + dst IP (4) + zero byte (1) +
    # protocol number (1) + TTP segment length (2).
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
        0,
        TTP_PROTOCOL,
        len(ttp_data),
    )

    return pseudo_header + ttp_data

def calculate_ttp_checksum(source_ip: str, destination_ip: str, ttp_data: bytes) -> int:
    # Convenience wrapper: build the pseudo-header + segment buffer, then
    # run the Internet checksum algorithm over it.
    data = build_ttp_checksum_data(
        source_ip,
        destination_ip,
        ttp_data,
    )

    return checksum(data)

def validate_ttp_checksum(source_ip: str, destination_ip: str, ttp_packet: TTPPacket) -> bool:
    # Verifies a received packet's checksum by recomputing it the exact
    # same way the sender did: temporarily zero out the checksum field,
    # re-serialize the packet, compute the checksum over pseudo-header +
    # segment, and compare against the value that arrived on the wire.
    received_checksum = ttp_packet.checksum

    ttp_packet.checksum = 0

    ttp_data = ttp_packet.pack()

    calculated_checksum = (
        calculate_ttp_checksum(
            source_ip,
            destination_ip,
            ttp_data,
        )
    )

    # Restore the original checksum value so the caller's packet object is
    # left unmodified after validation.
    ttp_packet.checksum = received_checksum

    return received_checksum == calculated_checksum
