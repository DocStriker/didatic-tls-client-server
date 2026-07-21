import socket
import struct

from ttp.packet import TTPPacket
from ttp.constants import TTP_PROTOCOL

def checksum(data: bytes) -> int:

    if len(data) % 2 != 0:
        data += b"\x00"

    total = 0

    for i in range(0, len(data), 2):

        word = (data[i] << 8) | data[i + 1]

        total += word

        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF

def build_ttp_checksum_data(
    source_ip: str,
    destination_ip: str,
    ttp_data: bytes,
) -> bytes:

    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
        0,
        TTP_PROTOCOL,
        len(ttp_data),
    )

    return pseudo_header + ttp_data

def calculate_ttp_checksum(
    source_ip: str,
    destination_ip: str,
    ttp_data: bytes,
) -> int:

    data = build_ttp_checksum_data(
        source_ip,
        destination_ip,
        ttp_data,
    )

    return checksum(data)

def validate_ttp_checksum(
    source_ip: str,
    destination_ip: str,
    ttp_packet: TTPPacket,
) -> bool:

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

    ttp_packet.checksum = received_checksum

    return received_checksum == calculated_checksum