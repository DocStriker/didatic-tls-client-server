import socket
import struct
from proto.ttp import TTPPacket

TTP_PROTOCOL = 253

def checksum(data: bytes) -> int:

    if len(data) % 2 != 0:
        data += b"\x00"

    total = 0

    for i in range(0, len(data), 2):

        word = (data[i] << 8) | data[i + 1]

        total += word

        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def build_ipv4_header(
    source_ip: str,
    destination_ip: str,
    payload_length: int,
    protocol: int = TTP_PROTOCOL,
) -> bytes:

    version = 4

    ihl = 5

    version_ihl = ((version << 4) | ihl)

    tos = 0

    total_length = 20 + payload_length

    identification = 54321

    flags_fragment_offset = 0

    ttl = 64

    header_checksum = 0

    source_address = socket.inet_aton(source_ip)

    destination_address = socket.inet_aton(destination_ip)

    header = struct.pack(
        "!BBHHHBBH4s4s",

        version_ihl,
        tos,

        total_length,

        identification,

        flags_fragment_offset,

        ttl,
        protocol,

        header_checksum,

        source_address,
        destination_address,
    )

    header_checksum = checksum(header)

    header = struct.pack(
        "!BBHHHBBH4s4s",

        version_ihl,
        tos,

        total_length,

        identification,

        flags_fragment_offset,

        ttl,
        protocol,

        header_checksum,

        source_address,
        destination_address,
    )

    return header

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

    received_checksum = (
        ttp_packet.checksum
    )

    ttp_packet.checksum = 0

    ttp_data = ttp_packet.pack()

    calculated_checksum = (
        calculate_ttp_checksum(
            source_ip,
            destination_ip,
            ttp_data,
        )
    )

    ttp_packet.checksum = (
        received_checksum
    )

    return (
        received_checksum
        == calculated_checksum
    )

def build_ttp_ipv4_packet(
    source_ip: str,
    destination_ip: str,
    ttp_packet: TTPPacket,
) -> bytes:

    # Primeiro criamos o TTP com checksum zerado.

    ttp_packet.checksum = 0

    ttp_data = ttp_packet.pack()

    ttp_checksum = calculate_ttp_checksum(
        source_ip,
        destination_ip,
        ttp_data,
    )

    ttp_packet.checksum = ttp_checksum

    ttp_data = ttp_packet.pack()

    ip_header = build_ipv4_header(
        source_ip,
        destination_ip,
        len(ttp_data),
    )

    return ip_header + ttp_data

def extract_ttp_from_ipv4(raw_packet: bytes) -> bytes:
            if len(raw_packet) < 20:
                raise ValueError("Pacote IPv4 muito pequeno.")

            version_ihl = raw_packet[0]

            version = version_ihl >> 4

            if version != 4:
                raise ValueError(
                    f"IPv4 inválido. "
                    f"Version={version}"
                )

            ihl = version_ihl & 0x0F

            ip_header_size = ihl * 4

            if len(raw_packet) < ip_header_size:
                raise ValueError("Pacote menor que o cabeçalho IPv4.")

            return raw_packet[ip_header_size:]