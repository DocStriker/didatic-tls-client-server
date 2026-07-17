import socket

from ipv4 import build_ttp_ipv4_packet
from ttp import TTPPacket, TTPFlags


SOURCE_IP = "127.0.0.1"
DESTINATION_IP = "127.0.0.1"

SOURCE_PORT = 50000
DESTINATION_PORT = 8443


def main():

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_RAW,
    )

    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_HDRINCL,
        1,
    )

    packet = TTPPacket(
        source_port=SOURCE_PORT,

        destination_port=DESTINATION_PORT,

        sequence_number=1000,

        acknowledgment_number=0,

        flags=TTPFlags.DATA,

        window_size=65535,

        payload=b"Hello from TTP!",
    )

    raw_packet = build_ttp_ipv4_packet(
        source_ip=SOURCE_IP,

        destination_ip=DESTINATION_IP,

        ttp_packet=packet,
    )

    sock.sendto(
        raw_packet,

        (
            DESTINATION_IP,
            0,
        ),
    )

    print(
        "[TTP] Pacote enviado."
    )

    print(
        f"[TTP] Tamanho: "
        f"{len(raw_packet)} bytes"
    )


if __name__ == "__main__":

    main()