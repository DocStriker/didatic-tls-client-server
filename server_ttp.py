import socket

from ipv4 import (
    TTP_PROTOCOL,
    calculate_ttp_checksum,
)

from ttp import TTPPacket


SERVER_IP = "127.0.0.1"


def main():

    sock = socket.socket(
        socket.AF_INET,

        socket.SOCK_RAW,

        TTP_PROTOCOL,
    )

    print(
        "[TTP] Aguardando pacotes..."
    )

    while True:

        raw_packet, address = sock.recvfrom(
            65535
        )

        source_ip = address[0]

        print(
            f"\n[TTP] Pacote recebido "
            f"de {source_ip}"
        )

        # IPv4 header mínimo = 20 bytes.
        #
        # Porém, o IHL pode ser maior.
        #
        # O primeiro byte contém:
        #
        # Version: 4 bits
        # IHL: 4 bits

        version_ihl = raw_packet[0]

        ihl = version_ihl & 0x0F

        ip_header_size = ihl * 4

        ip_header = raw_packet[
            :ip_header_size
        ]

        ttp_data = raw_packet[
            ip_header_size:
        ]

        packet = TTPPacket.unpack(
            ttp_data
        )

        print(
            f"[TTP] Porta origem: "
            f"{packet.source_port}"
        )

        print(
            f"[TTP] Porta destino: "
            f"{packet.destination_port}"
        )

        print(
            f"[TTP] Sequence: "
            f"{packet.sequence_number}"
        )

        print(
            f"[TTP] ACK: "
            f"{packet.acknowledgment_number}"
        )

        print(
            f"[TTP] Flags: "
            f"{packet.flags}"
        )

        print(
            f"[TTP] Window: "
            f"{packet.window_size}"
        )

        print(
            f"[TTP] Checksum: "
            f"{packet.checksum:#06x}"
        )

        print(
            f"[TTP] Payload: "
            f"{packet.payload!r}"
        )


if __name__ == "__main__":

    main()