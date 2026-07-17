import socket
from ip.ipv4 import (
    TTP_PROTOCOL,
    calculate_ttp_checksum,
)

from proto.ttp import TTPPacket

SERVER_IP = "127.0.0.1"

def server_ttp(host: str, port: int) -> None:
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

def handle_client(conn: socket.socket, address: tuple[str, int]) -> None:
    print(f"[servidor] cliente conectado: {address[0]}:{address[1]}")

    data = conn.recv(4096)

    message = data.decode("utf-8").strip()

    print(f"[servidor] mensagem recebida: {message}")

    response = ("Olá do servidor TCP! Sua mensagem chegou sem criptografia.")
    
    conn.sendall(response.encode("utf-8"))

def server_tcp(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((host, port))
        server.listen()

        print(f"[servidor] aguardando conexões em {host}:{port}")

        while True:
            conn, addr = server.accept()
            handle_client(conn, addr)
            conn.close()

def server_udp(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((host, port))

        print(f"[servidor] aguardando mensagens UDP em {host}:{port}")

        while True:
            data, addr = server.recvfrom(4096)

            message = data.decode("utf-8").strip()

            print(f"[servidor] mensagem recebida de {addr}: {message}")

            response = ("Olá do servidor UDP! Sua mensagem chegou sem criptografia.")

            server.sendto(response.encode("utf-8"), addr)