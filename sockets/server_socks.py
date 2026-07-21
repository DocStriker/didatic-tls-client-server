import socket
import random

from ip.ipv4 import (
    TTP_PROTOCOL,
    build_ttp_ipv4_packet,
    validate_ttp_checksum,
    extract_ttp_from_ipv4
)

from proto.ttp import TTPPacket, TTPFlags, TTPState

SERVER_IP = "127.0.0.1"


def server_ttp(host: str, port: int) -> None:
    send_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_RAW,
    )

    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    recv_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        TTP_PROTOCOL,
    )

    state = TTPState.CLOSED

    print("[TTP] Aguardando SYN...")

    print(f"[TTP] Estado: {state.name}")

    while True:
        raw_packet, adress = recv_sock.recvfrom(65535)

        source_ip = adress[0]

        ttp_data = extract_ttp_from_ipv4(raw_packet)
        
        packet = TTPPacket.unpack(ttp_data)

        # ==================================================
        # FILTRAR PORTA DESTINO
        # ==================================================

        if packet.destination_port != port:
            continue

        # ==================================================
        # VALIDAR CHECKSUM
        # ==================================================

        valid_checksum = (validate_ttp_checksum(source_ip, SERVER_IP, packet))

        if not valid_checksum:
            print("[TTP] Checksum inválido.")
            continue

        # ==================================================
        # 1. RECEBE SYN
        # ==================================================

        if (state == TTPState.CLOSED and packet.flags == TTPFlags.SYN):
            client_sequence = (packet.sequence_number)

            server_sequence = (random.randint(0, 2**32 - 1,))

            print("[TTP] SYN recebido.")

            print(
                f"[TTP] Client SEQ: "
                f"{client_sequence}"
            )

            print(
                f"[TTP] Server SEQ: "
                f"{server_sequence}"
            )

            # ==========================================
            # SERVIDOR ENVIA SYN-ACK
            # ==========================================

            syn_ack_packet = TTPPacket(
                source_port=packet.destination_port,
                destination_port=packet.source_port,
                sequence_number=server_sequence,
                acknowledgment_number=client_sequence + 1,
                flags=TTPFlags.SYN_ACK,
                window_size=65535,
                payload=b"",
            )

            raw_syn_ack = (
                build_ttp_ipv4_packet(
                    source_ip=SERVER_IP,
                    destination_ip=source_ip,
                    ttp_packet=syn_ack_packet,
                )
            )

            send_sock.sendto(raw_syn_ack, (source_ip, 0))

            state = (TTPState.SYN_RECEIVED)

            print("[TTP] SYN-ACK enviado.")

            print(
                f"[TTP] Estado: "
                f"{state.name}"
            )

            continue

        # ==================================================
        # 2. RECEBE ACK FINAL
        # ==================================================

        if (state == TTPState.SYN_RECEIVED and packet.flags == TTPFlags.ACK):
            expected_ack = (server_sequence + 1)

            if (packet.acknowledgment_number != expected_ack):
                print("[TTP] ACK inválido.")

                continue

            state = (TTPState.ESTABLISHED)

            print("[TTP] ACK final recebido.")

            print(
                f"[TTP] Estado: "
                f"{state.name}"
            )

            continue

        # ==================================================
        # 3. RECEBE DATA
        # ==================================================

        if (state == TTPState.ESTABLISHED and packet.flags == TTPFlags.DATA):
            print("[TTP] DATA recebida.")

            print(
                f"[TTP] Payload: "
                f"{packet.payload.decode('utf-8')}"
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