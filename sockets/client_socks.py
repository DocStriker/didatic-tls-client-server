import socket
from proto.trp import TRPSocket, TRPRecord, RecordType
from ip.ipv4 import build_ttp_ipv4_packet, calculate_ttp_checksum
from proto.ttp import TTPPacket, TTPFlags, TTPState
import random

SOURCE_IP = "127.0.0.1"
DESTINATION_IP = "127.0.0.1"

SOURCE_PORT = 50000
DESTINATION_PORT = 8443

def ttp_client(message: str) -> None:
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

    state = TTPState.CLOSED

    client_sequence = random.randint(
        0,
        2**32 - 1,
    )

    print(
        f"[TTP] Estado: {state.name}"
    )

    # ==================================================
    # 1. CLIENTE ENVIA SYN
    # ==================================================

    syn_packet = TTPPacket(

        source_port=SOURCE_PORT,

        destination_port=DESTINATION_PORT,

        sequence_number=client_sequence,

        acknowledgment_number=0,

        flags=TTPFlags.SYN,

        window_size=65535,

        payload=b"",
    )

    raw_syn = build_ttp_ipv4_packet(

        source_ip=SOURCE_IP,

        destination_ip=DESTINATION_IP,

        ttp_packet=syn_packet,
    )

    sock.sendto(

        raw_syn,

        (
            DESTINATION_IP,

            0,
        ),
    )

    state = TTPState.SYN_SENT

    print(
        "[TTP] SYN enviado."
    )

    print(
        f"[TTP] Estado: {state.name}"
    )

     # ==================================================
    # 2. CLIENTE ESPERA SYN-ACK
    # ==================================================

    while True:

        raw_packet, address = (
            sock.recvfrom(65535)
        )

        source_ip = address[0]

        version_ihl = (
            raw_packet[0]
        )

        ihl = (
            version_ihl
            & 0x0F
        )

        ip_header_size = (
            ihl * 4
        )

        ttp_data = raw_packet[
            ip_header_size:
        ]

        packet = TTPPacket.unpack(
            ttp_data
        )

        if packet.source_port != (
            DESTINATION_PORT
        ):

            continue

        print("Break 1")
        if not (
            packet.flags
            & TTPFlags.SYN
        ):

            continue
        print("Break 2")
        if not (
            packet.flags
            & TTPFlags.ACK
        ):

            continue

        expected_ack = (
            client_sequence + 1
        )

        if (
            packet.acknowledgment_number
            != expected_ack
        ):

            print(
                "[TTP] ACK inválido."
            )

            continue

        server_sequence = (
            packet.sequence_number
        )

        print(
            "[TTP] SYN-ACK recebido."
        )

        break

    # ==================================================
    # 3. CLIENTE ENVIA ACK FINAL
    # ==================================================

    ack_packet = TTPPacket(

        source_port=SOURCE_PORT,

        destination_port=DESTINATION_PORT,

        sequence_number=(
            client_sequence + 1
        ),

        acknowledgment_number=(
            server_sequence + 1
        ),

        flags=TTPFlags.ACK,

        window_size=65535,

        payload=b"",
    )

    raw_ack = build_ttp_ipv4_packet(

        source_ip=SOURCE_IP,

        destination_ip=DESTINATION_IP,

        ttp_packet=ack_packet,
    )

    sock.sendto(

        raw_ack,

        (
            DESTINATION_IP,

            0,
        ),
    )

    state = TTPState.ESTABLISHED

    print(
        "[TTP] ACK final enviado."
    )

    print(
        f"[TTP] Estado: {state.name}"
    )

    # ==================================================
    # 4. ENVIA DATA
    # ==================================================

    data_packet = TTPPacket(

        source_port=SOURCE_PORT,

        destination_port=DESTINATION_PORT,

        sequence_number=(
            client_sequence + 1
        ),

        acknowledgment_number=(
            server_sequence + 1
        ),

        flags=TTPFlags.DATA,

        window_size=65535,

        payload=message.encode(
            "utf-8"
        ),
    )

    raw_data = build_ttp_ipv4_packet(

        source_ip=SOURCE_IP,

        destination_ip=DESTINATION_IP,

        ttp_packet=data_packet,
    )

    sock.sendto(

        raw_data,

        (
            DESTINATION_IP,

            0,
        ),
    )

    print(
        "[TTP] DATA enviada."
    )

def tcp_client(host: str, port: int, message: str) -> None:
    with socket.create_connection((host, port), timeout=10) as client_socket:
        print(f"[cliente] conectado em {host}:{port}")

        client_socket.sendall((message).encode("utf-8"))

        response = client_socket.recv(4096)

        print(f"[cliente] resposta: {response.decode('utf-8').strip()}")

def udp_client(host: str, port: int, message: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.sendto(message.encode("utf-8"), (host, port))

        data, addr = client.recvfrom(4096)

        print(f"[cliente] resposta: {data.decode('utf-8').strip()} from {addr}")

def trp_client (message: str) -> None:
    with TRPSocket() as client:
                client.send_record(
                    TRPRecord(RecordType.APPLICATION_DATA, message.encode("utf-8"))
                )

                response = client.recv_record()
                print(f"[cliente] resposta: {response.payload.decode('utf-8').strip()}")