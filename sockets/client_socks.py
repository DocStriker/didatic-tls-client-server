import socket
from proto.trp import TRPSocket, TRPRecord, RecordType
from ip.ipv4 import build_ttp_ipv4_packet
from proto.ttp import TTPPacket, TTPFlags


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