import socket
from proto.trp import TRPSocket, TRPRecord, RecordType
from ttp.connection import TTPConnection

def ttp_client(message: str) -> None:
    connection = TTPConnection(
    local_ip="127.0.0.1",
    remote_ip="127.0.0.1",
    local_port=50000,
    remote_port=8443,
)

    connection.connect()

    connection.send(
        "Olá servidor!"
    )

    connection.close()

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