import socket
from ttp.connection import TTPConnection

def server_ttp(host: str, port: int) -> None:
    listener = TTPConnection(
        local_ip="127.0.0.1",
        local_port=8443,
    )

    connection = listener.accept()

    dados = connection.recv()

    print(dados)

    connection.close()

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