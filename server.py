import argparse
import socket


def handle_client(conn: socket.socket, address: tuple[str, int]) -> None:
    print(f"[servidor] cliente conectado: {address[0]}:{address[1]}")

    data = conn.recv(4096)

    # ======================================================
    # TODO:
    # Futuramente:
    #
    # ciphertext
    #      ↓
    # decrypt()
    #      ↓
    # plaintext
    # ======================================================

    message = data.decode("utf-8").strip()

    print(f"[servidor] mensagem recebida: {message}")

    response = (
        "Olá do servidor TCP! Sua mensagem chegou sem criptografia."
    )

    # ======================================================
    # TODO:
    # Futuramente:
    #
    # plaintext
    #      ↓
    # encrypt()
    #      ↓
    # ciphertext
    # ======================================================

    conn.sendall(response.encode("utf-8"))


def serve(protocol: str, host: str, port: int) -> None:

    if protocol == "TCP":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:

            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            server_socket.bind((host, port))

            server_socket.listen(5)

            print(f"[servidor] aguardando conexões em {host}:{port}")
            print("[servidor] protocolo: TCP puro")
            print("[servidor] pressione Ctrl+C para parar")

            while True:
                conn, address = server_socket.accept()

                with conn:
                    handle_client(conn, address)

    elif protocol == "UDP":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:

            server.bind(("127.0.0.1", 8443))

            print("Servidor UDP iniciado")

            while True:

                data, addr = server.recvfrom(4096)

                print(f"{addr} -> {data.decode()}")

                server.sendto(b"Recebido", addr)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Servidor TCP didático.")

    parser.add_argument("--protocol", default="TCP")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    serve(args.protocol, args.host, args.port)