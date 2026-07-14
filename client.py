import argparse
import socket


def run_client(protocol: str, host: str, port: int, message: str) -> None:

    if protocol == "TCP":
        with socket.create_connection((host, port), timeout=10) as client_socket:
            print(f"[cliente] conectado em {host}:{port}")

            client_socket.sendall((message).encode("utf-8"))

            response = client_socket.recv(4096)

            print(f"[cliente] resposta: {response.decode('utf-8').strip()}")

    elif protocol == "UDP":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:

            client.sendto(
                b"Ola servidor",
                ("127.0.0.1", 8443)
            )

            data, addr = client.recvfrom(4096)

            print(data.decode(), "from", addr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cliente TCP didático.")

    parser.add_argument("--protocol", default="TCP")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)

    parser.add_argument(
        "--message",
        default="Olá servidor! Esta mensagem está em texto puro.",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_client(args.protocol, args.host, args.port, args.message)