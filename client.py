import argparse
import socket


def run_client(host: str, port: int, message: str) -> None:
    with socket.create_connection((host, port), timeout=10) as client_socket:
        print(f"[cliente] conectado em {host}:{port}")

        # ======================================================
        # TODO:
        # Nesta etapa a mensagem será enviada em texto puro.
        # Futuramente ela poderá passar por:
        #
        # plaintext
        #     ↓
        # encrypt()
        #     ↓
        # ciphertext
        #
        # antes de ser enviada.
        # ======================================================

        client_socket.sendall((message + "\n").encode("utf-8"))

        response = client_socket.recv(4096)

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

        print(f"[cliente] resposta: {response.decode('utf-8').strip()}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cliente TCP didático.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)

    parser.add_argument(
        "--message",
        default="Olá servidor! Esta mensagem está em texto puro.",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_client(args.host, args.port, args.message)