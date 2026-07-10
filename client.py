import argparse
import socket
import ssl
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CA = BASE_DIR / "certs" / "server.crt"


def build_context(cafile: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    return context


def run_client(host: str, port: int, cafile: Path, message: str) -> None:
    context = build_context(cafile)

    with socket.create_connection((host, port), timeout=10) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            print(f"[cliente] conectado em {host}:{port}")
            print(
                f"[cliente] TLS usado: {tls_socket.version()} | "
                f"cifra: {tls_socket.cipher()[0]}"
            )

            tls_socket.sendall((message + "\n").encode("utf-8"))
            response = tls_socket.recv(4096).decode("utf-8").strip()
            print(f"[cliente] resposta do servidor: {response}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cliente TLS simples.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ca", type=Path, default=DEFAULT_CA)
    parser.add_argument(
        "--message",
        default="Ola, servidor. Esta mensagem esta passando por TLS.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_client(args.host, args.port, args.ca, args.message)
