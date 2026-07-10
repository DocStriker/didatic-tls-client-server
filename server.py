import argparse
import socket
import ssl
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CERT = BASE_DIR / "certs" / "server.crt"
DEFAULT_KEY = BASE_DIR / "certs" / "server.key"


def build_context(certfile: Path, keyfile: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def handle_client(conn: ssl.SSLSocket, address: tuple[str, int]) -> None:
    print(f"[servidor] cliente conectado: {address[0]}:{address[1]}")
    print(f"[servidor] TLS usado: {conn.version()} | cifra: {conn.cipher()[0]}")

    data = conn.recv(4096)
    message = data.decode("utf-8").strip()
    print(f"[servidor] mensagem recebida: {message!r}")

    response = (
        "Ola do servidor TLS! Sua mensagem chegou por um canal criptografado.\n"
    )
    conn.sendall(response.encode("utf-8"))


def serve(host: str, port: int, certfile: Path, keyfile: Path) -> None:
    context = build_context(certfile, keyfile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"[servidor] aguardando conexoes TLS em {host}:{port}")
        print("[servidor] pressione Ctrl+C para parar")

        while True:
            raw_conn, address = server_socket.accept()
            try:
                with context.wrap_socket(raw_conn, server_side=True) as tls_conn:
                    handle_client(tls_conn, address)
            except ssl.SSLError as error:
                print(f"[servidor] falha TLS com {address}: {error}")
            finally:
                raw_conn.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Servidor TLS simples.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", type=Path, default=DEFAULT_CERT)
    parser.add_argument("--key", type=Path, default=DEFAULT_KEY)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    serve(args.host, args.port, args.cert, args.key)
