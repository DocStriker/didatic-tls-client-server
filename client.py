import argparse
from sockets.client_socks import tcp_client, udp_client, ttp_client

def run_client(protocol: str, host: str, port: int, message: str) -> None:

    if protocol == "TCP":
        tcp_client(host, port, message)

    elif protocol == "UDP":
       udp_client(host, port, message)

    elif protocol == "TTP":
        ttp_client(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cliente TCP didático.")

    parser.add_argument("--protocol", default="TCP")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=50000)

    parser.add_argument(
        "--message",
        default="Olá servidor! Esta mensagem está em texto puro.",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_client(args.protocol, args.host, args.port, args.message)