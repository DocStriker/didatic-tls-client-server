import argparse
from sockets.server_socks import server_tcp, server_udp, server_ttp

def serve(protocol: str, host: str, port: int) -> None:

    if protocol == "TCP":
        server_tcp(host, port)

    elif protocol == "UDP":
        server_udp(host, port)

    elif protocol == "TTP":
        server_ttp(host, port)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Servidor TCP didático.")

    parser.add_argument("--protocol", default="TCP")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    serve(args.protocol, args.host, args.port)