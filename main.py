import argparse
from applications.client import connect
from applications.server import serve

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Network didático.")

    parser.add_argument("--mode")
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

    if args.mode == "server":
        serve(args.protocol, args.host, args.port)

    else:
        connect(args.protocol, args.host, args.port, args.message,)