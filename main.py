# =============================================================================
# main.py
# -----------------------------------------------------------------------------
# This is the single entry point for the whole didactic networking demo.
# It is a thin command-line wrapper: it does NOT implement any networking
# logic itself. Instead, it parses CLI arguments and delegates the real work
# to `applications/client.py` (connect) or `applications/server.py` (serve).
#
# The whole point of this file is to let the user pick, at run time, which
# transport-layer implementation to exercise: TCP (real OS sockets), UDP
# (real OS sockets), or TTP (the hand-rolled, TCP-like protocol implemented
# from scratch in the `ttp/` package using raw IP sockets).
#
# Example usage:
#   python main.py --mode server --protocol TTP --port 8443
#   python main.py --mode client --protocol TTP --port 8443 --message "hi"
# =============================================================================

import argparse
from applications.client import connect
from applications.server import serve

def parse_args() -> argparse.Namespace:
    # Builds and parses the command line interface.
    # --mode      : "server" to listen for connections, anything else -> client
    # --protocol  : which transport implementation to use (TCP/UDP/TTP)
    # --host      : IP address to bind (server) or connect to (client)
    # --port      : TCP/UDP/TTP port number
    # --message   : payload the client will send to the server
    parser = argparse.ArgumentParser(description="Network didático.")

    parser.add_argument("--mode")
    parser.add_argument("--protocol", default="TCP")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--message", default="Olá servidor! Esta mensagem está em texto puro.",)

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    if args.mode == "server":
        # Server side: bind/listen and wait for one client, per the chosen protocol.
        serve(args.protocol, args.host, args.port)

    else:
        # Client side (default): connect to the server and send --message.
        connect(args.protocol, args.host, args.port, args.message,)
