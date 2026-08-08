# =============================================================================
# applications/server.py
# -----------------------------------------------------------------------------
# Mirror of applications/client.py, but for the server side.
#
# It maps the --protocol argument to the "server" entry point of the matching
# transport module (transport.tcp.server / transport.udp.server / transport.ttp.server)
# and simply calls it. All three "server" functions share the signature
# (host, port) -> None and block forever, serving one connection/message at a
# time (this project is intentionally simple/didactic, not concurrent).
# =============================================================================

from transport import tcp
from transport import udp
from transport import ttp

def serve(protocol: str, host: str, port: int) -> None:
    # Lookup table: protocol name -> server implementation.
    PROTOCOLS = {
        "TCP": tcp.server,
        "UDP": udp.server,
        "TTP": ttp.server,
    }

    protocol = protocol.upper()

    try:
        handler = PROTOCOLS[protocol]

    except KeyError:
        raise ValueError(f"Protocolo '{protocol}' não suportado.")

    handler(host, port)
