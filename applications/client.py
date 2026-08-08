# =============================================================================
# applications/client.py
# -----------------------------------------------------------------------------
# Very small "dispatcher" module for the client side of the demo.
#
# It does not know anything about sockets, handshakes, or byte layouts.
# Its only job is to look up the correct low-level client function
# (transport.tcp.client / transport.udp.client / transport.ttp.client)
# based on the --protocol argument, and call it.
#
# This is a simple Strategy pattern implemented with a dict lookup table.
# =============================================================================

from transport import tcp
from transport import udp
from transport import ttp

def connect(protocol: str, host: str, port: int, message: str) -> None:
    # Maps the human-readable protocol name to the concrete implementation
    # of "client" living in each transport module.
    PROTOCOLS = {
        "TCP": tcp.client,
        "UDP": udp.client,
        "TTP": ttp.client,
    }

    # Normalize so "tcp", "Tcp", "TCP" all work the same way.
    protocol = protocol.upper()

    try:
        handler = PROTOCOLS[protocol]

    except KeyError:
        # Fail fast with a clear error if an unsupported protocol name was given.
        raise ValueError(f"Protocolo '{protocol}' não suportado.")

    # Delegate to the chosen implementation. Every "client" function shares
    # the same signature: (host, port, message) -> None.
    handler(host, port, message)
