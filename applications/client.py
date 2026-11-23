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

def connect(protocol: str, host: str, port: int, message: str, count: int = 1, interval: float = 0.0, keepalive: float | None = None) -> None:
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

    # TCP e UDP são demonstrações de UMA mensagem. A conexão contínua
    # (várias mensagens, keepalive) só existe no TTP.
    if protocol == "TTP":
        handler(host, port, message, count=count, interval=interval, keepalive=keepalive)
        return

    if count != 1:
        print(f"[Aviso] --count só é suportado em TTP; enviando 1 mensagem via {protocol}.")

    handler(host, port, message)
