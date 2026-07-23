from transport import tcp
from transport import udp
from transport import ttp

def serve(protocol: str, host: str, port: int) -> None:
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