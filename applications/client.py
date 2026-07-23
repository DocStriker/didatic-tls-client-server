from transport import tcp
from transport import udp
from transport import ttp

def connect(protocol: str, host: str, port: int, message: str) -> None:

    PROTOCOLS = {
    
        "TCP": tcp.client,
    
        "UDP": udp.client,
    
        "TTP": ttp.client,
    }
    
    protocol = protocol.upper()
    
    try:
        handler = PROTOCOLS[protocol]
    
    except KeyError:
        raise ValueError(f"Protocolo '{protocol}' não suportado.")
    
    handler(host, port, message)