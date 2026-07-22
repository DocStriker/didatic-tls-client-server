from transport.tcp import tcp_client
from transport.udp import udp_client
from transport.ttp import ttp_client

def connect(protocol: str, host: str, port: int, message: str) -> None:

    if protocol == "TCP":
        tcp_client(host, port, message)

    elif protocol == "UDP":
       udp_client(host, port, message)

    elif protocol == "TTP":
        ttp_client(message)