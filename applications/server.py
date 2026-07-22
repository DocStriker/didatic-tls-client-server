from transport.tcp import tcp_server
from transport.udp import udp_server
from transport.ttp import ttp_server

def serve(protocol: str, host: str, port: int) -> None:

    if protocol == "TCP":
        tcp_server(host, port)

    elif protocol == "UDP":
        udp_server(host, port)

    elif protocol == "TTP":
        ttp_server(host, port)