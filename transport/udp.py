# =============================================================================
# transport/udp.py
# -----------------------------------------------------------------------------
# Baseline UDP implementation (SOCK_DGRAM), using the OS network stack.
# UDP is connectionless: there is no handshake, no guaranteed delivery, and
# no guaranteed ordering. Each sendto()/recvfrom() call transports exactly
# one independent datagram. This module is here to contrast with TCP and
# TTP: it is the simplest of the three, and also the least reliable.
# =============================================================================

import socket

def client(host: str, port: int, message: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        # sendto() fires the datagram at (host, port). There is no
        # connection setup step -- the packet may simply be lost, and the
        # sender would never know.
        client.sendto(message.encode("utf-8"), (host, port))

        # Blocks waiting for a reply datagram (up to 4096 bytes).
        data, addr = client.recvfrom(4096)

        print(f"[Client][UDP] Resposta: {data.decode('utf-8').strip()} from {addr}")

def server(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        # bind() is enough for UDP -- there is no listen()/accept() because
        # there are no connections, only datagrams arriving at this address.
        server.bind((host, port))

        print(f"[Server][UDP] Aguardando mensagens UDP em {host}:{port}")

        while True:
            # recvfrom() returns both the payload and the sender's address,
            # since (unlike TCP) each read can come from a different peer.
            data, addr = server.recvfrom(4096)

            message = data.decode("utf-8").strip()

            print(f"[Server][UDP] Mensagem recebida de {addr}: {message}")

            response = ("Olá do servidor UDP! Sua mensagem chegou sem criptografia.")

            # Reply straight back to whoever sent the datagram.
            server.sendto(response.encode("utf-8"), addr)
