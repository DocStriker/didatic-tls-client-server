# =============================================================================
# transport/tcp.py
# -----------------------------------------------------------------------------
# Baseline "control group" implementation using the operating system's real
# TCP stack (Python's built-in `socket` module, SOCK_STREAM). This exists so
# the reader can compare a battle-tested, kernel-implemented transport
# protocol against the hand-written TTP implementation in ttp/.
#
# No encryption, no custom framing: whatever the client sends is exactly what
# the server receives (TCP is a byte stream, so in a more complex example
# you would normally need explicit message framing -- here a single recv()
# is enough because each side only exchanges one short message).
# =============================================================================

import socket

def client(host: str, port: int, message: str) -> None:
    # socket.create_connection() opens a TCP connection and performs the
    # classic 3-way handshake (SYN, SYN-ACK, ACK) transparently for us.
    with socket.create_connection((host, port), timeout=10) as client_socket:
        print(f"[Client][TCP] Conectado em {host}:{port}")

        # sendall() keeps calling send() internally until every byte of the
        # UTF-8 encoded message has been written to the socket buffer.
        client_socket.sendall((message).encode("utf-8"))

        # Blocks until up to 4096 bytes are available from the server.
        response = client_socket.recv(4096)

        print(f"[Client][TCP] Resposta: {response.decode('utf-8').strip()}")

def handle_client(conn: socket.socket, address: tuple[str, int]) -> None:
    # Handles a single already-accepted TCP connection: read one message,
    # print it, and answer with a canned response.
    print(f"[Server][TCP] Cliente conectado: {address[0]}:{address[1]}")

    data = conn.recv(4096)

    message = data.decode("utf-8").strip()

    print(f"[Server][TCP] Mensagem recebida: {message}")

    response = ("Olá do servidor TCP! Sua mensagem chegou sem criptografia.")

    conn.sendall(response.encode("utf-8"))

def server(host: str, port: int) -> None:
    # Standard BSD-socket server flow: create -> bind -> listen -> accept loop.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((host, port))
        server.listen()

        print(f"[Server][TCP] Aguardando conexões em {host}:{port}")

        while True:
            # accept() blocks until a client completes the TCP handshake.
            conn, addr = server.accept()
            handle_client(conn, addr)
            # This demo handles one client at a time (no threads); the
            # connection is closed before accept() is called again.
            conn.close()
