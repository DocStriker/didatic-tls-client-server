# =============================================================================
# ttls/transport.py
# -----------------------------------------------------------------------------
# Adaptador que faz um socket TCP comum (ou um socketpair) obedecer ao
# contrato de transporte do TTLSSession: send / recv(max, timeout) / close.
# Serve para testar o TTLS sem raw sockets e para rodar TTLS sobre TCP real.
# =============================================================================

import socket


class SocketTransport:
    def __init__(self, sock: socket.socket):
        self.sock = sock

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv(self, max_bytes: int, timeout: float | None = None) -> bytes:
        self.sock.settimeout(timeout)

        try:
            return self.sock.recv(max_bytes)
        except socket.timeout:
            raise TimeoutError("recv() excedeu o tempo limite.") from None
        except ConnectionError:
            return b""

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        self.sock.close()
