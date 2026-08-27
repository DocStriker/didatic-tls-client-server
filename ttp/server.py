# =============================================================================
# ttp/server.py
# -----------------------------------------------------------------------------
# TTPServer is the persistent listening endpoint of TTP.
#
# Unlike TTPConnection, TTPServer does not represent an established
# connection. It owns the listening RAW socket and creates a new
# TTPConnection for every incoming SYN.
# =============================================================================

from ttp.connection import TTPConnection
from ttp.packet import TTPFlags, TTPState
from ttp.socket import TTPSocket
from ttp.constants import DEFAULT_WINDOW_SIZE
import socket


class TTPServer:
    def __init__(
        self,
        local_ip: str,
        local_port: int,
        window_size: int = DEFAULT_WINDOW_SIZE,
        side_name: str = "Server",
    ):
        self.local_ip = local_ip
        self.local_port = local_port
        self.window_size = window_size
        self.side_name = side_name

        # Single RAW socket owned by the persistent listener.
        self.socket = TTPSocket(timeout=0.5)

        self.running = False

    def _wait_for_syn(self):
        """
        Waits for an incoming SYN.

        Unlike TTPConnection._wait_for_packet(), the listener does not know
        the remote endpoint yet, so it only filters by destination port
        and SYN flag.
        """

        while self.running:
            try:
                packet, ipv4 = self.socket.receive_packet()

            except socket.timeout:
                continue

            if packet.destination_port != self.local_port:
                continue

            if not (packet.flags & TTPFlags.SYN):
                continue

            return packet, ipv4

        return None, None

    def accept(self) -> TTPConnection:
        """
        Waits for an incoming SYN and creates an established TTPConnection.

        This is the TTP equivalent of a listening TCP socket's accept().
        """

        if not self.running:
            raise RuntimeError("Servidor não está iniciado.")

        syn, ipv4 = self._wait_for_syn()

        if syn is None:
            raise RuntimeError("Servidor encerrado durante accept().")

        connection = TTPConnection(
            local_ip=self.local_ip,
            local_port=self.local_port,
            remote_ip=ipv4.source_ip,
            remote_port=syn.source_port,
            window_size=self.window_size,
            side_name=self.side_name,
            socket=self.socket,
            owns_socket=False
        )

        connection._server_handshake_from_syn(syn)

        connection._start_receiver()

        return connection

    def start(self):
        if self.running:
            raise RuntimeError("Servidor já está iniciado.")

        self.running = True

    def close(self):
        if not self.running:
            return

        self.running = False
        self.socket.close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False