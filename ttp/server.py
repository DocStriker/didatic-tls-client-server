# =============================================================================
# ttp/server.py
# -----------------------------------------------------------------------------
# TTPServer: ponto de escuta persistente do TTP (o "listening socket").
#
# O QUE MUDOU:
#   * Aceita VÁRIOS clientes ao mesmo tempo. Um PacketDispatcher lê o socket
#     raw e entrega cada pacote à conexão certa (chave: IP+porta do par).
#     Antes, todas as conexões liam do mesmo socket e roubavam pacotes umas
#     das outras.
#   * O handshake é conduzido pela thread da própria conexão (com
#     retransmissão do SYN-ACK); accept() só devolve conexões JÁ
#     ESTABELECIDAS.
#   * SYN para porta sem listener (ou com o servidor fechado) recebe RST:
#     o cliente falha rápido com TTPRefused em vez de esperar timeout.
#   * `backlog` limita conexões semi-abertas (defesa básica contra SYN flood).
#   * O IP de origem das respostas é o IP para o qual o cliente enviou
#     (funciona com local_ip="0.0.0.0").
# =============================================================================

from __future__ import annotations

import queue
import threading

from ttp.config import TTPConfig
from ttp.connection import TTPConnection
from ttp.constants import DEFAULT_WINDOW_SIZE
from ttp.dispatcher import PacketDispatcher
from ttp.errors import TTPClosed
from ttp.log_config import LoggerManager
from ttp.packet import TTPPacket, TTPState, make_reset_for
from ttp.socket import TTPSocket

_CLOSED = object()


class TTPServer:
    def __init__(
        self,
        local_ip: str,
        local_port: int,
        window_size: int = DEFAULT_WINDOW_SIZE,
        side_name: str = "Server",
        socket: TTPSocket | None = None,
        config: TTPConfig | None = None,
        backlog: int = 64,
    ):
        self.local_ip = local_ip
        self.local_port = local_port
        self.window_size = window_size
        self.side_name = side_name
        self.config = config
        self.backlog = backlog
        self.logger = LoggerManager(side_name)

        # Single RAW socket owned by the persistent listener.
        self.socket = socket or TTPSocket(timeout=0.1)

        self.running = False
        self.dispatcher: PacketDispatcher | None = None

        self._connections: dict[tuple[str, int], TTPConnection] = {}
        self._accept_queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self._socket_released = False

    # ---- ciclo de vida -----------------------------------------------------

    def start(self) -> None:
        if self.running:
            raise RuntimeError("Servidor já está iniciado.")

        self.running = True
        self.dispatcher = PacketDispatcher(
            self.socket, self.local_port, on_unmatched=self._on_unmatched, name=f"{self.side_name}-rx"
        )
        self.dispatcher.start()

    def accept(self, timeout: float | None = None) -> TTPConnection:
        """
        Devolve a próxima conexão ESTABELECIDA (equivalente ao accept() de um
        socket TCP em escuta). Levanta TTPClosed se o servidor for fechado e
        TimeoutError se `timeout` esgotar.
        """
        if not self.running and self._accept_queue.empty():
            raise RuntimeError("Servidor não está iniciado.")

        try:
            item = self._accept_queue.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("accept() excedeu o tempo limite.")

        if item is _CLOSED:
            self._accept_queue.put(_CLOSED)  # acorda também outros accept() em espera
            raise TTPClosed("Servidor encerrado durante accept().")

        return item

    def close(self) -> None:
        """
        Para de aceitar conexões novas. As já estabelecidas continuam até
        terminarem; o socket só é liberado quando a última fecha (antes,
        fechar o listener matava as conexões em andamento).
        """
        with self._lock:
            if not self.running:
                return

            self.running = False
            idle = not self._connections

        self._accept_queue.put(_CLOSED)

        if idle:
            self._release_socket()

    def _release_socket(self) -> None:
        with self._lock:
            if self._socket_released:
                return

            self._socket_released = True

        if self.dispatcher is not None:
            self.dispatcher.stop()

        self.socket.close()

    # ---- pacotes sem conexão (roda na thread do dispatcher) -------------------

    def _on_unmatched(self, packet: TTPPacket, ipv4) -> None:
        if packet.is_rst:
            return  # nunca se responde RST com RST

        if self.local_ip not in ("0.0.0.0", ipv4.destination_ip):
            return  # endereçado a outro IP desta máquina

        is_new_syn = packet.is_syn and not packet.is_ack

        if is_new_syn and self.running:
            with self._lock:
                half_open = sum(
                    1 for c in self._connections.values() if c.state == TTPState.SYN_RECEIVED
                )

            if half_open >= self.backlog:
                self.logger.log("backlog cheio: SYN descartado")
                return  # o cliente retransmite o SYN mais tarde

            connection = TTPConnection(
                local_ip=ipv4.destination_ip,
                local_port=self.local_port,
                remote_ip=ipv4.source_ip,
                remote_port=packet.source_port,
                window_size=self.window_size,
                side_name=self.side_name,
                socket=self.socket,
                owns_socket=False,
                config=self.config,
                dispatcher=self.dispatcher,
                on_established=self._on_established,
                on_closed=self._on_closed,
            )

            with self._lock:
                self._connections[(ipv4.source_ip, packet.source_port)] = connection

            connection._begin_passive(packet)
            return

        # Qualquer outra coisa: ninguém conhece essa conexão -> RST.
        try:
            self.socket.send_packet(ipv4.destination_ip, ipv4.source_ip, make_reset_for(packet))
        except OSError:
            pass

    def _on_established(self, connection: TTPConnection) -> None:
        self._accept_queue.put(connection)

    def _on_closed(self, connection: TTPConnection) -> None:
        with self._lock:
            key = (connection.remote_ip, connection.remote_port)

            if self._connections.get(key) is connection:
                del self._connections[key]

            finished = not self.running and not self._connections

        if finished:
            self._release_socket()

    @property
    def connections(self) -> list[TTPConnection]:
        with self._lock:
            return list(self._connections.values())

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
