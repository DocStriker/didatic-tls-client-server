# =============================================================================
# ttp/dispatcher.py
# -----------------------------------------------------------------------------
# PacketDispatcher: UMA thread lê o socket e ENTREGA cada pacote à conexão
# certa (demultiplexação).
#
# POR QUE ISSO EXISTE
#   O socket raw do TTP recebe TODO tráfego do protocolo 253 da máquina. No
#   código antigo, cada TTPConnection lia direto desse socket e simplesmente
#   DESCARTAVA o que não era dela ("continue"). Com mais de uma conexão
#   (vários clientes no mesmo servidor) as threads receptoras roubavam
#   pacotes umas das outras. Pior: qualquer pacote com checksum ruim
#   levantava ValueError e MATAVA a thread receptora para sempre.
#
#   Agora:
#     * um pacote inválido (checksum, tamanho, versão) é apenas descartado e
#       contado -- exatamente como o TCP faz;
#     * a chave de roteamento é (IP do par, porta do par): cada conexão tem
#       sua própria fila (inbox);
#     * pacote que não pertence a nenhuma conexão vai para `on_unmatched`
#       (o servidor decide: SYN novo -> cria conexão; resto -> RST).
# =============================================================================

from __future__ import annotations

import queue
import socket
import threading

from ttp.log_config import LoggerManager


class PacketDispatcher:
    def __init__(self, ttp_socket, local_port: int, on_unmatched=None, name: str = "dispatcher"):
        self.socket = ttp_socket
        self.local_port = local_port
        self.on_unmatched = on_unmatched
        self.logger = LoggerManager(name)

        self._routes: dict[tuple[str, int], queue.Queue] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name=f"ttp-{name}")

        self.bad_packets = 0   # descartados por checksum/formato inválido
        self.unmatched = 0     # sem conexão correspondente

    # ---- ciclo de vida -----------------------------------------------------

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # ---- tabela de rotas ---------------------------------------------------

    def register(self, remote_ip: str, remote_port: int, inbox: queue.Queue) -> None:
        with self._lock:
            self._routes[(remote_ip, remote_port)] = inbox

    def unregister(self, remote_ip: str, remote_port: int, inbox: queue.Queue | None = None) -> None:
        with self._lock:
            current = self._routes.get((remote_ip, remote_port))

            # Só remove se a rota ainda é DESTA conexão (uma conexão nova com
            # o mesmo par pode ter assumido a chave).
            if current is not None and (inbox is None or current is inbox):
                del self._routes[(remote_ip, remote_port)]

    # ---- laço principal ----------------------------------------------------

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                packet, ipv4 = self.socket.receive_packet()

            except socket.timeout:
                continue

            except ValueError as error:
                # Checksum inválido, pacote truncado, protocolo errado...
                # Descarta e segue: o remetente vai retransmitir.
                self.bad_packets += 1
                self.logger.debug(f"pacote inválido descartado: {error}")
                continue

            except OSError:
                if self._stop.is_set() or not self.socket.is_open:
                    break

                # Erro transitório do kernel (ex.: ENOBUFS): não derruba o laço.
                self._stop.wait(0.01)
                continue

            if packet.destination_port != self.local_port:
                continue  # tráfego de outra porta/aplicação (ou eco do que enviamos)

            with self._lock:
                inbox = self._routes.get((ipv4.source_ip, packet.source_port))

            if inbox is not None:
                inbox.put((packet, ipv4))
            else:
                self.unmatched += 1

                if self.on_unmatched is not None:
                    try:
                        self.on_unmatched(packet, ipv4)
                    except Exception as error:  # nunca derruba o dispatcher
                        self.logger.log(f"erro em on_unmatched: {error!r}")
