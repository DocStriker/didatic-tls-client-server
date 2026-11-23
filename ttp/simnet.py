# =============================================================================
# ttp/simnet.py
# -----------------------------------------------------------------------------
# Rede SIMULADA em memória, com o mesmo contrato do TTPSocket (send_packet /
# receive_packet), mas SEM raw sockets: não precisa de root e permite
# injetar defeitos de forma reprodutível (semente fixa):
#
#     loss       probabilidade de descartar um pacote
#     duplicate  probabilidade de entregá-lo duas vezes
#     reorder    probabilidade de atrasá-lo a mais (chega depois dos seguintes)
#     corrupt    probabilidade de inverter um byte (o checksum TTP deve pegar)
#     delay/jitter  latência de ida (s) e variação aleatória
#
# É assim que se TESTA a parte difícil do TTP (retransmissão, ordenação,
# janela) -- coisas que quase nunca acontecem no loopback real.
#
# Uso:
#     net = SimNetwork(loss=0.1, seed=1)
#     a = net.socket("10.0.0.1"); b = net.socket("10.0.0.2")
#     conn = TTPConnection("10.0.0.1", 0, "10.0.0.2", 9000, socket=a, owns_socket=False)
#
# Cada endereço IP tem UMA SimSocket; a rede roteia pelo IP de destino.
# =============================================================================

from __future__ import annotations

import heapq
import queue
import random
import socket
import threading
import time

from ttp.packet import TTPPacket
from ttp.socket import TTPSocket


class SimNetwork:
    def __init__(
        self,
        loss: float = 0.0,
        duplicate: float = 0.0,
        reorder: float = 0.0,
        corrupt: float = 0.0,
        delay: float = 0.002,
        jitter: float = 0.0,
        seed: int | None = None,
        drop_filter=None,
    ):
        self.loss = loss
        self.duplicate = duplicate
        self.reorder = reorder
        self.corrupt = corrupt
        self.delay = delay
        self.jitter = jitter
        # drop_filter(src_ip, dst_ip, packet) -> True para descartar: perda
        # DETERMINÍSTICA ("descarte o 3º segmento de dados").
        self.drop_filter = drop_filter
        # Enquanto True, a rede descarta tudo (enlace caiu / par morreu).
        self.partitioned = False

        self.rng = random.Random(seed)
        self.stats = dict(sent=0, delivered=0, dropped=0, duplicated=0, corrupted=0, reordered=0)

        self._endpoints: dict[str, SimSocket] = {}
        self._heap: list = []
        self._counter = 0
        self._cv = threading.Condition()
        self._closed = False

        self._thread = threading.Thread(target=self._run, daemon=True, name="simnet")
        self._thread.start()

    # ---- API --------------------------------------------------------------

    def socket(self, ip: str, timeout: float = 0.02) -> "SimSocket":
        endpoint = SimSocket(self, ip, timeout)

        with self._cv:
            self._endpoints[ip] = endpoint

        return endpoint

    def close(self) -> None:
        with self._cv:
            self._closed = True
            self._cv.notify_all()

    # ---- envio: aplica os defeitos -----------------------------------------

    def _submit(self, raw: bytes, source_ip: str, destination_ip: str, packet: TTPPacket) -> None:
        with self._cv:
            self.stats["sent"] += 1

            if self.partitioned:
                self.stats["dropped"] += 1
                return

            if self.drop_filter is not None and self.drop_filter(source_ip, destination_ip, packet):
                self.stats["dropped"] += 1
                return

            if self.rng.random() < self.loss:
                self.stats["dropped"] += 1
                return

            copies = 1

            if self.rng.random() < self.duplicate:
                copies = 2
                self.stats["duplicated"] += 1

            for _ in range(copies):
                data = raw
                latency = self.delay + self.rng.random() * self.jitter

                if self.rng.random() < self.reorder:
                    # Atraso extra: este pacote será ultrapassado pelos seguintes.
                    latency += self.rng.uniform(1.0, 4.0) * max(self.delay, 0.002)
                    self.stats["reordered"] += 1

                if self.rng.random() < self.corrupt:
                    buffer = bytearray(data)
                    # Só depois do cabeçalho IP (20 bytes): queremos testar o
                    # checksum do TTP, não o do IP (o kernel real já filtra).
                    index = self.rng.randrange(20, len(buffer))
                    buffer[index] ^= 1 << self.rng.randrange(8)
                    data = bytes(buffer)
                    self.stats["corrupted"] += 1

                self._counter += 1
                heapq.heappush(self._heap, (time.monotonic() + latency, self._counter, data, destination_ip))

            self._cv.notify_all()

    # ---- entrega -------------------------------------------------------------

    def _run(self) -> None:
        with self._cv:
            while not self._closed:
                if not self._heap:
                    self._cv.wait(0.1)
                    continue

                due, _, data, destination_ip = self._heap[0]
                wait = due - time.monotonic()

                if wait > 0:
                    self._cv.wait(wait)
                    continue

                heapq.heappop(self._heap)
                endpoint = self._endpoints.get(destination_ip)

                if endpoint is not None and endpoint.is_open:
                    endpoint._rx.put(data)
                    self.stats["delivered"] += 1
                else:
                    self.stats["dropped"] += 1


class SimSocket(TTPSocket):
    """TTPSocket que conversa com uma SimNetwork em vez de raw sockets."""

    def __init__(self, network: SimNetwork, ip: str, timeout: float = 0.02):
        # NÃO chama super().__init__ (ele abriria raw sockets de verdade).
        self.network = network
        self.ip = ip
        self.timeout = timeout
        self._rx: queue.Queue[bytes] = queue.Queue()
        self._open = True

    def send_packet(self, source_ip: str, destination_ip: str, packet: TTPPacket) -> None:
        if not self._open:
            raise OSError("socket simulado fechado")

        # Reaproveita a serialização REAL (IPv4 + TTP + checksum): assim a
        # corrupção injetada é pega pelo mesmo código que roda em produção.
        raw = self._build_raw_packet(source_ip, destination_ip, packet)

        self.network._submit(raw, source_ip, destination_ip, packet)

    def receive_packet(self):
        if not self._open:
            raise OSError("socket simulado fechado")

        try:
            raw = self._rx.get(timeout=self.timeout)
        except queue.Empty:
            raise socket.timeout("timed out")

        return self._parse_raw_packet(raw)

    def close(self) -> None:
        self._open = False

    @property
    def is_open(self) -> bool:
        return self._open
