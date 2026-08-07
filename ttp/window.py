from __future__ import annotations
from collections import OrderedDict, deque
from ttp.packet import TTPPacket

class SendWindow:
    def __init__(self, size: int = 65535):
        self.size = size

        # Pacotes aguardando envio
        self.queue: deque[TTPPacket] = deque()

        # Pacotes enviados e ainda não confirmados
        self.pending: OrderedDict[int, TTPPacket] = OrderedDict()

    # ----------------------------------------------------
    # Fila
    # ----------------------------------------------------

    def enqueue(self, packet: TTPPacket) -> None:
        """
        Adiciona um pacote para envio.
        """
        self.queue.append(packet)

    def next_packet(self) -> TTPPacket | None:
        """
        Retorna o próximo pacote aguardando envio.
        """
        if not self.queue:
            return None

        return self.queue[0]

    def mark_sent(self) -> TTPPacket | None:
        """
        Move um pacote da fila para a lista de pendentes.
        """
        if not self.queue:
            return None

        packet = self.queue.popleft()

        self.pending[packet.sequence_number] = packet

        return packet

    # ----------------------------------------------------
    # ACK
    # ----------------------------------------------------

    def acknowledge(self, ack_number: int):
        confirmed = []

        for seq, packet in self.pending.items():

            end = packet.sequence_number + packet.sequence_space

            if end <= ack_number:
                confirmed.append(seq)

        for seq in confirmed:
            del self.pending[seq]

    # ----------------------------------------------------
    # Janela
    # ----------------------------------------------------

    @property
    def bytes_in_flight(self):
        return sum(packet.sequence_space for packet in self.pending.values())

    @property
    def bytes_available(self):
        return self.size - self.bytes_in_flight

    def can_send(self, packet_size: int):
        return packet_size <= self.bytes_available

    # ----------------------------------------------------
    # Retransmissão
    # ----------------------------------------------------

    def pending_packets(self):
        yield from self.pending.values()

    def oldest(self):
        if not self.pending:
            return None

        return next(iter(self.pending.values()))

    # ----------------------------------------------------
    # Utilidades
    # ----------------------------------------------------

    def clear(self):
        self.queue.clear()

        self.pending.clear()

    @property
    def empty(self):
        return (not self.queue and not self.pending)

    @property
    def queued(self):
        return len(self.queue)

    @property
    def pending_count(self):
        return len(self.pending)

    def __repr__(self):
        return (
            "SendWindow("
            f"queue={len(self.queue)}, "
            f"pending={len(self.pending)}, "
            f"bytes={self.bytes_in_flight}/{self.size}"
            ")"
        )