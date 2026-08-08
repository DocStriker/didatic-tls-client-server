# =============================================================================
# ttp/window.py
# -----------------------------------------------------------------------------
# SendWindow implements the sender-side sliding window: outgoing packets
# wait in a FIFO `queue` until there is enough room in the window, then
# move into `pending` (sent, awaiting ACK). When ACKs arrive, fully
# acknowledged packets are removed from `pending`, freeing up window space
# for more packets to be sent. This is the same core idea TCP uses for flow
# control (bounded by the receiver's advertised window).
# =============================================================================

from __future__ import annotations
from collections import OrderedDict, deque
from ttp.packet import TTPPacket

class SendWindow:
    def __init__(self, size: int = 65535):
        self.size = size

        # Pacotes aguardando envio
        # (Packets waiting to be sent -- not yet transmitted at all.)
        self.queue: deque[TTPPacket] = deque()

        # Pacotes enviados e ainda não confirmados
        # (Packets already transmitted but not yet acknowledged, keyed by
        # their starting sequence number. OrderedDict preserves insertion
        # order, so `oldest()` below can cheaply find the earliest unacked
        # packet -- the one whose retransmission timer matters most.)
        self.pending: OrderedDict[int, TTPPacket] = OrderedDict()

    # ----------------------------------------------------
    # Fila (Queue)
    # ----------------------------------------------------

    def enqueue(self, packet: TTPPacket) -> None:
        """
        Adiciona um pacote para envio.
        """
        self.queue.append(packet)

    def next_packet(self) -> TTPPacket | None:
        """
        Retorna o próximo pacote aguardando envio.
        (Peeks at, without removing, the head of the send queue.)
        """
        if not self.queue:
            return None

        return self.queue[0]

    def mark_sent(self) -> TTPPacket | None:
        """
        Move um pacote da fila para a lista de pendentes.
        (Pops the head of the queue and moves it into `pending`, tracked by
        its sequence number so it can later be matched against an ACK.)
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
        # Cumulative ACK handling: any pending packet whose last sequence
        # byte is fully covered by ack_number is considered delivered and
        # removed from the pending map.
        confirmed = []

        for seq, packet in self.pending.items():

            end = packet.sequence_number + packet.sequence_space

            if end <= ack_number:
                confirmed.append(seq)

        for seq in confirmed:
            del self.pending[seq]

    # ----------------------------------------------------
    # Janela (Window)
    # ----------------------------------------------------

    @property
    def bytes_in_flight(self):
        # Total sequence space currently tied up in unacknowledged packets.
        return sum(packet.sequence_space for packet in self.pending.values())

    @property
    def bytes_available(self):
        # How much more we're allowed to have "in flight" before hitting
        # the window limit.
        return self.size - self.bytes_in_flight

    def can_send(self, packet_size: int):
        return packet_size <= self.bytes_available

    # ----------------------------------------------------
    # Retransmissão (Retransmission)
    # ----------------------------------------------------

    def pending_packets(self):
        # Generator over all currently unacknowledged packets, e.g. for a
        # "resend everything still pending" retransmission strategy.
        yield from self.pending.values()

    def oldest(self):
        # Returns the earliest (lowest sequence number, first inserted)
        # unacknowledged packet -- the one the retransmission timer is
        # conceptually tracking (Go-Back-N style: if the oldest packet
        # times out, that's what needs to be retransmitted first).
        if not self.pending:
            return None

        return next(iter(self.pending.values()))

    # ----------------------------------------------------
    # Utilidades (Utilities)
    # ----------------------------------------------------

    def clear(self):
        self.queue.clear()

        self.pending.clear()

    @property
    def empty(self):
        # True once there is nothing left queued AND nothing left pending
        # -- i.e. every byte sent so far has been fully acknowledged.
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
