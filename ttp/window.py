# =============================================================================
# ttp/window.py
# -----------------------------------------------------------------------------
# SendWindow: o que está "em voo" (enviado e ainda sem ACK) do lado remetente.
#
# O QUE MUDOU:
#   * Antes, `size` era o tamanho do buffer LOCAL (fixo em 4096) -- ou seja,
#     não havia controle de fluxo de verdade: o remetente ignorava a janela
#     que o receptor anuncia em cada segmento. Agora `size` é atualizado com
#     a janela ANUNCIADA PELO PAR (ver TTPConnection._update_peer_window).
#   * A fila de envio (`queue`) saiu daqui: a conexão guarda um buffer de
#     BYTES e só "corta" um segmento na hora de enviar, respeitando janela e
#     MSS. Assim nunca existe um pacote maior que a janela esperando para
#     sempre (era exatamente o deadlock com mensagens > 4096 bytes).
#   * Cada segmento em voo guarda `sent_at` (para medir RTT) e
#     `retransmitted` (algoritmo de Karn).
#   * A comparação de ACK usa aritmética módulo 2**32 (wraparound).
#
#      SND.UNA                         SND.NXT
#         |<------ em voo (sem ACK) ------>|<---- ainda pode enviar ---->|
#         |<------------------ janela do par (size) ------------------->|
# =============================================================================

from __future__ import annotations

from collections import OrderedDict

from ttp.constants import DEFAULT_WINDOW_SIZE
from ttp.packet import TTPPacket
from ttp.sequence import seq_add, seq_leq


class InFlight:
    """Um segmento enviado e ainda não confirmado."""

    __slots__ = ("packet", "sent_at", "retransmitted")

    def __init__(self, packet: TTPPacket, sent_at: float):
        self.packet = packet
        self.sent_at = sent_at
        self.retransmitted = False


class SendWindow:
    def __init__(self, size: int = DEFAULT_WINDOW_SIZE):
        # Janela anunciada pelo par (bytes que ele aceita receber agora).
        self.size = size

        # Em voo, indexado pelo número de sequência inicial do segmento.
        # OrderedDict mantém a ordem de envio: o primeiro é o mais antigo.
        self.pending: OrderedDict[int, InFlight] = OrderedDict()

    # ---- registro ------------------------------------------------------

    def track(self, packet: TTPPacket, now: float) -> InFlight:
        item = InFlight(packet, now)

        self.pending[packet.sequence_number] = item

        return item

    # ---- ACK -------------------------------------------------------------

    def acknowledge(self, ack_number: int) -> list[InFlight]:
        """
        ACK cumulativo: remove todo segmento cujo ÚLTIMO byte já está
        coberto por `ack_number`. Devolve os removidos (na ordem de envio).
        Um ACK que cai no meio de um segmento não o remove.
        """
        confirmed = []

        for seq, item in self.pending.items():
            end = seq_add(seq, item.packet.sequence_space)

            if seq_leq(end, ack_number):
                confirmed.append(seq)
            else:
                break  # OrderedDict está em ordem de sequência

        return [self.pending.pop(seq) for seq in confirmed]

    # ---- janela ------------------------------------------------------------

    @property
    def bytes_in_flight(self) -> int:
        return sum(item.packet.sequence_space for item in self.pending.values())

    @property
    def bytes_available(self) -> int:
        return max(0, self.size - self.bytes_in_flight)

    def can_send(self, packet_size: int) -> bool:
        return packet_size <= self.bytes_available

    # ---- retransmissão -----------------------------------------------------

    def pending_packets(self):
        for item in self.pending.values():
            yield item.packet

    def oldest(self) -> InFlight | None:
        """O segmento sem ACK mais antigo: aquele que o timer vigia."""
        if not self.pending:
            return None

        return next(iter(self.pending.values()))

    # ---- utilidades ----------------------------------------------------------

    def clear(self):
        self.pending.clear()

    @property
    def empty(self) -> bool:
        return not self.pending

    @property
    def pending_count(self) -> int:
        return len(self.pending)

    def __repr__(self):
        return (
            "SendWindow("
            f"pending={len(self.pending)}, "
            f"bytes={self.bytes_in_flight}/{self.size}"
            ")"
        )
