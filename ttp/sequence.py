# =============================================================================
# ttp/sequence.py
# -----------------------------------------------------------------------------
# Controle dos números de sequência de UMA conexão, espelhando as variáveis
# SND.UNA / SND.NXT / RCV.NXT da RFC 793.
#
# O QUE MUDOU (e por quê):
#   * Os números são de 32 bits e "dão a volta" (wraparound): depois de
#     4 294 967 295 vem 0. O código antigo usava `<` e `>` comuns, e o ISN
#     aleatório podia ser, por exemplo, 4 294 967 290 -> poucos bytes depois
#     struct.pack("!I") estourava com "argument out of range". Agora toda
#     comparação usa a "aritmética de números de série" da RFC 1982.
#   * O ISN vem de `secrets` (criptograficamente aleatório), não de `random`:
#     um ISN previsível permite a um atacante fora do caminho forjar segmentos.
#
# INTUIÇÃO DA COMPARAÇÃO MÓDULO 2**32
#   Pense num relógio de 32 bits. "a vem antes de b" significa que b está à
#   frente de a por menos de meia volta (2**31):
#
#       seq_lt(a, b)  <=>  (a - b) mod 2**32  >= 2**31
#
#   Ex.: a = 4_294_967_290, b = 5  ->  (a-b) mod 2**32 = 4_294_967_285 >= 2**31
#        => a vem antes de b (b "deu a volta"), exatamente como queremos.
# =============================================================================

from __future__ import annotations

import secrets
from enum import Enum

from ttp.constants import SEQ_HALF, SEQ_MASK


# ----------------------------------------------------------------------------
# Aritmética módulo 2**32
# ----------------------------------------------------------------------------

def seq_add(a: int, n: int) -> int:
    """a + n, com wraparound."""
    return (a + n) & SEQ_MASK


def seq_diff(a: int, b: int) -> int:
    """Distância 'para frente' de b até a: (a - b) mod 2**32."""
    return (a - b) & SEQ_MASK


def seq_lt(a: int, b: int) -> bool:
    """a vem estritamente antes de b."""
    return seq_diff(a, b) >= SEQ_HALF


def seq_leq(a: int, b: int) -> bool:
    return a == b or seq_lt(a, b)


def seq_gt(a: int, b: int) -> bool:
    return seq_lt(b, a)


def seq_geq(a: int, b: int) -> bool:
    return seq_leq(b, a)


class ReceiveStatus(Enum):
    # Resultado de classificar um segmento que acabou de chegar.
    EXPECTED = 0       # começa exatamente em RCV.NXT -> aceita
    DUPLICATE = 1      # já recebido por inteiro (ACK perdido?) -> só re-ACK
    FUTURE = 2         # chegou adiantado (há um buraco antes) -> guarda
    OVERLAP = 3        # começa em dados já recebidos mas traz bytes novos -> apara
    OUT_OF_WINDOW = 4  # além da janela anunciada -> descarta e re-ACK


class SequenceSpace:
    """
    send_unacked (SND.UNA) -> byte mais antigo enviado e ainda não confirmado.
    send_next    (SND.NXT) -> próximo número de sequência a usar ao enviar.
    recv_next    (RCV.NXT) -> próximo byte que esperamos receber do par.

    Invariante do remetente:  SND.UNA <= SND.NXT   (tudo módulo 2**32)
        bytes em voo = SND.NXT - SND.UNA
    """

    def __init__(self, initial_sequence: int | None = None):
        if initial_sequence is None:
            initial_sequence = secrets.randbits(32)

        self.initial_sequence = initial_sequence & SEQ_MASK
        self.send_unacked = self.initial_sequence
        self.send_next = self.initial_sequence
        self.recv_next = 0

    # ---- lado que envia -------------------------------------------------

    @property
    def bytes_in_flight(self) -> int:
        return seq_diff(self.send_next, self.send_unacked)

    def advance_send(self, amount: int) -> None:
        self.send_next = seq_add(self.send_next, amount)

    def acknowledge(self, ack_number: int) -> bool:
        """
        Avança SND.UNA se `ack_number` confirma algo novo e legítimo:
            SND.UNA < ack <= SND.NXT
        ACK velho (duplicado/reordenado) ou ACK de algo que nunca enviamos
        são ignorados -> retorna False e não mexe no estado.
        """
        if seq_lt(self.send_unacked, ack_number) and seq_leq(ack_number, self.send_next):
            self.send_unacked = ack_number
            return True

        return False

    # ---- lado que recebe ------------------------------------------------

    def classify(self, sequence_number: int, length: int, window: int) -> ReceiveStatus:
        """
        Classifica um segmento [seq, seq+length) em relação a RCV.NXT e à
        janela de recepção `window` (bytes que ainda cabem no buffer).

              já recebido        |  esperado ... janela  |  além
          ...-----------------RCV.NXT====================RCV.NXT+window----...
        """
        offset = seq_diff(sequence_number, self.recv_next)

        if offset == 0:
            return ReceiveStatus.EXPECTED

        if offset >= SEQ_HALF:
            # seq está ANTES de RCV.NXT.
            already_have = seq_diff(self.recv_next, sequence_number)

            if already_have >= length:
                return ReceiveStatus.DUPLICATE

            return ReceiveStatus.OVERLAP

        # seq está DEPOIS de RCV.NXT: há um buraco.
        if offset < window:
            return ReceiveStatus.FUTURE

        return ReceiveStatus.OUT_OF_WINDOW

    def advance_receive(self, amount: int) -> None:
        self.recv_next = seq_add(self.recv_next, amount)

    def receive(self, sequence_number: int, amount: int) -> ReceiveStatus:
        """
        Versão simples (sem janela), mantida por compatibilidade: se o
        segmento é o esperado, já avança RCV.NXT.
        """
        status = self.classify(sequence_number, amount, window=1 << 31)

        if status is ReceiveStatus.EXPECTED:
            self.advance_receive(amount)

        return status

    def __repr__(self):
        return (
            "SequenceSpace("
            f"SND.UNA={self.send_unacked}, "
            f"SND.NXT={self.send_next}, "
            f"RCV.NXT={self.recv_next})"
        )
