from __future__ import annotations

import random

class SequenceSpace:
    """
    Gerencia o espaço de sequência de uma conexão TTP.

    send_next:
        Próximo número de sequência a ser utilizado ao enviar.

    send_unacked:
        Primeiro byte ainda não confirmado pelo receptor.

    recv_next:
        Próximo byte esperado do remetente.
    """

    def __init__(self, initial_sequence: int | None = None, receive_sequence: int = 0,):

        if initial_sequence is None:
            initial_sequence = random.randint(0, 0xFFFFFFFF)

        self.initial_sequence = initial_sequence

        self.send_unacked = initial_sequence
        self.send_next = initial_sequence

        self.recv_next = 0

    @property
    def bytes_in_flight(self) -> int:
        """
        Quantidade de bytes enviados e ainda não confirmados.
        """
        return self.send_next - self.send_unacked

    def advance_send(self, amount: int) -> None:
        """
        Avança o próximo número de sequência disponível.
        """
        self.send_next += amount

    def acknowledge(self, ack_number: int) -> None:
        """
        Atualiza o maior ACK recebido.
        """
        if ack_number > self.send_unacked:
            self.send_unacked = ack_number

    def expect(self, sequence_number: int, amount: int) -> bool:
        """
        Verifica se o pacote recebido possui o número
        de sequência esperado.
        """

        if sequence_number != self.recv_next:
            return False

        self.recv_next += amount
        return True

    def reset(self) -> None:

        self.send_unacked = self.initial_sequence
        self.send_next = self.initial_sequence
        self.recv_next = 0

    def __repr__(self):

        return (
            "SequenceSpace("
            f"SND.UNA={self.send_unacked}, "
            f"SND.NXT={self.send_next}, "
            f"RCV.NXT={self.recv_next})"
        )