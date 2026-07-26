from __future__ import annotations

from collections import OrderedDict

from ttp.packet import TTPPacket


class SendWindow:
    """
    Gerencia a janela de envio da conexão.

    Responsabilidades:
        - controlar bytes em voo;
        - armazenar pacotes pendentes;
        - liberar pacotes confirmados;
        - indicar retransmissões.
    """

    def __init__(self, size: int = 65535):

        self.size = size

        self.pending: OrderedDict[int, TTPPacket] = OrderedDict()

    def add(self, packet: TTPPacket) -> None:
        """
        Adiciona um pacote enviado à janela.
        """

        self.pending[packet.sequence_number] = packet

    def acknowledge(self, ack_number: int) -> None:
        """
        Remove todos os pacotes completamente confirmados.
        """

        confirmed = []

        for seq, packet in self.pending.items():

            end = packet.sequence_number + packet.sequence_space

            if end <= ack_number:
                confirmed.append(seq)

        for seq in confirmed:
            del self.pending[seq]

    def can_send(self, packet_size: int) -> bool:
        """
        Verifica se ainda existe espaço disponível na janela.
        """

        return (
            self.bytes_in_flight + packet_size
        ) <= self.size

    def packets_for_retransmission(self):
        """
        Iterador sobre os pacotes ainda pendentes.
        """

        yield from self.pending.values()

    def clear(self):

        self.pending.clear()

    @property
    def bytes_in_flight(self) -> int:
        return sum(
            packet.sequence_space
            for packet in self.pending.values()
        )

    @property
    def empty(self):

        return len(self.pending) == 0

    def __len__(self):

        return len(self.pending)

    def __repr__(self):

        return (
            f"SendWindow("
            f"size={self.size}, "
            f"pending={len(self.pending)})"
        )