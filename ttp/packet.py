# =============================================================================
# ttp/packet.py
# -----------------------------------------------------------------------------
# Defines the TTP segment format itself: the header layout, the control
# flags (SYN/ACK/FIN/RST/DATA), and the connection state-machine states.
# This is the TTP equivalent of a TCP segment (RFC 793), simplified for
# teaching purposes.
#
# TTP header layout (24 bytes total, see HEADER_FORMAT in constants.py):
#
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |         Source Port           |       Destination Port       |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                        Sequence Number                       |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Acknowledgment Number                     |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |    Flags      | Header Length |            Reserved          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |             Window            |         Payload Length       |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                           Checksum                           |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                        Payload (variable)                    |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# =============================================================================

import struct
from enum import IntFlag, IntEnum
from ttp.constants import HEADER_FORMAT

class TTPState(IntEnum):
    # Máquina de estados no estilo da RFC 793. O encerramento agora tem os
    # estados de verdade (antes só havia um "FIN_WAIT" genérico, que não
    # conseguia distinguir "esperando o ACK do meu FIN" de "esperando o FIN
    # do par" -- por isso era impossível fazer meio-fechamento ou saber que
    # o par já tinha terminado de enviar).
    #
    #   Abertura ativa :  CLOSED -> SYN_SENT -> ESTABLISHED
    #   Abertura passiva: CLOSED -> SYN_RECEIVED -> ESTABLISHED
    #   Fechamento ativo : ESTABLISHED -> FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT -> CLOSED
    #   Fechamento passivo: ESTABLISHED -> CLOSE_WAIT -> LAST_ACK -> CLOSED
    #   Fechamento simultâneo: FIN_WAIT_1 -> CLOSING -> TIME_WAIT -> CLOSED
    CLOSED = 0          # Nenhuma conexão / já encerrada.
    SYN_SENT = 1        # Cliente enviou SYN, espera SYN-ACK.
    SYN_RECEIVED = 2    # Servidor recebeu SYN, enviou SYN-ACK, espera ACK.
    ESTABLISHED = 3     # Handshake completo; dados fluem nos dois sentidos.
    FIN_WAIT_1 = 4      # Enviamos FIN, esperando o ACK dele.
    FIN_WAIT = 4        # (alias do nome antigo)
    CLOSING = 5         # FIN simultâneo: ambos enviaram FIN, falta o ACK do nosso.
    FIN_WAIT_2 = 6      # Nosso FIN foi confirmado; esperando o FIN do par.
    CLOSE_WAIT = 7      # O par já enviou FIN (EOF); nós ainda podemos enviar.
    LAST_ACK = 8        # Enviamos nosso FIN depois do FIN do par; esperando o ACK.
    TIME_WAIT = 9       # Tudo confirmado; fica re-ACKando FINs duplicados um tempo.

class TTPFlags(IntFlag):
    # Bitmask flags packed into a single byte in the header (see 'flags').
    # IntFlag lets us combine them with bitwise OR, e.g. SYN | ACK.
    NONE = 0x00

    SYN = 0x01   # Synchronize sequence numbers (start of handshake).
    ACK = 0x02   # Acknowledgment number field is significant.
    FIN = 0x04   # Sender has finished sending data (start of teardown).
    RST = 0x08   # Reset the connection (defined but not actively used here).
    DATA = 0x10  # Segment carries an application payload.

class TTPPacket:
    # HEADER_SIZE is computed once from the struct format string, so it
    # automatically stays correct if HEADER_FORMAT ever changes.
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(
        self,
        source_port: int,
        destination_port: int,
        sequence_number: int,
        acknowledgment_number: int,
        flags: TTPFlags,
        window_size: int,
        payload: bytes = b"",
        checksum: int = 0,
    ):

        self.source_port = source_port
        self.destination_port = destination_port
        self.sequence_number = sequence_number
        self.acknowledgment_number = acknowledgment_number
        self.flags = flags
        self.header_length = self.HEADER_SIZE
        self.reserved = 0
        self.window = window_size
        self.payload = payload
        self.checksum = checksum

    def pack(self) -> bytes:
        # Serializes this TTPPacket into the exact bytes to embed as the
        # payload of an IPv4 datagram (see ttp/ipv4.py / ttp/socket.py).
        if self.payload_length > 0xFFFF:
            raise ValueError("Payload excede o tamanho máximo suportado (65535 bytes).")

        header = struct.pack(
            HEADER_FORMAT,
            self.source_port,
            self.destination_port,
            self.sequence_number,
            self.acknowledgment_number,
            self.flags,
            self.header_length,
            self.reserved,
            self.window,
            self.payload_length,
            self.checksum,
        )

        return header + self.payload

    @classmethod
    def unpack(cls, data: bytes):
        # Reconstructs a TTPPacket from raw bytes received off the wire
        # (the IPv4 payload). Performs basic sanity checks on lengths
        # before trusting the declared header_length/payload_length.
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Pacote TTP menor que o cabeçalho.")

        header = data[:cls.HEADER_SIZE]

        (
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            flags,
            header_length,
            reserved,
            window_size,
            payload_length,
            checksum,

        ) = struct.unpack(HEADER_FORMAT, header)

        # header_length vem da rede, então é dado NÃO confiável. Antes não
        # era validado: um valor 0 fazia o "payload" incluir o próprio
        # cabeçalho, e um valor enorme fazia o pacote parecer incompleto.
        if header_length != cls.HEADER_SIZE:
            raise ValueError(f"header_length inválido: {header_length}.")

        expected_size = header_length + payload_length

        if len(data) < expected_size:
            raise ValueError("Pacote TTP incompleto.")

        # Payload starts right after the header and runs for payload_length
        # bytes (header_length here doubles as "offset to payload start").
        payload = data[header_length:expected_size]

        packet = cls(
            source_port=source_port,
            destination_port=destination_port,
            sequence_number=sequence_number,
            acknowledgment_number=acknowledgment_number,
            flags=TTPFlags(flags),
            window_size=window_size,
            payload=payload,
            checksum=checksum,
        )

        packet.header_length = header_length
        packet.reserved = reserved

        return packet

    @property
    def payload_length(self) -> int:
        # Always derived from the actual payload bytes, never stored
        # separately, so it can never drift out of sync.
        return len(self.payload)

    @property
    def segment_size(self) -> int:
        # Total size on the wire: header + payload.
        return self.HEADER_SIZE + self.payload_length

    @property
    def is_syn(self):
        return bool(self.flags & TTPFlags.SYN)

    @property
    def is_ack(self):
        return bool(self.flags & TTPFlags.ACK)

    @property
    def is_fin(self):
        return bool(self.flags & TTPFlags.FIN)

    @property
    def is_rst(self):
        return bool(self.flags & TTPFlags.RST)

    @property
    def is_data(self):
        return bool(self.flags & TTPFlags.DATA)

    @property
    def sequence_space(self) -> int:
        """
        How many sequence numbers this packet "uses up". Just like TCP,
        SYN and FIN each consume exactly one sequence number even though
        they carry no payload bytes -- this lets the receiver ACK them
        unambiguously.
        """

        size = len(self.payload)

        if self.is_syn:
            size += 1

        if self.is_fin:
            size += 1

        return size

    @property
    def consumes_sequence(self):
        # True for any packet that needs to advance the sender's sequence
        # counter: SYN, FIN, or a segment carrying application DATA.
        # Pure ACK packets (no SYN/FIN/DATA) do NOT consume sequence space.
        return (self.is_syn or self.is_fin or self.is_data)

    def __repr__(self):
        # Human-friendly summary, mainly used in log lines/print debugging.
        return (
            f"TTPPacket("
            f"{self.source_port} -> "
            f"{self.destination_port}, "
            f"SEQ={self.sequence_number}, "
            f"ACK={self.acknowledgment_number}, "
            f"FLAGS={self.flags}, "
            f"PAYLOAD={self.payload_length} bytes, "
            f"RESERVED={self.reserved}, "
            f"HEADER_LENGHT={self.header_length} bytes)"
        )

    @property
    def is_pure_ack(self) -> bool:
        # ACK puro: só confirma; não carrega dados nem consome sequência.
        return self.is_ack and not (self.payload or self.is_syn or self.is_fin or self.is_rst)

    def copy(self):
        # Shallow copy used before mutating fields (e.g. zeroing the
        # checksum to recompute it) so the original packet object -- which
        # may still be sitting in the retransmission window -- is untouched.
        return TTPPacket(
            source_port=self.source_port,
            destination_port=self.destination_port,
            sequence_number=self.sequence_number,
            acknowledgment_number=self.acknowledgment_number,
            flags=self.flags,
            window_size=self.window,
            payload=self.payload,
            checksum=self.checksum,
        )


def make_reset_for(packet: "TTPPacket") -> "TTPPacket":
    """
    Monta o RST que responde a um segmento que não pertence a nenhuma
    conexão (regra da RFC 793, "Reset Generation"):

      * se o segmento tinha ACK, o RST usa SEQ = ACK do segmento (é o número
        de sequência que o outro lado "espera" de nós);
      * senão, o RST leva ACK = SEQ + tamanho do segmento, com SEQ = 0.

    Um RST nunca é respondido com outro RST (evita ricochete infinito).
    """
    if packet.is_ack:
        return TTPPacket(
            source_port=packet.destination_port,
            destination_port=packet.source_port,
            sequence_number=packet.acknowledgment_number,
            acknowledgment_number=0,
            flags=TTPFlags.RST,
            window_size=0,
        )

    return TTPPacket(
        source_port=packet.destination_port,
        destination_port=packet.source_port,
        sequence_number=0,
        acknowledgment_number=(packet.sequence_number + packet.sequence_space) & 0xFFFFFFFF,
        flags=TTPFlags.RST | TTPFlags.ACK,
        window_size=0,
    )
