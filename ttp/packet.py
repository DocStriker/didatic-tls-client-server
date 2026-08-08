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
#  |         Source Port          |       Destination Port       |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                        Sequence Number                       |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Acknowledgment Number                     |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |    Flags      | Header Length |            Reserved          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |             Window           |         Payload Length        |
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
    # Deliberately much simpler than TCP's 11-state machine (RFC 793),
    # covering only the states this didactic implementation actually needs.
    CLOSED = 0          # No connection exists yet / has been torn down.
    SYN_SENT = 1        # Client sent SYN, waiting for SYN-ACK.
    SYN_RECEIVED = 2    # Server received SYN, sent SYN-ACK, waiting for ACK.
    ESTABLISHED = 3     # Handshake complete; data can flow both ways.
    FIN_WAIT = 4        # We sent our FIN and are waiting for it to be ACKed.
    CLOSING = 5         # Reserved for a full FIN/FIN-ACK teardown (unused by
                         # the current close() implementation, kept for clarity).

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
        Quantidade de números de sequência consumidos por este pacote.
        (How many sequence numbers this packet "uses up". Just like TCP,
        SYN and FIN each consume exactly one sequence number even though
        they carry no payload bytes -- this lets the receiver ACK them
        unambiguously.)
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
