# =============================================================================
# ttp/sequence.py
# -----------------------------------------------------------------------------
# Tracks the sequence-number bookkeeping for one TTP connection, mirroring
# the "SND.UNA / SND.NXT / RCV.NXT" variables from TCP's RFC 793 state
# machine. This is the piece of state that lets TTP tell the difference
# between "this is the data I was expecting next", "I already saw this
# (duplicate)", and "this arrived out of order (future segment)".
# =============================================================================

from __future__ import annotations
import random
from enum import Enum

class ReceiveStatus(Enum):
    # Outcome of trying to accept an incoming segment's sequence number.
    EXPECTED = 0   # Exactly the next byte we needed -> accept immediately.
    DUPLICATE = 1  # Already-seen data (e.g. our ACK was lost) -> re-ACK, discard.
    FUTURE = 2     # Arrived ahead of what we need -> buffer until the gap fills.

class SequenceSpace:
    """
    Manages the sequence-number space of a TTP connection.
     send_next    -> next sequence number this side will use when sending.
     send_unacked -> oldest byte we sent that hasn't been ACKed yet.
     recv_next    -> next byte we expect to receive from the peer.
    """

    def __init__(self, initial_sequence: int | None = None, receive_sequence: int = 0,):
        if initial_sequence is None:
            # Just like TCP's Initial Sequence Number (ISN), start from a
            # random 32-bit value instead of always 0, so that stale
            # segments from a previous connection are unlikely to be
            # mistaken for new ones.
            initial_sequence = random.randint(0, 0xFFFFFFFF)

        self.initial_sequence = initial_sequence
        self.send_unacked = initial_sequence
        self.send_next = initial_sequence
        self.recv_next = 0
        self.send_window = 4096

    def can_send(self, size: int) -> bool:
        # True if sending `size` more bytes would still fit under the
        # current flow-control window (sliding-window style admission check).
        return (self.bytes_in_flight + size <= self.send_window)

    def receive(self, sequence_number: int, amount: int,) -> ReceiveStatus:
        # Classifies an incoming segment relative to what we expect next.
        if sequence_number == self.recv_next:
            # Exactly what we needed: advance the "next expected" pointer.
            self.recv_next += amount

            return ReceiveStatus.EXPECTED

        if sequence_number < self.recv_next:
            # We've already advanced past this sequence number before ->
            # this segment (or its ACK) must have been retransmitted.
            return ReceiveStatus.DUPLICATE

        # sequence_number > recv_next: there's a gap, some earlier segment
        # hasn't arrived yet.
        return ReceiveStatus.FUTURE

    @property
    def bytes_in_flight(self) -> int:
        """
        Amount of data sent but not yet acknowledged -- the classic
        "in-flight" quantity used for flow/congestion control decisions.
        """
        return self.send_next - self.send_unacked

    def advance_send(self, amount: int) -> None:
        """
        Called every time we build a packet that consumes sequence space,
        so the next packet gets the correct following sequence number.
        """
        self.send_next += amount

    def acknowledge(self, ack_number: int) -> None:
        """
        Moves send_unacked forward, but only forward -- an ACK for data we
        already considered acknowledged is simply ignored, protecting
        against out-of-order or duplicate ACKs rewinding our state.
        """
        if ack_number > self.send_unacked:
            self.send_unacked = ack_number

    def expect(self, sequence_number: int, amount: int) -> bool:
        """
        Strict variant of receive(): only accepts an exact match and
        advances recv_next; otherwise leaves state untouched and returns
        False. Provided as a simpler alternative to receive()/ReceiveStatus
        for callers that don't need to distinguish DUPLICATE from FUTURE.
        """

        if sequence_number != self.recv_next:
            return False

        self.recv_next += amount
        return True

    def reset(self) -> None:
        # Restores send_unacked/send_next back to the connection's initial
        # sequence number and clears recv_next -- effectively "rewinds" the
        # sequence space (not used in the current connection lifecycle, but
        # handy for tests or reconnect logic).
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
