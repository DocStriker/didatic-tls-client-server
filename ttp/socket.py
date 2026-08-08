# =============================================================================
# ttp/socket.py
# -----------------------------------------------------------------------------
# TTPSocket is the lowest layer of the TTP stack: it owns the two raw OS
# sockets used to actually put bytes on the wire and pull them back off,
# and it glues together IPv4Packet + TTPPacket + checksum validation into
# simple send_packet()/receive_packet() calls.
#
# IMPORTANT: SOCK_RAW sockets require elevated privileges (root on
# Linux/macOS, Administrator + special setup on Windows) because they let a
# program bypass the normal TCP/UDP kernel processing and inject/observe
# raw IP traffic directly.
# =============================================================================

import socket

from ttp.packet import TTPPacket
from ttp.ipv4 import IPv4Packet
from ttp.checksums import calculate_ttp_checksum, validate_ttp_checksum
from ttp.constants import TTP_PROTOCOL

class TTPSocket:
    def __init__(self, timeout: float | None = None):
        # Two separate raw sockets are used: one purely for sending
        # (with IP_HDRINCL so *we* control the IP header) and one purely
        # for receiving (bound to our custom protocol number so the kernel
        # filters out everything that isn't TTP traffic for us).
        self.send_socket = self._create_send_socket()
        self.receive_socket = self._create_receive_socket()

        if timeout is not None:
            self.receive_socket.settimeout(timeout)

    def _create_send_socket(self) -> socket.socket:
        """
        Socket utilizado somente para envio.
        Espera um pacote IPv4 completo.
        (Send-only socket. IPPROTO_RAW + IP_HDRINCL means the kernel will
        NOT add its own IP header -- we must supply a complete, valid IPv4
        datagram ourselves, which is exactly what IPv4Packet.pack() builds.)
        """

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_RAW,
        )

        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_HDRINCL,
            1,
        )

        return sock

    def _create_receive_socket(self) -> socket.socket:
        """
        Socket utilizado somente para recepção.
        Recebe apenas pacotes cujo protocolo seja o TTP.
        (Receive-only socket. Opening a raw socket with our custom protocol
        number (253) as the third argument tells the kernel to hand us only
        IP datagrams whose "Protocol" field matches TTP_PROTOCOL -- so we
        never see stray TCP/UDP/ICMP traffic here.)
        """

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            TTP_PROTOCOL,
        )

        return sock

    def send_packet(self, source_ip: str, destination_ip: str, packet: TTPPacket) -> None:
        # Wraps a TTPPacket inside a full IPv4 datagram and ships it out.
        raw_packet = self._build_raw_packet(
            source_ip,
            destination_ip,
            packet,
        )

        # Port 0 in sendto()'s address tuple is irrelevant for raw IP
        # sockets (there is no L4 port concept at this layer); only the
        # destination IP actually matters for routing.
        self.send_socket.sendto(raw_packet, (destination_ip, 0))

    def receive_packet(self) -> tuple[TTPPacket, IPv4Packet]:
        # Blocks (or times out) waiting for the next raw IPv4 datagram
        # tagged with our protocol number, then unwraps it.
        raw_packet, _ = self.receive_socket.recvfrom(65535)

        return self._parse_raw_packet(raw_packet)

    def _build_raw_packet(self, source_ip: str, destination_ip: str, packet: TTPPacket) -> bytes:
        """
        Constrói um datagrama IPv4 contendo um segmento TTP.
        (Builds a complete IPv4 datagram carrying a TTP segment as its
        payload, with a correctly computed TTP checksum.)
        """

        # Work on a copy so we never mutate the caller's original packet
        # (which might still be referenced elsewhere, e.g. in the
        # retransmission window).
        packet = packet.copy()
        packet.checksum = 0

        ttp_data = packet.pack()

        # Compute the checksum over the pseudo-header + zero-checksum
        # segment, exactly as the receiver will when validating it.
        packet.checksum = calculate_ttp_checksum(
            source_ip,
            destination_ip,
            ttp_data,
        )

        ipv4 = IPv4Packet(
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=TTP_PROTOCOL,
            payload=packet.pack(),  # re-pack, now with the real checksum set
        )

        return ipv4.pack()

    def _parse_raw_packet(self, raw_packet: bytes) -> tuple[TTPPacket, IPv4Packet]:
        """
        Desencapsula um datagrama IPv4 e retorna
        o segmento TTP correspondente.
        (Unwraps a raw IPv4 datagram and returns the TTP segment inside it,
        after validating that the protocol number is TTP and that the
        checksum matches.)
        """

        ipv4 = IPv4Packet.unpack(raw_packet)

        if not ipv4.is_ttp():
            raise ValueError("Protocolo IPv4 inválido.")

        packet = TTPPacket.unpack(ipv4.payload)

        if not validate_ttp_checksum(
            ipv4.source_ip,
            ipv4.destination_ip,
            packet,
        ):
            raise ValueError("Checksum TTP inválido.")

        return packet, ipv4

    def close(self) -> None:
        """
        Fecha os sockets RAW.
        """

        self.send_socket.close()

        self.receive_socket.close()

    def __enter__(self):
        # Enables `with TTPSocket() as sock:` usage.
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    @property
    def is_open(self):
        # fileno() returns -1 once a socket object has been closed.
        return (self.send_socket.fileno() != -1) and (self.receive_socket.fileno() != -1)
