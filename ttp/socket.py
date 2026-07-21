import socket

from ttp.packet import TTPPacket
from ttp.ipv4 import IPv4Packet
from ttp.checksums import calculate_ttp_checksum, validate_ttp_checksum
from ttp.constants import TTP_PROTOCOL

class TTPSocket:

    def __init__(
        self,
        timeout: float | None = None,
    ):
        if timeout is not None:
            self.receive_socket.settimeout(timeout)
        self.send_socket = self._create_send_socket()
        self.receive_socket = self._create_receive_socket()

    def _create_send_socket(self) -> socket.socket:
        """
        Socket utilizado somente para envio.
        Espera um pacote IPv4 completo.
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
        """

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            TTP_PROTOCOL,
        )

        return sock

    def send_packet(
        self,
        source_ip: str,
        destination_ip: str,
        packet: TTPPacket,
    ) -> None:

        raw_packet = self._build_raw_packet(
            source_ip,
            destination_ip,
            packet,
        )

        self.send_socket.sendto(
            raw_packet,
            (destination_ip, 0),
        )

    def receive_packet(self) -> tuple[TTPPacket, IPv4Packet]:

        raw_packet, _ = self.receive_socket.recvfrom(65535)

        return self._parse_raw_packet(raw_packet)
    
    def _build_raw_packet(
        self,
        source_ip: str,
        destination_ip: str,
        packet: TTPPacket,
    ) -> bytes:
        """
        Constrói um datagrama IPv4 contendo um segmento TTP.
        """

        packet = packet.copy()
        packet.checksum = 0

        ttp_data = packet.pack()

        packet.checksum = calculate_ttp_checksum(
            source_ip,
            destination_ip,
            ttp_data,
        )

        ipv4 = IPv4Packet(
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=TTP_PROTOCOL,
            payload=packet.pack(),
        )

        return ipv4.pack()
    
    def _parse_raw_packet(
        self,
        raw_packet: bytes,
    ) -> tuple[TTPPacket, IPv4Packet]:
        """
        Desencapsula um datagrama IPv4 e retorna
        o segmento TTP correspondente.
        """

        ipv4 = IPv4Packet.unpack(raw_packet)

        if not ipv4.is_ttp():
            raise ValueError("Protocolo IPv4 inválido.")

        packet = TTPPacket.unpack(
            ipv4.payload
        )

        if not validate_ttp_checksum(
            ipv4.source_ip,
            ipv4.destination_ip,
            packet,
        ):
            raise ValueError(
                "Checksum TTP inválido."
            )

        return packet, ipv4
    
    def close(self) -> None:
        """
        Fecha os sockets RAW.
        """

        self.send_socket.close()

        self.receive_socket.close()

    def __enter__(self):
        return self
    
    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ):
        self.close()
        return False

    @property
    def is_open(self):
        return (
            self.send_socket.fileno() != -1
            and
            self.receive_socket.fileno() != -1
        )