from ttp.sequence import SequenceSpace
from ttp.packet import TTPPacket, TTPFlags,TTPState
from ttp.socket import TTPSocket

class TTPConnection:
    def __init__(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str | None = None,
        remote_port: int | None = None,
        window_size: int = 65535,
    ):
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.window_size = window_size
        self.state = TTPState.CLOSED
        self.sequence = SequenceSpace()
        self.socket = TTPSocket()

    def _send_syn(self):
        packet = TTPPacket(
            source_port=self.local_port,
            destination_port=self.remote_port,
            sequence_number=self.sequence.send_next,
            acknowledgment_number=self.sequence.recv_next,
            flags=TTPFlags.SYN,
            window_size=self.window_size,
        )

        self.socket.send_packet(
            source_ip=self.local_ip,
            destination_ip=self.remote_ip,
            packet=packet,
        )

        self.sequence.advance_send(packet.sequence_space)

        print("[TTP] SYN enviado.")

    def _send_syn_ack(self):
        packet = TTPPacket(
            source_port=self.local_port,
            destination_port=self.remote_port,
            sequence_number=self.sequence.send_next,
            acknowledgment_number=self.sequence.recv_next,
            flags=TTPFlags.SYN | TTPFlags.ACK,
            window_size=self.window_size,
        )

        print(packet.__repr__)

        self.socket.send_packet(
            source_ip=self.local_ip,
            destination_ip=self.remote_ip,
            packet=packet,
        )

        self.sequence.advance_send(packet.sequence_space)

        print("[TTP] SYN-ACK enviado.")

    def _send_ack(self):
        packet = TTPPacket(
            source_port=self.local_port,
            destination_port=self.remote_port,
            sequence_number=self.sequence.send_next,
            acknowledgment_number=self.sequence.recv_next,
            flags=TTPFlags.ACK,
            window_size=self.window_size,
        )

        self.socket.send_packet(
            source_ip=self.local_ip,
            destination_ip=self.remote_ip,
            packet=packet,
        )

        print("[TTP] ACK enviado.")

    def _wait_for_packet(self, expected_flags: TTPFlags | None = None,) -> TTPPacket:
        while True:
            packet, ipv4 = self.socket.receive_packet()

            if packet.destination_port != self.local_port:
                continue

            if (self.remote_port is not None) and (packet.source_port != self.remote_port):
                continue

            if (expected_flags is not None) and (packet.flags != expected_flags):
                continue

            self.remote_ip = ipv4.source_ip

            self.remote_port = packet.source_port

            return packet, ipv4
        
    def connect(self):
        if self.state != TTPState.CLOSED:
            raise RuntimeError("Conexão já iniciada.")

        print("[TTP] Estado:", self.state.name)

        self._send_syn()

        self.state = TTPState.SYN_SENT

        print("[TTP] Estado:", self.state.name)

        syn_ack, _ = self._wait_for_packet(TTPFlags.SYN | TTPFlags.ACK)

        print("[TTP] SYN-ACK recebido.")

        if syn_ack.acknowledgment_number != self.sequence.send_next:
            raise RuntimeError("ACK inválido.")

        self.sequence.recv_next = syn_ack.sequence_number + syn_ack.sequence_space

        self._send_ack()

        print("[TTP] ACK final enviado.")

        self.state = TTPState.ESTABLISHED

        print("[TTP] Estado:", self.state.name)

        return self

    def accept(self):
        """
        Aguarda uma conexão de entrada.
        """

        if self.state != TTPState.CLOSED:
            raise RuntimeError("Socket já está em uso.")

        print("[TTP] Aguardando SYN...")

        print("[TTP] Estado:", self.state.name)

        syn, ipv4 = self._wait_for_packet(TTPFlags.SYN)

        print("[TTP] SYN recebido.")

        self.remote_ip = ipv4.source_ip
        self.remote_port = syn.source_port

        self.sequence.recv_next = syn.sequence_number + syn.sequence_space

        self._send_syn_ack()

        self.state = TTPState.SYN_RECEIVED

        print("[TTP] Estado:", self.state.name)

        ack, _ = self._wait_for_packet(TTPFlags.ACK)

        if ack.acknowledgment_number != self.sequence.send_next:
            raise RuntimeError("ACK inválido.")

        self.state = TTPState.ESTABLISHED

        print("[TTP] ACK final recebido.")

        print("[TTP] Estado:", self.state.name)

        return self
    
    def send(self, data: bytes):
        if self.state != TTPState.ESTABLISHED:
            raise RuntimeError("Conexão não estabelecida.")

        packet = TTPPacket(
            source_port=self.local_port,
            destination_port=self.remote_port,
            sequence_number=self.sequence.send_next,
            acknowledgment_number=self.sequence.recv_next,
            flags=TTPFlags.DATA,
            window_size=self.window_size,
            payload=data,
        )

        self.socket.send_packet(
            source_ip=self.local_ip,
            destination_ip=self.remote_ip,
            packet=packet,
        )

        self.sequence.advance_send(packet.sequence_space)

        print("[TTP] DATA enviada.")

    def recv(self) -> bytes:
        if self.state != TTPState.ESTABLISHED:
            raise RuntimeError("Conexão não estabelecida.")

        while True:
            packet, _ = self._wait_for_packet()

            if not packet.is_data:
                continue

            if not self.sequence.expect(packet.sequence_number, packet.sequence_space):
                raise RuntimeError("Número de sequência inesperado.")

            print("[TTP] DATA recebida.")

            return packet.payload
        
    def close(self):

        self.socket.close()

        self.state = TTPState.CLOSED

        print("[TTP] Conexão encerrada.")

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):

        self.close()

        return False

    @property
    def connected(self):
        return self.state == TTPState.ESTABLISHED