from ttp.sequence import SequenceSpace, ReceiveStatus
from ttp.packet import TTPPacket, TTPFlags,TTPState
from ttp.socket import TTPSocket
from ttp.retransmission import RetransmissionManager
from ttp.window import SendWindow
import time
import threading
from collections import deque

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
        self.retransmission = RetransmissionManager(timeout=1.0, max_retries=5)
        self.window = SendWindow(window_size)
        self.receive_buffer = deque()
        self.window_lock = threading.Lock()

    def _transmit_packet(self, packet: TTPPacket) -> None:
        self.socket.send_packet(
            source_ip=self.local_ip,
            destination_ip=self.remote_ip,
            packet=packet,
        )

    def _build_packet(self, flags: TTPFlags, payload: bytes = b"") -> TTPPacket:
        packet = TTPPacket(
            source_port=self.local_port,
            destination_port=self.remote_port,
            sequence_number=self.sequence.send_next,
            acknowledgment_number=self.sequence.recv_next,
            flags=flags,
            window_size=self.window_size,
            payload=payload
        )

        #print(packet.__repr__)

        if packet.consumes_sequence:
            self.sequence.advance_send(packet.sequence_space)

        return packet

    def _wait_for_packet(self, expected_flags: TTPFlags | None = None,) -> TTPPacket:
        while True:
            packet, ipv4 = self.socket.receive_packet()

            if packet.destination_port != self.local_port:
                continue

            if (self.remote_port is not None) and (packet.source_port != self.remote_port):
                continue

            # allow matching when the expected flags are present in the packet
            if (expected_flags is not None) and ((packet.flags & expected_flags) != expected_flags):
                continue

            self.remote_ip = ipv4.source_ip

            self.remote_port = packet.source_port

            return packet, ipv4

    def _process_ack(self, packet):
        # atualiza o espaço de sequência com o ACK recebido
        self.sequence.acknowledge(packet.acknowledgment_number)

        self.window.acknowledge(packet.acknowledgment_number)

        self._flush_window()

        self.retransmission.stop()

        print(f"[TTP] ACK {packet.acknowledgment_number} processado.")

        print(self.window)

    def _process_data(self, packet: TTPPacket) -> bytes | None:

        status = self.sequence.receive(packet.sequence_number, packet.sequence_space)

        if status is ReceiveStatus.EXPECTED:

            print("[TTP] DATA recebida.")
            
            ack_packet = self._build_packet(TTPFlags.ACK)

            self._transmit_packet(ack_packet)

            print(f"[SERVER] Enviando ACK={ack_packet.acknowledgment_number}")

            return packet.payload

        if status is ReceiveStatus.DUPLICATE:

            print("[TTP] DATA duplicada.")

            ack_packet = self._build_packet(TTPFlags.ACK)
            
            self._transmit_packet(ack_packet)

            return None

        if status is ReceiveStatus.FUTURE:

            print("[TTP] DATA fora de ordem.")

            return None

        return None

    def _receive_loop(self):
        print("[DEBUG] Receive Loop iniciado")

        while self.connected:
            try:
                packet, _ = self._wait_for_packet()

                if packet.is_ack:
                    print("[DEBUG] Entrou no ACK")
                    self._process_ack(packet)
                    print("[DEBUG] Saiu do ACK")
                    continue

                if packet.is_data:
                    print("[DEBUG] Entrou no DATA")
                    payload = self._process_data(packet)

                    if payload:
                        self.receive_buffer.append(payload)

            except Exception as e:
                import traceback
                traceback.print_exc()
                break

    def _flush_window(self):
        while True:
            packet = self.window.next_packet()

            if packet is None:
                break

            if not self.window.can_send(packet.sequence_space):
                break

            packet = self.window.mark_sent()

            self._transmit_packet(packet)

            print(self.window)

            print(f"[TTP] Enviado SEQ={packet.sequence_number}")

            if len(self.window.pending) == 1:
                self.retransmission.start()

    def _start_receiver(self):
        self.receiver = threading.Thread(target=self._receive_loop, daemon=True)

        self.receiver.start()
        
    def connect(self):
        if self.state != TTPState.CLOSED:
            raise RuntimeError("Conexão já iniciada.")

        print("[TTP] Estado:", self.state.name)

        syn_packet = self._build_packet(TTPFlags.SYN)

        self._transmit_packet(syn_packet)

        self.state = TTPState.SYN_SENT

        print("[TTP] Estado:", self.state.name)

        syn_ack, _ = self._wait_for_packet(TTPFlags.SYN | TTPFlags.ACK)

        print("[TTP] SYN-ACK recebido.")

        if syn_ack.acknowledgment_number != self.sequence.send_next:
            raise RuntimeError("ACK inválido.")

        self.sequence.recv_next = syn_ack.sequence_number + syn_ack.sequence_space

        ack_packet = self._build_packet(TTPFlags.ACK)

        self._transmit_packet(ack_packet)

        self.state = TTPState.ESTABLISHED

        print("[TTP] Estado:", self.state.name)

        self._start_receiver()

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

        syn_ack_packet = self._build_packet(TTPFlags.SYN | TTPFlags.ACK)

        self._transmit_packet(syn_ack_packet)

        self.state = TTPState.SYN_RECEIVED

        print("[TTP] Estado:", self.state.name)

        ack, _ = self._wait_for_packet(TTPFlags.ACK)

        if ack.acknowledgment_number != self.sequence.send_next:
            raise RuntimeError("ACK inválido.")

        self.state = TTPState.ESTABLISHED

        print("[TTP] Estado:", self.state.name)

        self._start_receiver()

        return self
    
    def send(self, data: bytes):

        if self.state != TTPState.ESTABLISHED:
            raise RuntimeError("Conexão não estabelecida.")

        offset = 0

        while offset < len(data):

            chunk = data[offset:offset + 1600]

            packet = self._build_packet(TTPFlags.DATA, chunk)

            with self.window_lock:  
                self.window.enqueue(packet)

            offset += len(chunk)

        with self.window_lock:
            self._flush_window()

    def recv(self) -> bytes:
        if self.state != TTPState.ESTABLISHED:
            raise RuntimeError("Conexão não estabelecida.")

        while not self.receive_buffer:
            time.sleep(0.01)

        return self.receive_buffer.popleft()

    def close(self):

        self.socket.close()

        self.state = TTPState.CLOSED

        print("[TTP] Conexão encerrada.")

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):

        self.close()

        return False

    def wait_for_acks(self, timeout: float = 5.0) -> bool:
        """Aguarda até que todos os pacotes pendentes sejam ACKed ou até estourar o timeout."""
        start = time.time()

        while not self.window.empty:
            # se os retries de retransmissão foram exauridos, aborta
            if self.retransmission.exhausted:
                return False

            # timeout externo configurado pelo chamador
            if (timeout is not None) and ((time.time() - start) >= timeout):
                return False

            time.sleep(0.01)

        return True

    @property
    def connected(self):
        return self.state == TTPState.ESTABLISHED