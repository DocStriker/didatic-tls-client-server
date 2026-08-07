import threading
import time

from ttp.sequence import SequenceSpace, ReceiveStatus
from ttp.packet import TTPPacket, TTPFlags,TTPState
from ttp.socket import TTPSocket
from ttp.retransmission import RetransmissionManager
from ttp.window import SendWindow
from ttp.receive import ReceiveBuffer
from ttp.log_config import LoggerManager
from ttp.constants import DEFAULT_WINDOW_SIZE, MAX_PACKET_SIZE

class TTPConnection:
    def __init__(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str | None = None,
        remote_port: int | None = None,
        window_size: int = DEFAULT_WINDOW_SIZE,
        side_name: str = "unknown",
    ):
        
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.window_size = window_size
        self.logger_manager = LoggerManager(side_name)

        self.state = TTPState.CLOSED
        self.sequence = SequenceSpace()
        self.socket = TTPSocket()
        self.retransmission = RetransmissionManager(timeout=1.0, max_retries=5)
        self.fin_retransmission = RetransmissionManager(timeout=1.0, max_retries=5)
        self.window = SendWindow(window_size)
        self.receive_buffer = ReceiveBuffer()

        self.window_lock = threading.Lock()
        self.out_of_order = {}
        self.close_event = threading.Event()
        self.fin_ack_received = threading.Event()
        self.fin_received = threading.Event()


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

        #print(packet.payload_length)

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

        self.logger_manager.log(f"[TTP] ACK {packet.acknowledgment_number} processado.")

        self.logger_manager.log(self.window)

    def _flush_out_of_order(self):

        while True:
            packet = self.out_of_order.get(self.sequence.recv_next)

            if packet is None:
                break

            del self.out_of_order[packet.sequence_number]

            self.logger_manager.log(f"[TTP] Liberando pacote armazenado SEQ={packet.sequence_number}")

            status = self.sequence.receive(packet.sequence_number, packet.sequence_space)

            if status is not ReceiveStatus.EXPECTED:
                break

            self.receive_buffer.push(packet.payload)

    def _process_data(self, packet: TTPPacket) -> bytes | None:
        status = self.sequence.receive(packet.sequence_number, packet.sequence_space)

        if status is ReceiveStatus.EXPECTED:
            self.logger_manager.log("[TTP] DATA recebida.")

            self.receive_buffer.push(packet.payload)

            self._flush_out_of_order()

            ack_packet = self._build_packet(TTPFlags.ACK)

            self._transmit_packet(ack_packet)

            self.logger_manager.log(f"[SERVER] Enviando ACK={ack_packet.acknowledgment_number}")

            return None

        if status is ReceiveStatus.DUPLICATE:
            self.logger_manager.log("[TTP] DATA duplicada.")

            ack_packet = self._build_packet(TTPFlags.ACK)
            
            self._transmit_packet(ack_packet)

            return None

        if status is ReceiveStatus.FUTURE:
            self.logger_manager.log(f"[TTP] Armazenando pacote futuro SEQ={packet.sequence_number}")

            self.out_of_order[packet.sequence_number] = packet

            ack_packet = self._build_packet(TTPFlags.ACK)

            self._transmit_packet(ack_packet)

            return None

        return None

    def _send_fin(self):
        self.fin_packet = self._build_packet(TTPFlags.FIN)

        self._transmit_packet(self.fin_packet)

        self.fin_retransmission.start()

    def _process_fin(self, packet: TTPPacket):
        self.logger_manager.log("[TTP] FIN recebido.")

        status = self.sequence.receive(
            packet.sequence_number,
            packet.sequence_space
        )

        # sempre responde com ACK para evitar condição de espera mútua
        fin_ack = self._build_packet(TTPFlags.FIN | TTPFlags.ACK)

        self._transmit_packet(fin_ack)

        self.logger_manager.log("[TTP] FIN-ACK enviado.")

        # sinaliza para quem chamou close()
        self.fin_received.set()

        # se ainda não enviamos FIN, envia agora (resposta ao FIN)
        if self.state == TTPState.ESTABLISHED:
            fin = self._build_packet(TTPFlags.FIN)

            self._transmit_packet(fin)

            self.logger_manager.log("[TTP] FIN enviado.")

            self.state = TTPState.FIN_WAIT

    def _wait_fin_ack(self):
        while True:
            if self.fin_ack_received.wait(self.fin_retransmission.timeout):
                self.fin_retransmission.stop()

                return True

            if self.fin_retransmission.exhausted:
                return False

            self.logger_manager.log("[TTP] Retransmitindo FIN...")

            self._transmit_packet(self.fin_packet)

            self.fin_retransmission.restart()

    def _receive_loop(self):
        self.logger_manager.log("[DEBUG] Receive Loop iniciado")

        while self.connected:
            try:
                packet, _ = self._wait_for_packet()

                if packet.is_ack:
                    # FIN_ACK recebido, sinaliza para o close() que o outro lado reconheceu nosso FIN

                    if self.state == TTPState.FIN_WAIT:
                        self.logger_manager.log("[TTP] FIN-ACK recebido.")

                        self.fin_retransmission.stop()

                        self.fin_ack_received.set()

                        continue

                    self._process_ack(packet)

                    continue

                if packet.flags & TTPFlags.FIN:
                    self._process_fin(packet)

                    continue

                if packet.is_data:
                    self.logger_manager.log("[DEBUG] Entrou no DATA")
                    self._process_data(packet)          

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

            self.logger_manager.log(self.window)

            self.logger_manager.log(f"[TTP] Enviado SEQ={packet.sequence_number}")

            if len(self.window.pending) == 1:
                self.retransmission.start()

    def _start_receiver(self):
        self.receiver = threading.Thread(target=self._receive_loop, daemon=True)

        self.receiver.start()

    def _client_handshake(self):
        syn_packet = self._build_packet(TTPFlags.SYN)

        self._transmit_packet(syn_packet)

        self.state = TTPState.SYN_SENT

        syn_ack, _ = self._wait_for_packet(TTPFlags.SYN | TTPFlags.ACK)

        if syn_ack.acknowledgment_number != self.sequence.send_next:
            raise RuntimeError("ACK inválido.")

        self.sequence.recv_next = syn_ack.sequence_number + syn_ack.sequence_space

        ack_packet = self._build_packet(TTPFlags.ACK)

        self._transmit_packet(ack_packet)

        self.state = TTPState.ESTABLISHED

    def _server_handshake(self):
        syn, ipv4 = self._wait_for_packet(TTPFlags.SYN)

        self.remote_ip = ipv4.source_ip
        self.remote_port = syn.source_port

        self.sequence.recv_next = syn.sequence_number + syn.sequence_space

        syn_ack_packet = self._build_packet(TTPFlags.SYN | TTPFlags.ACK)

        self._transmit_packet(syn_ack_packet)

        self.state = TTPState.SYN_RECEIVED

        ack, _ = self._wait_for_packet(TTPFlags.ACK)

        if ack.acknowledgment_number != self.sequence.send_next:
            raise RuntimeError("ACK inválido.")

        self.state = TTPState.ESTABLISHED

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
        
    def connect(self):
        if self.state != TTPState.CLOSED:
            raise RuntimeError("Conexão já iniciada.")

        self.logger_manager.log("[TTP] Estado:", self.state.name)

        self._client_handshake()

        self._start_receiver()

        return self

    def accept(self):
        """
        Aguarda uma conexão de entrada.
        """

        if self.state != TTPState.CLOSED:
            raise RuntimeError("Socket já está em uso.")

        self.logger_manager.log("[TTP] Aguardando SYN...")

        self.logger_manager.log("[TTP] Estado:", self.state.name)

        self._server_handshake()

        self.logger_manager.log("[TTP] Estado:", self.state.name)

        self._start_receiver()

        return self
    
    def send(self, data: bytes):
        if self.state != TTPState.ESTABLISHED:
            raise RuntimeError("Conexão não estabelecida.")

        offset = 0

        while offset < len(data):
            chunk = data[offset:offset + MAX_PACKET_SIZE]

            packet = self._build_packet(TTPFlags.DATA, chunk)

            with self.window_lock:  
                self.window.enqueue(packet)

            offset += len(chunk)

        with self.window_lock:
            self._flush_window()

    def recv(self) -> bytes:
        if self.state != TTPState.ESTABLISHED:
            raise RuntimeError("Conexão não estabelecida.")

        return self.receive_buffer.pop()

    def close(self):
        if self.state == TTPState.CLOSED:
            return

        if self.state != TTPState.ESTABLISHED:
            self.socket.close()

            self.state = TTPState.CLOSED

            return

        self.logger_manager.log("[TTP] Iniciando encerramento...")

        self.state = TTPState.FIN_WAIT

        fin = self._build_packet(TTPFlags.FIN)

        self._send_fin()

        if not self._wait_fin_ack():
            self.logger_manager.log("[TTP] Timeout aguardando ACK do FIN.")

            self.socket.close()

            self.state = TTPState.CLOSED

            return

        # espera FIN do outro lado
        if not self.fin_received.wait(timeout=5):
            self.logger_manager.log("[TTP] Timeout aguardando FIN remoto.")

        self.receive_buffer.clear()

        self.socket.close()

        self.state = TTPState.CLOSED

        self.close_event.set()

        self.logger_manager.log("[TTP] Conexão encerrada.")

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

        return False

    @property
    def connected(self):
        # considerar também FIN_WAIT como ligado para continuar
        # processando pacotes (ACK/FIN) durante o encerramento
        return self.state in (TTPState.ESTABLISHED, TTPState.FIN_WAIT)