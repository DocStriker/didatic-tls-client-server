# =============================================================================
# ttp/connection.py
# -----------------------------------------------------------------------------
# TTPConnection is the "public API" of the whole ttp/ package: it plays the
# same role that a connected socket object plays for TCP, orchestrating:
#   - the 3-way handshake (connect / accept)
#   - sending data reliably through a sliding window with retransmission
#   - receiving data, handling duplicates/out-of-order/in-order segments
#   - a background thread that continuously drains incoming packets
#   - a graceful FIN/FIN-ACK based connection teardown
#
# It composes together every other module in ttp/:
#   TTPSocket           -> raw IP send/receive
#   SequenceSpace        -> SND.NXT / SND.UNA / RCV.NXT bookkeeping
#   SendWindow           -> sliding window of outgoing packets
#   RetransmissionManager -> per-packet retry/timeout tracking
#   ReceiveBuffer        -> hand-off of in-order data to the application
#   LoggerManager        -> shared debug logging to logs/ttp_shared.log
# =============================================================================

import threading
import time
import socket

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
        # remote_ip/remote_port are optional: a "server" / listener side
        # typically doesn't know its peer yet -- it will learn it from the
        # incoming SYN packet during _server_handshake().

        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.window_size = window_size
        self.logger_manager = LoggerManager(side_name)

        self.state = TTPState.CLOSED
        self.sequence = SequenceSpace()
        # Use a small receive timeout so the receive loop can periodically
        # wake up and perform retransmission checks / respond to shutdown
        # requests instead of blocking forever in recvfrom().
        self.socket = TTPSocket(timeout=0.5)
        # Separate RetransmissionManager instances for regular DATA packets
        # and for the closing FIN packet, since they are tracked
        # independently (a data retransmission timeout should not affect
        # the FIN retransmission clock, and vice versa).
        self.retransmission = RetransmissionManager(timeout=1.0, max_retries=5)
        self.fin_retransmission = RetransmissionManager(timeout=1.0, max_retries=5)
        self.window = SendWindow(window_size)
        self.receive_buffer = ReceiveBuffer()

        self.window_lock = threading.Lock()  # guards window/_flush_window
        self.out_of_order = {}  # sequence_number -> TTPPacket, for FUTURE segments
        self.close_event = threading.Event()
        self.fin_ack_received = threading.Event()
        self.fin_received = threading.Event()


    def _transmit_packet(self, packet: TTPPacket) -> None:
        # Thin wrapper around TTPSocket.send_packet, always using this
        # connection's local/remote IP addresses.
        self.socket.send_packet(
            source_ip=self.local_ip,
            destination_ip=self.remote_ip,
            packet=packet,
        )

    def _build_packet(self, flags: TTPFlags, payload: bytes = b"") -> TTPPacket:
        # Central packet factory: fills in source/destination ports,
        # current SEQ/ACK numbers, and the given flags/payload. If the
        # resulting packet consumes sequence space (SYN, FIN, or DATA), the
        # connection's send_next counter is advanced immediately so the
        # *next* call to _build_packet() gets the correct following
        # sequence number.
        packet = TTPPacket(
            source_port=self.local_port,
            destination_port=self.remote_port,
            sequence_number=self.sequence.send_next,
            acknowledgment_number=self.sequence.recv_next,
            flags=flags,
            window_size=self.window_size,
            payload=payload
        )

        #print(packet)

        if packet.consumes_sequence:
            self.sequence.advance_send(packet.sequence_space)

        return packet

    def _wait_for_packet(self, expected_flags: TTPFlags | None = None,) -> TTPPacket:
        # Blocks on the raw socket until a packet arrives that:
        #   1) is addressed to our local_port,
        #   2) comes from our expected remote_port (once known), and
        #   3) contains *at least* the requested flags (if any).
        # Anything else is silently discarded and we keep waiting -- this
        # filters out unrelated traffic sharing the same raw socket.
        while True:
            try:
                packet, ipv4 = self.socket.receive_packet()
            except socket.timeout:
                # No packet arrived within the socket timeout; caller will
                # typically loop again (or the receive thread can use this
                # opportunity to check timers / shutdown flags).
                continue

            if packet.destination_port != self.local_port:
                continue

            if (self.remote_port is not None) and (packet.source_port != self.remote_port):
                continue

            # allow matching when the expected flags are present in the packet
            if (expected_flags is not None) and ((packet.flags & expected_flags) != expected_flags):
                continue

            # Learn/confirm the peer's address from whatever packet we
            # just accepted (important the first time, during the server
            # handshake, when remote_ip/remote_port were still unknown).
            self.remote_ip = ipv4.source_ip

            self.remote_port = packet.source_port

            return packet, ipv4

    def _process_ack(self, packet):
        # atualiza o espaço de sequência com o ACK recebido
        # (Update sequence bookkeeping with the newly received ACK.)
        self.sequence.acknowledge(packet.acknowledgment_number)

        # Remove any now-fully-acknowledged packets from the send window.
        self.window.acknowledge(packet.acknowledgment_number)

        # Try to push more queued packets out now that window space freed up.
        self._flush_window()

        # This ACK confirms progress, so the current retransmission timer
        # (which was tracking the oldest unacked packet) can be cleared;
        # _flush_window() will restart it if there is still pending data.
        self.retransmission.stop()

        self.logger_manager.log(f"[TTP] ACK {packet.acknowledgment_number} processado.")

        self.logger_manager.log(self.window)

    def _flush_out_of_order(self):
        # After accepting an in-order segment, check whether any
        # previously-buffered "future" segments (stored in out_of_order)
        # can now be delivered in sequence, and keep draining them while
        # they chain together contiguously.
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
        # Core receive-side logic: classify the incoming DATA segment and
        # react accordingly (this mirrors TCP's handling of in-order,
        # duplicate, and out-of-order segments).
        status = self.sequence.receive(packet.sequence_number, packet.sequence_space)

        if status is ReceiveStatus.EXPECTED:
            # Exactly the next byte range we needed: deliver it to the
            # application-facing buffer immediately.
            self.logger_manager.log("[TTP] DATA recebida.")

            self.receive_buffer.push(packet.payload)

            # Now that recv_next advanced, maybe some buffered
            # out-of-order packets can be delivered too.
            self._flush_out_of_order()

            # ACK reflects the *new* recv_next (cumulative ACK).
            ack_packet = self._build_packet(TTPFlags.ACK)

            self._transmit_packet(ack_packet)

            self.logger_manager.log(f"[SERVER] Enviando ACK={ack_packet.acknowledgment_number}")

            return None

        if status is ReceiveStatus.DUPLICATE:
            # We already have this data (most likely our previous ACK was
            # lost and the sender retransmitted). Re-send an ACK so the
            # sender can stop retransmitting, but do not push the payload
            # again (avoids duplicating data in the receive buffer).
            self.logger_manager.log("[TTP] DATA duplicada.")

            ack_packet = self._build_packet(TTPFlags.ACK)
            
            self._transmit_packet(ack_packet)

            return None

        if status is ReceiveStatus.FUTURE:
            # There's a gap before this segment: buffer it for later and
            # still ACK (at the *current* recv_next, which is a duplicate
            # ACK from the sender's point of view -- signalling "I'm still
            # missing something before this").
            self.logger_manager.log(f"[TTP] Armazenando pacote futuro SEQ={packet.sequence_number}")

            self.out_of_order[packet.sequence_number] = packet

            ack_packet = self._build_packet(TTPFlags.ACK)

            self._transmit_packet(ack_packet)

            return None

        return None

    def _send_fin(self):
        # Sends this side's FIN and starts the FIN-specific retransmission
        # timer (used by _wait_fin_ack() below).
        self.fin_packet = self._build_packet(TTPFlags.FIN)

        self._transmit_packet(self.fin_packet)

        self.fin_retransmission.start()

    def _process_fin(self, packet: TTPPacket):
        # Called by the receive loop whenever a FIN arrives from the peer.
        self.logger_manager.log("[TTP] FIN recebido.")

        status = self.sequence.receive(
            packet.sequence_number,
            packet.sequence_space
        )

        # sempre responde com ACK para evitar condição de espera mútua
        # (Always answer with FIN+ACK to avoid a mutual-wait deadlock where
        # both sides are stuck waiting for the other to acknowledge first.)
        fin_ack = self._build_packet(TTPFlags.FIN | TTPFlags.ACK)

        self._transmit_packet(fin_ack)

        self.logger_manager.log("[TTP] FIN-ACK enviado.")

        # sinaliza para quem chamou close()
        # (Wake up any thread blocked in close() waiting for the peer's FIN.)
        self.fin_received.set()

        # se ainda não enviamos FIN, envia agora (resposta ao FIN)
        # (If we hadn't already started our own shutdown, this is the
        # passive-close side of the handshake: reply with our own FIN too.)
        if self.state == TTPState.ESTABLISHED:
            fin = self._build_packet(TTPFlags.FIN)

            self._transmit_packet(fin)

            self.logger_manager.log("[TTP] FIN enviado.")

            self.state = TTPState.FIN_WAIT

    def _wait_fin_ack(self):
        # Blocks (with retransmission) until fin_ack_received is set by the
        # receive loop, or until the FIN retransmission attempts run out.
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
        # Runs on a dedicated background daemon thread (started by
        # _start_receiver()) for the entire lifetime of an established
        # connection. Continuously pulls packets off the raw socket and
        # routes them to the right handler based on their flags.
        self.logger_manager.log("[DEBUG] Receive Loop iniciado")

        while self.connected:
            try:
                packet, _ = self._wait_for_packet()

                # Periodic retransmission check: if the retransmission timer
                # expired for the oldest in-flight DATA packet, resend it.
                if self.retransmission.running and self.retransmission.expired:
                    oldest = self.window.oldest()

                    if oldest is not None:
                        # If we've already exhausted retries, just log and
                        # let wait_for_acks() / callers decide to abort.
                        if self.retransmission.exhausted:
                            self.logger_manager.log("[TTP] Retransmissão exaurida para DATA.")
                        else:
                            self._transmit_packet(oldest)
                            self.logger_manager.log(f"[TTP] Retransmitindo SEQ={oldest.sequence_number}")
                            self.retransmission.restart()

                if packet.is_ack:
                    # FIN_ACK recebido, sinaliza para o close() que o outro lado reconheceu nosso FIN
                    # (Received an ACK. If we're in FIN_WAIT, this specific
                    # ACK is acknowledging our FIN -- signal close() so it
                    # can stop retransmitting the FIN.)

                    if self.state == TTPState.FIN_WAIT:
                        self.logger_manager.log("[TTP] FIN-ACK recebido.")

                        self.fin_retransmission.stop()

                        self.fin_ack_received.set()

                        continue

                    # Otherwise it's a normal data-ACK.
                    self._process_ack(packet)

                    continue

                if packet.flags & TTPFlags.FIN:
                    self._process_fin(packet)

                    continue

                if packet.is_data:
                    self.logger_manager.log("[DEBUG] Entrou no DATA")
                    self._process_data(packet)          

            except Exception:
                # Any unexpected error (e.g. the socket was closed while
                # recvfrom() was blocked) tears down the loop instead of
                # spinning forever. Avoid raising here to keep shutdown
                # behaviour predictable.
                import traceback
                traceback.print_exc()
                break

    def _flush_window(self):
        # Pulls packets out of the queue and actually transmits them, one
        # at a time, as long as there is enough free window space for
        # each one. This is the sliding-window "admission control" step.
        while True:
            packet = self.window.next_packet()

            if packet is None:
                break

            if not self.window.can_send(packet.sequence_space):
                # Window is full: stop here and wait for ACKs to free space.
                break

            packet = self.window.mark_sent()

            self._transmit_packet(packet)

            self.logger_manager.log(self.window)

            self.logger_manager.log(f"[TTP] Enviado SEQ={packet.sequence_number}")

            if len(self.window.pending) == 1:
                # Only (re)start the retransmission timer when this is the
                # *first* packet becoming pending -- i.e. we weren't
                # already waiting on an earlier unacked packet. This keeps
                # a single timer tracking the oldest in-flight packet,
                # similar in spirit to TCP's single retransmission timer.
                self.retransmission.start()

    def _start_receiver(self):
        # Launches _receive_loop on a daemon thread so it doesn't block
        # process exit, and doesn't need to be explicitly joined by callers.
        self.receiver = threading.Thread(target=self._receive_loop, daemon=True)

        self.receiver.start()

    def _client_handshake(self):
        # Active open: mirrors TCP's classic 3-way handshake.
        # 1) send SYN
        syn_packet = self._build_packet(TTPFlags.SYN)

        self._transmit_packet(syn_packet)

        self.state = TTPState.SYN_SENT

        # 2) wait for SYN+ACK
        syn_ack, _ = self._wait_for_packet(TTPFlags.SYN | TTPFlags.ACK)

        if syn_ack.acknowledgment_number != self.sequence.send_next:
            raise RuntimeError("ACK inválido.")

        # Learn the server's initial sequence number so we know what to
        # expect next from it.
        self.sequence.recv_next = syn_ack.sequence_number + syn_ack.sequence_space

        # 3) send final ACK, completing the handshake
        ack_packet = self._build_packet(TTPFlags.ACK)

        self._transmit_packet(ack_packet)

        self.state = TTPState.ESTABLISHED

    def _server_handshake(self):
        # Passive open: waits for a client's SYN, replies with SYN+ACK, and
        # waits for the final ACK.
        syn, ipv4 = self._wait_for_packet(TTPFlags.SYN)

        # This is where the server first learns who its peer is.
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
            """
            Blocks until every packet currently in the send window has been
            acknowledged, or until either the retransmission attempts are
            exhausted or the caller-supplied timeout elapses. Useful right
            before closing a connection, to avoid discarding unacknowledged
            data."""
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
        # Public entry point for the client side: performs the handshake
        # and starts the background receive thread. Analogous to a TCP
        # socket's connect().
        if self.state != TTPState.CLOSED:
            raise RuntimeError("Conexão já iniciada.")

        self.logger_manager.log("[TTP] Estado:", self.state.name)

        self._client_handshake()

        self._start_receiver()

        return self

    def accept(self):
        """
        Public entry point for the server side: blocks until a client
        connects, completing the passive-open handshake, then starts the
        background receive thread. Analogous to socket.accept(), except
        here the *same* TTPConnection object ends up representing the
        established connection -- there's no separate listening socket.
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
        # Splits arbitrary-length `data` into MAX_PACKET_SIZE-sized DATA
        # segments, enqueues them all in the send window, and then tries
        # to transmit as many as the window currently allows.
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
        # Pops the next fully in-order chunk of application data that the
        # background receive thread has already accepted. Blocks until one
        # is available.
        if self.state != TTPState.ESTABLISHED:
            raise RuntimeError("Conexão não estabelecida.")

        return self.receive_buffer.pop()

    def close(self):
        # Graceful shutdown. If the connection was never fully established,
        # simply release the raw sockets. Otherwise, run the FIN / FIN-ACK
        # exchange with the peer, waiting (with retransmission) for
        # confirmation on both sides before releasing resources.
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
            # Gave up waiting for our FIN to be acknowledged -- close
            # anyway rather than hanging forever.
            self.logger_manager.log("[TTP] Timeout aguardando ACK do FIN.")

            self.socket.close()

            self.state = TTPState.CLOSED

            return

        # Also wait a bit for the peer's own FIN, so we can be a "good
        # citizen" and acknowledge it before tearing down -- but don't
        # block forever if it never comes.
        if not self.fin_received.wait(timeout=5):
            self.logger_manager.log("[TTP] Timeout aguardando FIN remoto.")

        self.receive_buffer.clear()

        self.socket.close()

        self.state = TTPState.CLOSED

        self.close_event.set()

        self.logger_manager.log("[TTP] Conexão encerrada.")

    def __enter__(self):
        # Enables `with TTPConnection(...) as conn:` usage.
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

        return False

    @property
    def connected(self):
        # Treat FIN_WAIT as "still connected" too, so the receive loop
        # keeps running long enough to process the ACK/FIN exchange during
        # shutdown instead of stopping the instant we send our own FIN.
        return self.state in (TTPState.ESTABLISHED, TTPState.FIN_WAIT)
