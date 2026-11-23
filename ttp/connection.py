# =============================================================================
# ttp/connection.py
# -----------------------------------------------------------------------------
# TTPConnection é a "API pública" do pacote ttp/: faz o papel de um socket
# TCP já conectado. Orquestra:
#   - handshake de 3 vias (connect / accept) COM retransmissão do SYN/SYN-ACK
#   - envio confiável com janela deslizante, RTO adaptativo, fast retransmit
#   - recepção com reordenação, descarte de duplicados e controle de fluxo
#   - fechamento gracioso (FIN/ACK nos dois sentidos, meio-fechamento, TIME_WAIT)
#   - detecção de par morto (keepalive) e reset (RST)
#
# ---------------------------------------------------------------------------
# COMO A SINCRONIA FUNCIONA (o que foi corrigido em relação à versão antiga)
# ---------------------------------------------------------------------------
# 1) UMA thread por conexão e UM lock. Antes, a thread receptora e send()
#    mexiam na mesma janela de envio sem o mesmo lock (corrida de dados).
#
# 2) Os timers são verificados a cada "tick", CHEGUE PACOTE OU NÃO. Antes, a
#    checagem de retransmissão ficava depois de _wait_for_packet(), que só
#    retornava quando chegava um pacote: se o único pacote em voo se perdia,
#    nada mais chegava e a retransmissão nunca disparava (deadlock).
#
# 3) Todo segmento depois do SYN carrega ACK ("piggyback") com o RCV.NXT atual
#    no instante do ENVIO (também nas retransmissões). Antes, segmentos DATA
#    não tinham a flag ACK e o servidor, ainda em SYN_RECEIVED, ignorava
#    dados se o ACK final do handshake se perdesse.
#
# 4) Controle de fluxo real: a janela anunciada = espaço livre no buffer de
#    recepção, e o remetente respeita a janela ANUNCIADA PELO PAR.
#
# 5) Pacote ruim nunca derruba a conexão (o PacketDispatcher descarta).
#
# 6) Aritmética de sequência módulo 2**32 (ver ttp/sequence.py).
# =============================================================================

from __future__ import annotations

import queue
import random
import threading
import time
import traceback

from ttp.config import TTPConfig
from ttp.constants import DEFAULT_WINDOW_SIZE, SEQ_HALF
from ttp.dispatcher import PacketDispatcher
from ttp.errors import TTPClosed, TTPRefused, TTPReset, TTPTimeout
from ttp.log_config import LoggerManager
from ttp.packet import TTPFlags, TTPPacket, TTPState, make_reset_for
from ttp.receive import ReceiveBuffer
from ttp.retransmission import RetransmissionManager
from ttp.sequence import (
    ReceiveStatus,
    SequenceSpace,
    seq_add,
    seq_diff,
    seq_leq,
    seq_lt,
)
from ttp.socket import TTPSocket
from ttp.timer import TTPTimer
from ttp.window import InFlight, SendWindow

# Estados em que a conexão já está "sincronizada" (handshake concluído).
_SYNCHRONIZED = (
    TTPState.ESTABLISHED,
    TTPState.FIN_WAIT_1,
    TTPState.FIN_WAIT_2,
    TTPState.CLOSE_WAIT,
    TTPState.CLOSING,
    TTPState.LAST_ACK,
)


class TTPConnection:
    def __init__(
        self,
        local_ip: str,
        local_port: int = 0,
        remote_ip: str | None = None,
        remote_port: int | None = None,
        window_size: int = DEFAULT_WINDOW_SIZE,
        side_name: str = "unknown",
        socket: TTPSocket | None = None,
        owns_socket: bool = True,
        config: TTPConfig | None = None,
        dispatcher: PacketDispatcher | None = None,
        on_established=None,
        on_closed=None,
    ):
        self.cfg = config or TTPConfig()

        self.local_ip = local_ip
        # Porta 0 = efêmera (antes o cliente fixava 50000 e dois clientes colidiam).
        self.local_port = local_port or random.randint(49152, 65535)
        self.remote_ip = remote_ip
        self.remote_port = remote_port

        # window_size = capacidade do buffer de recepção = janela que anunciamos.
        self.recv_capacity = max(1, min(window_size, 0xFFFF))
        self.window_size = self.recv_capacity
        self.mss = max(1, min(self.cfg.mss, self.recv_capacity))

        self.logger_manager = LoggerManager(side_name)

        self.state = TTPState.CLOSED
        self.sequence = SequenceSpace()
        self.socket = socket
        self.owns_socket = owns_socket

        self._dispatcher = dispatcher
        self._owns_dispatcher = False
        self._on_established = on_established
        self._on_closed = on_closed

        self.window = SendWindow(0)  # tamanho = janela do par (aprendida no handshake)
        self.receive_buffer = ReceiveBuffer(self.recv_capacity)

        self.rtx = RetransmissionManager(
            timeout=self.cfg.rto_initial,
            max_retries=self.cfg.max_retries,
            min_rto=self.cfg.rto_min,
            max_rto=self.cfg.rto_max,
        )
        # alias do nome antigo
        self.retransmission = self.rtx

        # --- sincronização: um lock, uma condição ---------------------------
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._inbox: queue.Queue = queue.Queue()
        self.receiver: threading.Thread | None = None

        # --- estado de envio ------------------------------------------------
        self._send_buf = bytearray()   # bytes aceitos de send() e ainda não segmentados
        self._fin_queued = False       # close()/shutdown_write() pediu FIN
        self._fin_sent = False
        self._fin_seq = 0
        self._peer_window = 0          # SND.WND: janela mais recente anunciada pelo par
        self._wl1 = 0                  # SND.WL1/WL2: qual segmento atualizou a janela
        self._wl2 = 0                  # (evita que ACK velho/reordenado a encolha)
        self._dup_acks = 0
        self._recover: int | None = None   # ponto de recuperação (NewReno)
        self._persist = TTPTimer(self.cfg.rto_initial)
        self._persist_rto = self.cfg.rto_initial
        self._persist_probes = 0

        # --- estado de recepção ---------------------------------------------
        self._irs = 0                  # ISN do par
        self._ooo: dict[int, tuple[bytes, bool]] = {}   # seq -> (payload, fin)  fora de ordem
        self._last_adv = 0             # última janela que anunciamos

        # --- ciclo de vida / keepalive --------------------------------------
        self._error: BaseException | None = None
        self._finalized = False
        self._time_wait_deadline = 0.0
        self._fin_wait2_deadline = 0.0
        self._last_rx = time.monotonic()
        self._last_probe = 0.0
        self._ka_probes = 0

        self.close_event = threading.Event()

        self.stats = dict(
            segments_sent=0, segments_received=0,
            bytes_sent=0, bytes_received=0,
            retransmissions=0, fast_retransmissions=0, timeouts=0,
            dup_acks=0, duplicates=0, out_of_order=0, out_of_window=0,
        )

    # =========================================================================
    # Utilidades de baixo nível
    # =========================================================================

    def _log(self, *args):
        self.logger_manager.log(*args)

    def _debug(self, *args):
        self.logger_manager.debug(*args)

    def _set_state(self, new_state: TTPState) -> None:
        if new_state != self.state:
            self._log(f"[TTP] Estado: {self.state.name} -> {new_state.name}")

        self.state = new_state
        self._cond.notify_all()

    def _ensure_socket(self) -> None:
        if self.socket is None:
            # timeout curto: o laço do dispatcher reage rápido ao encerramento
            self.socket = TTPSocket(timeout=0.1)

    def _ensure_dispatcher(self) -> None:
        self._ensure_socket()

        if self._dispatcher is None:
            self._dispatcher = PacketDispatcher(
                self.socket,
                self.local_port,
                on_unmatched=self._on_stray_packet,
                name=f"{self.logger_manager.side_name}-rx",
            )
            self._owns_dispatcher = True
            self._dispatcher.start()

    def _on_stray_packet(self, packet: TTPPacket, ipv4) -> None:
        # Pacote para nossa porta vindo de quem não é nosso par: responde RST
        # (a menos que ele mesmo seja um RST), como o TCP.
        if packet.is_rst:
            return

        self._send_raw(make_reset_for(packet), ipv4.source_ip)

    def _send_raw(self, packet: TTPPacket, destination_ip: str | None = None) -> None:
        try:
            self.socket.send_packet(self.local_ip, destination_ip or self.remote_ip, packet)
        except OSError as error:
            self._debug(f"falha ao enviar: {error}")

    def _start_thread(self) -> None:
        self.receiver = threading.Thread(
            target=self._run,
            daemon=True,
            name=f"ttp-{self.logger_manager.side_name}-{self.local_port}",
        )
        self.receiver.start()

    # nome antigo
    _start_receiver = _start_thread

    def _raise_error(self) -> None:
        error = self._error

        if error is None:
            raise TTPClosed("Conexão encerrada.")

        # Nova instância: relançar o MESMO objeto vários vezes acumularia traceback.
        raise type(error)(*error.args)

    # =========================================================================
    # Construção e transmissão de segmentos
    # =========================================================================

    def _adv_window(self) -> int:
        """
        Janela que ANUNCIAMOS = espaço livre no buffer de recepção.

        Evita a "síndrome da janela boba" (SWS, RFC 1122 §4.2.3.3): se o que
        sobrou é menor que min(MSS, capacidade/2), anuncia 0 em vez de uma
        janelinha de poucos bytes que faria o remetente mandar segmentos
        minúsculos.
        """
        free = self.receive_buffer.free

        if free < min(self.mss, self.recv_capacity // 2):
            return 0

        return min(free, 0xFFFF)

    def _make_packet(self, flags: TTPFlags, payload: bytes = b"", seq: int | None = None) -> TTPPacket:
        return TTPPacket(
            source_port=self.local_port,
            destination_port=self.remote_port,
            sequence_number=self.sequence.send_next if seq is None else seq,
            acknowledgment_number=self.sequence.recv_next,
            flags=flags,
            window_size=self._adv_window(),
            payload=payload,
        )

    def _transmit(self, packet: TTPPacket) -> None:
        """
        Coloca um segmento na rede. ACK e janela são preenchidos AGORA (e não
        quando o segmento foi criado): numa retransmissão, o ACK e a janela
        enviados são os atuais, não os de quando o dado foi gerado.
        """
        packet.acknowledgment_number = self.sequence.recv_next

        window = self._adv_window()
        packet.window = window
        self._last_adv = window

        if self.state != TTPState.SYN_SENT:
            packet.flags |= TTPFlags.ACK  # tudo depois do SYN inicial leva ACK

        self.stats["segments_sent"] += 1
        self._debug(f"TX {packet}")
        self._send_raw(packet)

    def _send_tracked(self, packet: TTPPacket) -> None:
        """Envia um segmento que consome sequência (SYN/FIN/dados) e o vigia."""
        self.window.track(packet, time.monotonic())

        if self.window.pending_count == 1:
            self.rtx.start()

        self._transmit(packet)

    def _send_ack(self) -> None:
        self._transmit(self._make_packet(TTPFlags.ACK))

    def _send_probe(self) -> None:
        """
        Sonda de keepalive / janela zero: ACK puro com SEQ = SND.NXT - 1
        (um número de sequência "velho"). Pela regra da RFC 793, um segmento
        inaceitável provoca um ACK em resposta -- é o que queremos: provar
        que o par está vivo e descobrir a janela atual dele.
        """
        probe = self._make_packet(TTPFlags.ACK, seq=seq_add(self.sequence.send_next, -1))
        self._transmit(probe)

    def _retransmit(self, item: InFlight, reason: str) -> None:
        # Karn: segmento retransmitido não gera amostra de RTT.
        item.retransmitted = True
        self.stats["retransmissions"] += 1
        self._log(f"[TTP] Retransmitindo SEQ={item.packet.sequence_number} ({reason})")
        self._transmit(item.packet)

    # =========================================================================
    # Envio de dados
    # =========================================================================

    def _flush(self) -> None:
        """
        Corta segmentos do buffer de envio e transmite enquanto a janela do
        par permitir. Chamado quando: a aplicação envia, chega ACK (libera
        janela) ou a janela do par muda.

            usable = janela_do_par - bytes_em_voo
            n      = min(MSS, bytes_no_buffer, usable)
        """
        if self.state in (TTPState.ESTABLISHED, TTPState.CLOSE_WAIT):
            seq = self.sequence

            while self._send_buf:
                in_flight = seq.bytes_in_flight
                usable = self._peer_window - in_flight

                if usable <= 0:
                    break

                wanted = min(self.mss, len(self._send_buf))
                size = min(wanted, usable)

                # Janela boba (lado do remetente): só manda um pedaço menor
                # que o desejado se não há nada em voo; senão espera o ACK.
                if size < wanted and in_flight > 0:
                    break

                chunk = bytes(self._send_buf[:size])
                del self._send_buf[:size]

                packet = self._make_packet(TTPFlags.DATA | TTPFlags.ACK, chunk)
                seq.advance_send(size)
                self._send_tracked(packet)

            if self._fin_queued and not self._fin_sent and not self._send_buf:
                self._send_fin()

        self._manage_persist()
        self._cond.notify_all()

    def _send_fin(self) -> None:
        fin = self._make_packet(TTPFlags.FIN | TTPFlags.ACK)

        self._fin_seq = fin.sequence_number
        self._fin_sent = True
        self.sequence.advance_send(1)

        # Se o par já fechou (CLOSE_WAIT) vamos para LAST_ACK; senão, FIN_WAIT_1.
        self._set_state(TTPState.LAST_ACK if self.state == TTPState.CLOSE_WAIT else TTPState.FIN_WAIT_1)

        self._send_tracked(fin)

    def _manage_persist(self) -> None:
        """
        Timer de persistência. Se o par anunciou janela ZERO e temos dados
        esperando, a única coisa que pode nos destravar é o par avisar que a
        janela reabriu -- e esse aviso é um ACK sem dados que pode se perder.
        Então, de tempos em tempos, SONDAMOS o par (ver _send_probe).
        """
        needs_probe = (
            bool(self._send_buf)
            and self._peer_window == 0
            and self.window.empty
            and self.state in (TTPState.ESTABLISHED, TTPState.CLOSE_WAIT)
        )

        if needs_probe:
            if not self._persist.running:
                self._persist.start(self._persist_rto)
        else:
            self._persist.stop()
            self._persist_probes = 0
            self._persist_rto = max(self.rtx.rto, self.cfg.rto_min)

    # =========================================================================
    # Laço principal (uma thread por conexão)
    # =========================================================================

    def _run(self) -> None:
        self._debug("laço da conexão iniciado")

        while True:
            try:
                item = self._inbox.get(timeout=self.cfg.tick)
            except queue.Empty:
                item = None

            with self._lock:
                if self._finalized:
                    break

                try:
                    batch = 0

                    while item is not None and not self._finalized:
                        self._handle_packet(item[0])

                        batch += 1

                        if batch >= 64:
                            break

                        try:
                            item = self._inbox.get_nowait()
                        except queue.Empty:
                            item = None

                    if not self._finalized:
                        # Os timers rodam SEMPRE, com ou sem tráfego.
                        self._on_tick()

                except Exception:
                    # Um bug/entrada inesperada não pode matar a thread (e com
                    # ela a conexão): registra e continua.
                    self._log("[TTP] erro inesperado no laço:\n" + traceback.format_exc())

                if self._finalized:
                    break

        self._debug("laço da conexão encerrado")

    def _on_tick(self) -> None:
        now = time.monotonic()
        state = self.state

        if state == TTPState.CLOSED:
            return

        if state == TTPState.TIME_WAIT:
            if now >= self._time_wait_deadline:
                self._finalize()
            return

        # 1) Retransmissão por timeout (RTO).
        if self.rtx.running and self.rtx.expired:
            self._on_rto()

            if self._finalized:
                return

        # 2) Sondas de janela zero.
        if self._persist.running and self._persist.expired:
            self._on_persist()

            if self._finalized:
                return

        # 3) Esperando o FIN do par por tempo demais.
        if state == TTPState.FIN_WAIT_2 and now >= self._fin_wait2_deadline:
            self._abort(TTPTimeout("O par não enviou FIN a tempo."), send_rst=True)
            return

        # 4) Keepalive (só em conexão ociosa e sem nada em voo).
        interval = self.cfg.keepalive_interval

        if (
            interval
            and state in (TTPState.ESTABLISHED, TTPState.CLOSE_WAIT)
            and self.window.empty
            and not self._send_buf
        ):
            idle_since = max(self._last_rx, self._last_probe)
            threshold = interval if self._ka_probes == 0 else self.cfg.keepalive_probe_interval

            if now - idle_since >= threshold:
                if self._ka_probes >= self.cfg.keepalive_probes:
                    self._abort(TTPTimeout("O par não respondeu ao keepalive."), send_rst=False)
                    return

                self._ka_probes += 1
                self._last_probe = now
                self._debug(f"keepalive: sonda {self._ka_probes}")
                self._send_probe()

    def _on_rto(self) -> None:
        item = self.window.oldest()

        if item is None:
            self.rtx.stop()
            return

        in_handshake = self.state in (TTPState.SYN_SENT, TTPState.SYN_RECEIVED)
        limit = self.cfg.syn_retries if in_handshake else self.cfg.max_retries

        if self.rtx.retries >= limit:
            self._abort(
                TTPTimeout(f"Sem resposta do par após {self.rtx.retries} retransmissões."),
                send_rst=False,
            )
            return

        self.stats["timeouts"] += 1
        self._dup_acks = 0
        self._recover = self.sequence.send_next

        self._retransmit(item, f"timeout, RTO={self.rtx.rto * 1000:.0f} ms")
        self.rtx.backoff()  # dobra o RTO e conta a tentativa

    def _on_persist(self) -> None:
        if self._persist_probes >= self.cfg.persist_max_probes:
            self._abort(TTPTimeout("Janela do par ficou zero e ele não responde."), send_rst=False)
            return

        self._persist_probes += 1
        self._persist_rto = min(self._persist_rto * 2, self.cfg.rto_max)
        self._debug(f"persist: sondando janela zero ({self._persist_probes})")
        self._send_probe()
        self._persist.start(self._persist_rto)

    # =========================================================================
    # Chegada de segmentos (RFC 793, "SEGMENT ARRIVES", simplificada)
    # =========================================================================

    def _handle_packet(self, packet: TTPPacket) -> None:
        if self.state == TTPState.CLOSED:
            return

        self._last_rx = time.monotonic()
        self._ka_probes = 0
        self.stats["segments_received"] += 1
        self._debug(f"RX {packet}")

        if self.state == TTPState.SYN_SENT:
            self._handle_in_syn_sent(packet)
            return

        # --- RST ------------------------------------------------------------
        if packet.is_rst:
            offset = seq_diff(packet.sequence_number, self.sequence.recv_next)

            # Só vale se o SEQ cai dentro da janela de recepção (evita que um
            # atacante às cegas derrube a conexão com um RST qualquer).
            if offset < max(self.receive_buffer.free, 1):
                self._abort(TTPReset("Conexão reiniciada pelo par (RST)."), send_rst=False)

            return

        # --- SYN em estado sincronizado -------------------------------------
        if packet.is_syn:
            if self.state == TTPState.SYN_RECEIVED and packet.sequence_number == self._irs:
                # O cliente não recebeu nosso SYN-ACK e reenviou o SYN.
                item = self.window.oldest()

                if item is not None:
                    self._retransmit(item, "SYN duplicado")
            else:
                # SYN-ACK retransmitido (nosso ACK final se perdeu) ou SYN velho:
                # um ACK atual resolve os dois casos.
                self._send_ack()

            return

        # Depois do SYN inicial, todo segmento legítimo carrega ACK.
        if not packet.is_ack:
            return

        # --- ACK -------------------------------------------------------------
        if not self._process_ack(packet):
            return

        if self._finalized or self.state == TTPState.CLOSED:
            return

        # --- Dados e/ou FIN ----------------------------------------------------
        if packet.payload or packet.is_fin:
            if self.state in (TTPState.ESTABLISHED, TTPState.FIN_WAIT_1, TTPState.FIN_WAIT_2):
                self._process_data(packet)
            else:
                # CLOSE_WAIT/CLOSING/LAST_ACK/TIME_WAIT: o par já enviou o FIN;
                # qualquer coisa a mais é retransmissão -> só re-ACK.
                self.stats["duplicates"] += 1
                self._send_ack()

                if self.state == TTPState.TIME_WAIT:
                    self._time_wait_deadline = time.monotonic() + self.cfg.time_wait

            return

        # ACK puro com SEQ velho = sonda de keepalive / janela zero -> responde.
        if seq_lt(packet.sequence_number, self.sequence.recv_next):
            self._send_ack()

    def _handle_in_syn_sent(self, packet: TTPPacket) -> None:
        seq = self.sequence

        if packet.is_ack:
            acceptable = seq_lt(seq.initial_sequence, packet.acknowledgment_number) and seq_leq(
                packet.acknowledgment_number, seq.send_next
            )

            if not acceptable:
                if not packet.is_rst:
                    self._send_raw(make_reset_for(packet))
                return

        if packet.is_rst:
            if packet.is_ack:
                self._abort(TTPRefused("Conexão recusada pelo par."), send_rst=False)
            return

        if packet.is_syn and packet.is_ack:
            self._irs = packet.sequence_number
            seq.recv_next = seq_add(packet.sequence_number, 1)

            self._peer_window = packet.window
            self.window.size = packet.window
            self._wl1 = packet.sequence_number
            self._wl2 = packet.acknowledgment_number

            self._consume_ack(packet.acknowledgment_number)
            self.rtx.stop()

            self._set_state(TTPState.ESTABLISHED)
            self._send_ack()
            self._notify_established()

    def _consume_ack(self, ack: int) -> list[InFlight]:
        """Avança SND.UNA, remove da janela o que foi confirmado e mede RTT."""
        self.sequence.acknowledge(ack)
        acked = self.window.acknowledge(ack)
        now = time.monotonic()

        # Karn: pega o segmento confirmado MAIS NOVO que nunca foi retransmitido.
        for item in reversed(acked):
            if not item.retransmitted:
                self.rtx.sample(now - item.sent_at)
                break

        return acked

    def _update_peer_window(self, packet: TTPPacket) -> None:
        # SND.WL1/WL2 (RFC 793): só aceita a janela de um segmento mais novo
        # que o último que a atualizou -- senão um ACK velho/reordenado
        # reabriria/fecharia a janela com um valor ultrapassado.
        newer = seq_lt(self._wl1, packet.sequence_number) or (
            packet.sequence_number == self._wl1 and seq_leq(self._wl2, packet.acknowledgment_number)
        )

        if newer:
            self._peer_window = packet.window
            self.window.size = packet.window
            self._wl1 = packet.sequence_number
            self._wl2 = packet.acknowledgment_number

            if packet.window > 0:
                self._persist_probes = 0

    def _process_ack(self, packet: TTPPacket) -> bool:
        seq = self.sequence
        ack = packet.acknowledgment_number

        if self.state == TTPState.SYN_RECEIVED:
            # O ACK precisa confirmar nosso SYN-ACK; senão, é lixo/antigo -> RST.
            if not (seq_lt(seq.send_unacked, ack) and seq_leq(ack, seq.send_next)):
                self._send_raw(make_reset_for(packet))
                return False

        if seq_lt(seq.send_next, ack):
            # Confirma algo que nunca enviamos: ignora e diz onde estamos.
            self._send_ack()
            return False

        if seq_lt(seq.send_unacked, ack):
            # ---- ACK novo: progresso ---------------------------------------
            self._consume_ack(ack)
            self._dup_acks = 0

            self.rtx.progress()

            if self.window.pending_count:
                self.rtx.restart()   # o timer passa a vigiar o novo segmento mais antigo
            else:
                self.rtx.stop()

            self._update_peer_window(packet)

            if self.state == TTPState.SYN_RECEIVED:
                self._set_state(TTPState.ESTABLISHED)
                self._notify_established()

            if self._fin_sent and ack == seq_add(self._fin_seq, 1):
                self._on_fin_acked()

            # NewReno: ACK PARCIAL (não cobre tudo que estava em voo na perda)
            # significa que há outro buraco -> retransmite já, sem esperar RTO.
            if self._recover is not None:
                if seq_lt(ack, self._recover) and self.window.pending_count:
                    item = self.window.oldest()

                    if item is not None:
                        self._retransmit(item, "ACK parcial")
                else:
                    self._recover = None

        elif ack == seq.send_unacked:
            # ---- ACK repetido ----------------------------------------------
            # Duplicado "de verdade" (RFC 5681): sem dados, janela igual, e
            # existe algo em voo. Significa "recebi algo DEPOIS de um buraco".
            is_duplicate = (
                not packet.payload
                and not packet.is_syn
                and not packet.is_fin
                and packet.window == self._peer_window
                and self.window.pending_count > 0
            )

            self._update_peer_window(packet)

            if is_duplicate:
                self._dup_acks += 1
                self.stats["dup_acks"] += 1

                if self._dup_acks == self.cfg.dup_ack_threshold:
                    # FAST RETRANSMIT: 3 ACKs repetidos => quase certamente o
                    # segmento do buraco se perdeu; não vale esperar o RTO.
                    item = self.window.oldest()

                    if item is not None:
                        self.stats["fast_retransmissions"] += 1
                        self._recover = seq.send_next
                        self._retransmit(item, f"fast retransmit, {self._dup_acks} ACKs repetidos")

        # (ACK menor que SND.UNA: velho/reordenado -> ignora)

        if not self._finalized:
            self._flush()  # a janela pode ter aberto

        return True

    # ---- Dados -----------------------------------------------------------------

    def _process_data(self, packet: TTPPacket) -> None:
        seq = self.sequence
        seq_no = packet.sequence_number
        payload = packet.payload
        fin = packet.is_fin

        window = self.receive_buffer.free  # espaço REAL (não o anunciado com SWS)
        length = len(payload) + (1 if fin else 0)

        status = seq.classify(seq_no, length, window)

        if status is ReceiveStatus.DUPLICATE:
            # Já temos tudo isso (nosso ACK se perdeu?). Re-ACK para o
            # remetente parar de retransmitir; NÃO entrega de novo.
            self.stats["duplicates"] += 1
            self._debug(f"duplicado SEQ={seq_no}")
            self._send_ack()
            return

        if status is ReceiveStatus.OUT_OF_WINDOW:
            self.stats["out_of_window"] += 1
            self._debug(f"fora da janela SEQ={seq_no}")
            self._send_ack()
            return

        if status is ReceiveStatus.OVERLAP:
            # Começa em bytes que já temos mas traz bytes novos (retransmissão
            # com outra segmentação): descarta só a parte velha.
            cut = seq_diff(seq.recv_next, seq_no)
            payload = payload[cut:]
            seq_no = seq.recv_next
            status = ReceiveStatus.EXPECTED

        # Corta o que passa da borda direita da janela (o remetente reenvia).
        if payload:
            room = window - seq_diff(seq_no, seq.recv_next)

            if len(payload) > room:
                payload = payload[: max(room, 0)]
                fin = False

        if status is ReceiveStatus.EXPECTED:
            self._deliver(payload, fin)
            self._drain_out_of_order()

        else:  # FUTURE: há um buraco antes deste segmento
            self.stats["out_of_order"] += 1
            self._debug(f"fora de ordem SEQ={seq_no} (esperado {seq.recv_next})")

            previous = self._ooo.get(seq_no)

            if previous is None or len(payload) > len(previous[0]) or (fin and not previous[1]):
                self._ooo[seq_no] = (payload, fin)

        # ACK imediato e cumulativo. Num FUTURE ele repete o RCV.NXT atual =
        # ACK duplicado, que é justamente o sinal para o fast retransmit.
        self._send_ack()

    def _deliver(self, payload: bytes, fin: bool) -> None:
        """Entrega bytes EM ORDEM para a aplicação e avança RCV.NXT."""
        if payload:
            self.receive_buffer.push(payload)
            self.sequence.advance_receive(len(payload))
            self.stats["bytes_received"] += len(payload)

        if fin:
            self.sequence.advance_receive(1)  # o FIN ocupa 1 número de sequência
            self._on_remote_fin()

    def _drain_out_of_order(self) -> None:
        """Depois de avançar RCV.NXT, entrega o que estava guardado e agora encaixa."""
        while self._ooo and not self._finalized:
            recv_next = self.sequence.recv_next

            key = next(
                (
                    candidate
                    for candidate in self._ooo
                    if seq_diff(candidate, recv_next) == 0 or seq_diff(candidate, recv_next) >= SEQ_HALF
                ),
                None,
            )

            if key is None:
                break

            payload, fin = self._ooo.pop(key)

            if key != recv_next:
                cut = seq_diff(recv_next, key)

                if cut >= len(payload) + (1 if fin else 0):
                    continue  # já coberto por dados entregues

                payload = payload[cut:]

            self._log_drain(key, len(payload))
            self._deliver(payload, fin)

    def _log_drain(self, seq_no: int, size: int) -> None:
        self._debug(f"liberando segmento guardado SEQ={seq_no} ({size} bytes)")

    # ---- FIN -------------------------------------------------------------------

    def _on_remote_fin(self) -> None:
        """O FIN do par foi recebido EM ORDEM (todos os dados antes dele já chegaram)."""
        self._log("[TTP] FIN do par recebido (EOF).")
        self.receive_buffer.set_eof()

        if self.state == TTPState.ESTABLISHED:
            self._set_state(TTPState.CLOSE_WAIT)
        elif self.state == TTPState.FIN_WAIT_1:
            self._set_state(TTPState.CLOSING)
        elif self.state == TTPState.FIN_WAIT_2:
            self._enter_time_wait()

    def _on_fin_acked(self) -> None:
        """O ACK do NOSSO FIN chegou."""
        if self.state == TTPState.FIN_WAIT_1:
            self._fin_wait2_deadline = time.monotonic() + self.cfg.fin_wait2_timeout
            self._set_state(TTPState.FIN_WAIT_2)
        elif self.state == TTPState.CLOSING:
            self._enter_time_wait()
        elif self.state == TTPState.LAST_ACK:
            self._finalize()

    def _enter_time_wait(self) -> None:
        self._time_wait_deadline = time.monotonic() + self.cfg.time_wait
        self.rtx.stop()
        self._set_state(TTPState.TIME_WAIT)

    # =========================================================================
    # Encerramento
    # =========================================================================

    def _finalize(self, error: BaseException | None = None) -> None:
        """Libera tudo e acorda quem estiver esperando. Idempotente."""
        if self._finalized:
            return

        self._finalized = True

        if error is not None and self._error is None:
            self._error = error

        self.state = TTPState.CLOSED
        self.rtx.stop()
        self._persist.stop()
        self.window.clear()
        self._send_buf.clear()
        self._ooo.clear()

        if self._error is not None:
            self.receive_buffer.set_error(self._error)
        else:
            self.receive_buffer.set_eof()

        self.close_event.set()
        self._cond.notify_all()

        self._log("[TTP] Conexão encerrada." if error is None else f"[TTP] Conexão abortada: {error}")

        if self._dispatcher is not None and self.remote_ip is not None:
            self._dispatcher.unregister(self.remote_ip, self.remote_port, self._inbox)

            if self._owns_dispatcher:
                self._dispatcher.stop()

        if self.owns_socket and self.socket is not None:
            self.socket.close()

        if self._on_closed is not None:
            try:
                self._on_closed(self)
            except Exception:
                self._log("erro no callback on_closed:\n" + traceback.format_exc())

    def _abort(self, error: BaseException, send_rst: bool) -> None:
        if self._finalized:
            return

        if send_rst and self.state in _SYNCHRONIZED + (TTPState.SYN_RECEIVED,):
            rst = self._make_packet(TTPFlags.RST)
            self._transmit(rst)

        self._finalize(error)

    def _notify_established(self) -> None:
        self._last_rx = time.monotonic()
        self._cond.notify_all()

        if self._on_established is not None:
            try:
                self._on_established(self)
            except Exception:
                self._log("erro no callback on_established:\n" + traceback.format_exc())

    # =========================================================================
    # API pública
    # =========================================================================

    def connect(self, timeout: float | None = None) -> "TTPConnection":
        """Abertura ativa (cliente). Bloqueia até ESTABLISHED ou falhar."""
        with self._cond:
            if self.state != TTPState.CLOSED or self._finalized:
                raise RuntimeError("Conexão já iniciada.")

            if self.remote_ip is None or self.remote_port is None:
                raise ValueError("connect() precisa de remote_ip e remote_port.")

            self._ensure_dispatcher()
            self._dispatcher.register(self.remote_ip, self.remote_port, self._inbox)
            self._start_thread()

            self._set_state(TTPState.SYN_SENT)

            syn = self._make_packet(TTPFlags.SYN)
            self.sequence.advance_send(1)
            self._send_tracked(syn)  # com retransmissão: SYN perdido não trava mais

            self._cond.wait_for(
                lambda: self.state != TTPState.SYN_SENT,
                timeout if timeout is not None else self.cfg.connect_timeout,
            )

            if self.state == TTPState.SYN_SENT:
                self._abort(TTPTimeout("connect() excedeu o tempo limite."), send_rst=False)

            if self._error is not None:
                self._raise_error()

        return self

    def _begin_passive(self, syn: TTPPacket) -> None:
        """Abertura passiva a partir de um SYN já recebido (usado pelo TTPServer)."""
        with self._cond:
            self._ensure_dispatcher()

            self._irs = syn.sequence_number
            self.sequence.recv_next = seq_add(syn.sequence_number, 1)
            self._peer_window = syn.window
            self.window.size = syn.window
            self._wl1 = syn.sequence_number
            self._wl2 = 0

            self._dispatcher.register(self.remote_ip, self.remote_port, self._inbox)
            self._start_thread()

            self._set_state(TTPState.SYN_RECEIVED)

            synack = self._make_packet(TTPFlags.SYN | TTPFlags.ACK)
            self.sequence.advance_send(1)
            self._send_tracked(synack)  # com retransmissão

    def accept(self, timeout: float | None = None) -> "TTPConnection":
        """
        Abertura passiva de UMA conexão avulsa (sem TTPServer): espera o
        primeiro SYN na própria porta. Para aceitar vários clientes use
        ttp.server.TTPServer.
        """
        with self._lock:
            if self.state != TTPState.CLOSED or self._finalized:
                raise RuntimeError("Socket já está em uso.")

        syns: queue.Queue = queue.Queue()

        self._ensure_socket()
        self._dispatcher = PacketDispatcher(
            self.socket,
            self.local_port,
            on_unmatched=lambda p, ip: syns.put((p, ip)) if (p.is_syn and not p.is_ack) else None,
            name=f"{self.logger_manager.side_name}-rx",
        )
        self._owns_dispatcher = True
        self._dispatcher.start()

        self._log("[TTP] Aguardando SYN...")

        try:
            syn, ipv4 = syns.get(timeout=timeout)
        except queue.Empty:
            self._dispatcher.stop()
            raise TTPTimeout("accept() excedeu o tempo limite.")

        self.remote_ip = ipv4.source_ip
        self.remote_port = syn.source_port
        self._begin_passive(syn)

        with self._cond:
            self._cond.wait_for(lambda: self.state != TTPState.SYN_RECEIVED, self.cfg.connect_timeout)

            if self.state != TTPState.ESTABLISHED:
                self._abort(TTPTimeout("Handshake não concluído."), send_rst=False)
                self._raise_error()

        return self

    def wait_established(self, timeout: float | None = None) -> bool:
        with self._cond:
            self._cond.wait_for(
                lambda: self.state not in (TTPState.SYN_SENT, TTPState.SYN_RECEIVED, TTPState.CLOSED)
                or self._finalized,
                timeout,
            )

            return self.state == TTPState.ESTABLISHED

    def send(self, data: bytes, timeout: float | None = None) -> int:
        """
        Enfileira `data` para envio e retorna QUANDO FOI ACEITO no buffer de
        envio (como send() do TCP): não significa que o par já recebeu. Use
        wait_for_acks() se precisar dessa garantia.

        Bloqueia (backpressure) se o buffer de envio estiver cheio -- ou seja,
        se o par/rede não está dando conta. Aceita qualquer tamanho: o corte
        em segmentos de até MSS bytes é feito em _flush().
        """
        data = bytes(data)
        deadline = None if timeout is None else time.monotonic() + timeout
        offset = 0

        with self._cond:
            while offset < len(data):
                self._check_writable()

                room = self.cfg.send_buffer - len(self._send_buf)

                if room <= 0:
                    remaining = None if deadline is None else deadline - time.monotonic()

                    if remaining is not None and remaining <= 0:
                        raise TimeoutError("send() excedeu o tempo limite.")

                    self._cond.wait(remaining)
                    continue

                take = min(room, len(data) - offset)
                self._send_buf += data[offset : offset + take]
                offset += take
                self.stats["bytes_sent"] += take

                self._flush()

        return len(data)

    def _check_writable(self) -> None:
        if self._error is not None:
            self._raise_error()

        if self.state not in (TTPState.ESTABLISHED, TTPState.CLOSE_WAIT) or self._fin_queued:
            raise TTPClosed("Conexão não está aberta para envio.")

    def recv(self, max_bytes: int | None = None, timeout: float | None = None) -> bytes:
        """
        Devolve até `max_bytes` bytes (ou tudo que houver). Bloqueia até
        haver dados. Devolve b"" quando o par encerrou (EOF). Levanta o erro
        da conexão (TTPReset/TTPTimeout...) depois de entregar o que sobrou.
        """
        data = self.receive_buffer.read(max_bytes, timeout)

        if data:
            self._maybe_send_window_update()

        return data

    def recv_exact(self, size: int, timeout: float | None = None) -> bytes:
        """Lê exatamente `size` bytes (levanta EOFError se o fluxo acabar antes)."""
        remaining = size
        chunks = []
        deadline = None if timeout is None else time.monotonic() + timeout

        while remaining > 0:
            left = None if deadline is None else max(0.0, deadline - time.monotonic())
            chunk = self.recv(remaining, left)

            if not chunk:
                raise EOFError(f"Fluxo encerrado: faltaram {remaining} de {size} bytes.")

            chunks.append(chunk)
            remaining -= len(chunk)

        return b"".join(chunks)

    def _maybe_send_window_update(self) -> None:
        """
        A aplicação leu dados e o buffer esvaziou. Se antes anunciávamos
        janela pequena/zero, avisa o remetente AGORA -- senão ele ficaria
        parado até o próximo persist-probe.
        """
        with self._lock:
            if self.state not in _SYNCHRONIZED:
                return

            window = self._adv_window()
            threshold = min(self.mss, self.recv_capacity // 2)

            if window - self._last_adv >= threshold or (self._last_adv == 0 and window > 0):
                self._send_ack()

    def wait_for_acks(self, timeout: float | None = 5.0) -> bool:
        """
        Bloqueia até TUDO que foi enviado ter sido confirmado pelo par (ou
        até o timeout / falha da conexão). Útil antes de fechar.
        """
        with self._cond:
            ok = self._cond.wait_for(
                lambda: (self.window.empty and not self._send_buf) or self._finalized,
                timeout,
            )

            return bool(ok) and self.window.empty and not self._send_buf

    def shutdown_write(self) -> None:
        """
        Meio-fechamento: avisa o par que não vamos enviar mais nada (FIN),
        depois de entregar tudo que está no buffer. Continuamos podendo
        RECEBER até o par também fechar.
        """
        with self._cond:
            if self.state in (TTPState.ESTABLISHED, TTPState.CLOSE_WAIT) and not self._fin_queued:
                self._fin_queued = True
                self._flush()

    def close(self, timeout: float | None = None) -> bool:
        """
        Fechamento gracioso. Devolve True se terminou limpo.

        1. entrega o que ainda estava no buffer de envio;
        2. envia FIN e espera o ACK dele;
        3. espera o FIN do par (que sinaliza que ele também terminou).

        O prazo (`close_timeout`) é de INATIVIDADE: enquanto houver progresso
        (dados sendo confirmados) ele é renovado, então fechar logo depois de
        enviar um arquivo grande não aborta no meio.
        """
        timeout = self.cfg.close_timeout if timeout is None else timeout

        with self._cond:
            if self.state == TTPState.CLOSED:
                return self._error is None

            if self.state in (TTPState.SYN_SENT, TTPState.SYN_RECEIVED):
                self._abort(TTPClosed("fechada antes de estabelecer"), send_rst=True)
                return False

            self.shutdown_write()

            def done() -> bool:
                return self.state in (TTPState.CLOSED, TTPState.TIME_WAIT)

            mark = (self.sequence.send_unacked, self.sequence.recv_next)
            deadline = time.monotonic() + timeout

            while not done():
                if time.monotonic() >= deadline:
                    self._log("[TTP] close(): sem progresso, abortando.")
                    self._abort(TTPTimeout("close() sem progresso."), send_rst=True)
                    return False

                self._cond.wait(0.05)

                now_mark = (self.sequence.send_unacked, self.sequence.recv_next)

                if now_mark != mark:
                    mark = now_mark
                    deadline = time.monotonic() + timeout

            return self._error is None

    def abort(self) -> None:
        """Derruba a conexão imediatamente (envia RST; dados pendentes são perdidos)."""
        with self._cond:
            self._abort(TTPClosed("Conexão abortada localmente."), send_rst=True)

    def wait_closed(self, timeout: float | None = None) -> bool:
        """Espera a conexão chegar a CLOSED (inclui o fim do TIME_WAIT)."""
        return self.close_event.wait(timeout)

    # ---- introspecção --------------------------------------------------------

    @property
    def connected(self) -> bool:
        return self.state in (
            TTPState.ESTABLISHED,
            TTPState.CLOSE_WAIT,
            TTPState.FIN_WAIT_1,
            TTPState.FIN_WAIT_2,
        )

    @property
    def peer_address(self) -> tuple[str | None, int | None]:
        return (self.remote_ip, self.remote_port)

    def info(self) -> dict:
        """Fotografia do estado interno (útil em demos e testes)."""
        with self._lock:
            return dict(
                state=self.state.name,
                srtt_ms=None if self.rtx.srtt is None else round(self.rtx.srtt * 1000, 3),
                rto_ms=round(self.rtx.rto * 1000, 1),
                peer_window=self._peer_window,
                in_flight=self.sequence.bytes_in_flight,
                send_buffer=len(self._send_buf),
                recv_buffer=len(self.receive_buffer),
                out_of_order_segments=len(self._ooo),
                **self.stats,
            )

    def __repr__(self):
        return (
            f"TTPConnection({self.local_ip}:{self.local_port} <-> "
            f"{self.remote_ip}:{self.remote_port}, {self.state.name})"
        )

    def __enter__(self):
        # Enables `with TTPConnection(...) as conn:` usage.
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

        return False
