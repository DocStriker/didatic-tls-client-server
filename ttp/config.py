# =============================================================================
# ttp/config.py
# -----------------------------------------------------------------------------
# Todos os "botões" de uma conexão TTP em um só lugar. Antes, valores como
# timeout de retransmissão (1.0 s), número de tentativas (5) e tamanho da
# janela estavam espalhados e fixos dentro de connection.py.
#
# Os valores padrão são razoáveis para uma LAN/loopback. Os testes usam
# valores bem menores (RTO de 20-50 ms) para simular perdas rapidamente.
# =============================================================================

from dataclasses import dataclass

from ttp.constants import MAX_SEGMENT_SIZE


@dataclass
class TTPConfig:
    # --- Segmentação / buffers ------------------------------------------
    mss: int = MAX_SEGMENT_SIZE           # maior payload por segmento (bytes)
    send_buffer: int = 256 * 1024         # send() bloqueia acima disso (backpressure)

    # --- Timer de retransmissão (RFC 6298) -------------------------------
    rto_initial: float = 1.0              # RTO antes da 1ª medição de RTT
    rto_min: float = 0.2                  # piso do RTO
    rto_max: float = 8.0                  # teto do RTO (com backoff exponencial)
    max_retries: int = 8                  # retransmissões de dados antes de desistir
    syn_retries: int = 5                  # idem, durante o handshake
    dup_ack_threshold: int = 3            # ACKs duplicados que disparam fast retransmit

    # --- Ciclo de vida ----------------------------------------------------
    connect_timeout: float = 30.0         # teto absoluto de connect()
    close_timeout: float = 8.0            # close() desiste se não houver progresso
    time_wait: float = 1.0                # fica re-ACKando FINs duplicados
    fin_wait2_timeout: float = 10.0       # espera máxima pelo FIN do par

    # --- Detecção de par morto (keepalive TCP-like; desligado por padrão) -
    keepalive_interval: float | None = None   # ocioso por X s -> começa a sondar
    keepalive_probes: int = 3                 # sondas sem resposta -> aborta
    keepalive_probe_interval: float = 1.0     # intervalo entre sondas

    # --- Janela zero (persist timer) ---------------------------------------
    persist_max_probes: int = 12

    # --- Granularidade do laço interno -------------------------------------
    tick: float = 0.02                    # de quanto em quanto tempo checa timers
