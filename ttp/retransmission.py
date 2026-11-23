# =============================================================================
# ttp/retransmission.py
# -----------------------------------------------------------------------------
# RetransmissionManager = timer + contador de tentativas + estimador de RTT.
#
# O QUE MUDOU:
#   Antes o timeout era FIXO (1.0 s). Numa LAN com RTT de 0,3 ms isso espera
#   3000x mais que o necessário; num enlace lento (RTT 2 s) retransmite sem
#   necessidade. Agora o RTO (Retransmission TimeOut) é ADAPTATIVO, calculado
#   como na RFC 6298:
#
#     1ª medição R:        SRTT   = R
#                          RTTVAR = R / 2
#     medições seguintes:  RTTVAR = (1 - β)·RTTVAR + β·|SRTT - R|     β = 1/4
#                          SRTT   = (1 - α)·SRTT   + α·R             α = 1/8
#     em ambos os casos:   RTO    = SRTT + max(G, 4·RTTVAR)    (G = granularidade)
#
#   Exemplo numérico (R1 = 100 ms, depois R2 = 140 ms):
#     R1:  SRTT = 100 ms              RTTVAR = 50 ms           RTO = 100 + 4·50 = 300 ms
#     R2:  RTTVAR = 0,75·50 + 0,25·|100-140| = 37,5 + 10 = 47,5 ms
#          SRTT   = 0,875·100 + 0,125·140    = 87,5 + 17,5 = 105 ms
#          RTO    = 105 + 4·47,5             = 295 ms
#
#   Além disso:
#     * Backoff exponencial: a cada timeout o RTO dobra (até rto_max). Se a
#       rede está congestionada, retransmitir mais rápido só piora.
#     * Algoritmo de Karn: RTT de segmento RETRANSMITIDO nunca é amostrado
#       (não dá para saber a qual transmissão o ACK se refere). Isso é
#       responsabilidade de quem chama sample(); ver TTPConnection._process_ack.
# =============================================================================

from ttp.timer import TTPTimer


class RetransmissionManager:
    ALPHA = 1 / 8
    BETA = 1 / 4
    K = 4

    def __init__(
        self,
        timeout: float = 1.0,
        max_retries: int = 5,
        min_rto: float = 0.2,
        max_rto: float = 8.0,
        granularity: float = 0.01,
    ):
        self.min_rto = min_rto
        self.max_rto = max_rto
        self.granularity = granularity
        self.max_retries = max_retries

        self.rto = self._clamp(timeout)
        self.timer = TTPTimer(self.rto)
        self.retries = 0

        self.srtt: float | None = None
        self.rttvar: float | None = None

    # ---- compatibilidade com o nome antigo -------------------------------
    @property
    def timeout(self) -> float:
        return self.rto

    # ---- controle do timer ------------------------------------------------

    def start(self):
        """Segmento novo ficou em voo: zera tentativas e arma o timer."""
        self.retries = 0
        self.timer.start(self.rto)

    def restart(self):
        """Rearma o timer (sem contar como retransmissão)."""
        self.timer.start(self.rto)

    def progress(self):
        """Chegou ACK de dado novo: a rede está viva, zera as tentativas."""
        self.retries = 0

    def backoff(self):
        """Estourou o timer: conta a tentativa, dobra o RTO e rearma."""
        self.retries += 1
        self.rto = self._clamp(self.rto * 2)
        self.timer.start(self.rto)

    def stop(self):
        self.timer.stop()

    # ---- estimador de RTT -------------------------------------------------

    def sample(self, rtt: float) -> float:
        """Incorpora uma medição de RTT (em segundos) e devolve o novo RTO."""
        if self.srtt is None:
            self.srtt = rtt
            self.rttvar = rtt / 2
        else:
            self.rttvar = (1 - self.BETA) * self.rttvar + self.BETA * abs(self.srtt - rtt)
            self.srtt = (1 - self.ALPHA) * self.srtt + self.ALPHA * rtt

        self.rto = self._clamp(self.srtt + max(self.granularity, self.K * self.rttvar))

        return self.rto

    def _clamp(self, value: float) -> float:
        return max(self.min_rto, min(self.max_rto, value))

    # ---- consultas --------------------------------------------------------

    @property
    def expired(self):
        return self.timer.expired

    @property
    def running(self):
        return self.timer.running

    @property
    def exhausted(self):
        # True once we've retried max_retries times without success --
        # signals the caller to give up (e.g. treat the connection as dead).
        return self.retries >= self.max_retries
