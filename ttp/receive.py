# =============================================================================
# ttp/receive.py
# -----------------------------------------------------------------------------
# ReceiveBuffer: ponte entre a thread que recebe pacotes da rede e a thread
# da aplicação que chama connection.recv().
#
# O QUE MUDOU:
#   * Era uma fila de "pedaços" (cada segmento = um item) sem limite de
#     tamanho e com espera ocupada (polling a cada 10 ms). Agora é um
#     FLUXO DE BYTES (como o TCP): `read(n)` devolve até n bytes,
#     independentemente de como o remetente os dividiu em segmentos.
#   * Tem CAPACIDADE: `free` é exatamente o que o TTP anuncia como "janela".
#     Se a aplicação lê devagar, o buffer enche, a janela vai a zero e o
#     remetente é freado (controle de fluxo / backpressure).
#   * Usa threading.Condition (acorda na hora, sem polling).
#   * Sabe sinalizar FIM DE FLUXO (EOF, quando o par enviou FIN) e ERRO
#     (reset/timeout). Antes, quem estava em recv() travava para sempre
#     se o par fechasse a conexão.
# =============================================================================

import threading
import time

from ttp.constants import DEFAULT_WINDOW_SIZE


class ReceiveBuffer:
    def __init__(self, capacity: int = DEFAULT_WINDOW_SIZE):
        self.capacity = capacity
        self._buffer = bytearray()
        self._cond = threading.Condition()
        self._eof = False
        self._error: BaseException | None = None

    # ---- produtor (thread de rede) ----------------------------------------

    def push(self, data: bytes) -> None:
        with self._cond:
            self._buffer += data
            self._cond.notify_all()

    def set_eof(self) -> None:
        with self._cond:
            self._eof = True
            self._cond.notify_all()

    def set_error(self, error: BaseException) -> None:
        with self._cond:
            if self._error is None:
                self._error = error
            self._cond.notify_all()

    # ---- consumidor (thread da aplicação) -----------------------------------

    def read(self, max_bytes: int | None = None, timeout: float | None = None) -> bytes:
        """
        Bloqueia até haver ao menos 1 byte e devolve até `max_bytes`.
        Devolve b"" quando o par encerrou e não há mais nada (EOF).
        Levanta o erro da conexão (se houver) depois de entregar o que sobrou.
        """
        deadline = None if timeout is None else time.monotonic() + timeout

        with self._cond:
            while not self._buffer and not self._eof and self._error is None:
                remaining = None if deadline is None else deadline - time.monotonic()

                if remaining is not None and remaining <= 0:
                    raise TimeoutError("recv() excedeu o tempo limite.")

                self._cond.wait(remaining)

            if self._buffer:
                count = len(self._buffer) if max_bytes is None else min(max_bytes, len(self._buffer))
                data = bytes(self._buffer[:count])
                del self._buffer[:count]

                return data

            if self._error is not None:
                raise self._error

            return b""

    def read_exact(self, size: int, timeout: float | None = None) -> bytes:
        """
        Lê EXATAMENTE `size` bytes (necessário para ler cabeçalhos de
        tamanho fixo em cima de um fluxo). Levanta EOFError se o fluxo
        acabar antes. Lê em pedaços para nunca exigir mais que a capacidade
        do buffer (senão a janela fecharia e daria deadlock).
        """
        chunks = []
        remaining = size
        deadline = None if timeout is None else time.monotonic() + timeout

        while remaining > 0:
            left = None if deadline is None else max(0.0, deadline - time.monotonic())

            chunk = self.read(remaining, left)

            if not chunk:
                raise EOFError(f"Fluxo encerrado: faltaram {remaining} de {size} bytes.")

            chunks.append(chunk)
            remaining -= len(chunk)

        return b"".join(chunks)

    # nome antigo
    pop = read

    # ---- consultas -----------------------------------------------------------

    @property
    def free(self) -> int:
        """Espaço livre = janela de recepção que podemos anunciar."""
        with self._cond:
            return max(0, self.capacity - len(self._buffer))

    @property
    def empty(self) -> bool:
        with self._cond:
            return not self._buffer

    @property
    def at_eof(self) -> bool:
        with self._cond:
            return self._eof and not self._buffer

    def clear(self) -> None:
        with self._cond:
            self._buffer.clear()

    def __len__(self) -> int:
        with self._cond:
            return len(self._buffer)
