# =============================================================================
# ttp/log_config.py
# -----------------------------------------------------------------------------
# Um único logging.Logger compartilhado (logs/ttp_shared.log) onde o lado
# cliente e o lado servidor escrevem, marcados com `side_name`, para que as
# linhas dos dois pares possam ser intercaladas e comparadas no tempo --
# muito útil para entender handshake/retransmissão.
#
# BUG CORRIGIDO: a versão anterior só atribuía `self.logger` dentro do bloco
# "se ainda não existe logger compartilhado". Na SEGUNDA conexão criada no
# mesmo processo (ex.: cliente e servidor no mesmo script, ou um servidor
# aceitando vários clientes) o logger já existia, o bloco era pulado,
# `self.logger` ficava None e o primeiro .log() quebrava com
# "AttributeError: 'NoneType' object has no attribute 'info'".
#
# Variáveis de ambiente:
#   TTP_LOG_DIR    diretório do arquivo de log (padrão: <projeto>/logs)
#   TTP_LOG_LEVEL  DEBUG | INFO (padrão) | WARNING | OFF
#                  (DEBUG mostra cada segmento enviado/recebido)
# =============================================================================

import datetime
import logging
import os
import threading
from pathlib import Path

_LOCK = threading.Lock()
_LOGGER: logging.Logger | None = None
_LOGGER_PATH: Path | None = None


class _MicrosecondFormatter(logging.Formatter):
    # Standard logging timestamps only have millisecond precision by
    # default; this formatter prints full microsecond precision, which
    # matters when comparing the exact ordering of fast retransmission /
    # ACK events.
    def formatTime(self, record, datefmt=None):
        if datefmt:
            return datetime.datetime.fromtimestamp(record.created).strftime(datefmt)
        return datetime.datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S.%f")


def _level_from_env() -> int | None:
    name = os.environ.get("TTP_LOG_LEVEL", "INFO").upper()

    if name in ("OFF", "NONE", "0"):
        return None

    return getattr(logging, name, logging.INFO)


def _get_logger() -> logging.Logger:
    """Cria (uma única vez por processo/diretório) e devolve o logger."""
    global _LOGGER, _LOGGER_PATH

    log_dir = Path(os.environ.get("TTP_LOG_DIR", Path(__file__).resolve().parents[1] / "logs"))
    path = log_dir / "ttp_shared.log"

    with _LOCK:
        if _LOGGER is not None and _LOGGER_PATH == path:
            return _LOGGER

        logger = logging.getLogger("ttp.shared")
        logger.propagate = False  # don't also bubble up to the root logger

        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()

        level = _level_from_env()

        if level is None:
            logger.addHandler(logging.NullHandler())
            logger.setLevel(logging.CRITICAL + 1)
        else:
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
                handler = logging.FileHandler(path, encoding="utf-8")
                handler.setFormatter(_MicrosecondFormatter("%(asctime)s %(levelname)s %(message)s"))
            except OSError:
                # Sem permissão de escrita (FS somente leitura, etc.): o
                # protocolo não pode falhar por causa de log.
                handler = logging.NullHandler()

            logger.addHandler(handler)
            logger.setLevel(level)

        _LOGGER = logger
        _LOGGER_PATH = path

        return logger


class LoggerManager:
    def __init__(self, side_name: str):
        self.side_name = side_name
        self.logger: logging.Logger | None = None

    def _ensure(self) -> logging.Logger:
        if self.logger is None:
            self.logger = _get_logger()

        return self.logger

    def log(self, *args, **kwargs) -> None:
        """Linha de nível INFO: eventos relevantes (estado, retransmissão...)."""
        self._emit(logging.INFO, args)

    def debug(self, *args) -> None:
        """Linha de nível DEBUG: detalhe por segmento (ligue com TTP_LOG_LEVEL=DEBUG)."""
        self._emit(logging.DEBUG, args)

    def _emit(self, level: int, args) -> None:
        logger = self._ensure()

        if not logger.isEnabledFor(level):
            return  # evita formatar strings à toa no caminho quente

        message = " ".join(str(arg) for arg in args)
        logger.log(level, "[%s] %s", self.side_name, message)
