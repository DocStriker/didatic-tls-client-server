# =============================================================================
# ttp/log_config.py
# -----------------------------------------------------------------------------
# Sets up a single shared `logging.Logger` (writing to logs/ttp_shared.log)
# that both the client-side and server-side TTPConnection instances write
# to, tagged with a `side_name` (e.g. "Client"/"Server") so log lines from
# both peers can be interleaved and compared chronologically -- extremely
# useful for understanding handshake/retransmission timing when debugging
# the protocol.
# =============================================================================

import datetime
import logging
import os
from pathlib import Path
from ttp.constants import _SHARED_LOGGER, _SHARED_LOG_FILE_PATH

class _MicrosecondFormatter(logging.Formatter):
    # Standard logging timestamps only have millisecond precision by
    # default; this formatter prints full microsecond precision, which
    # matters when comparing the exact ordering of fast retransmission /
    # ACK events.
    def formatTime(self, record, datefmt=None):
        if datefmt:
            return datetime.datetime.fromtimestamp(record.created).strftime(datefmt)
        return datetime.datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S.%f")

class LoggerManager:
    def __init__(self, side_name: str):
        self.side_name = side_name
        self.logger = None
        self.log_file_path = None

    def _setup_logger(self, side_name: str) -> logging.Logger:
            # Uses module-level globals (imported from ttp.constants) as a
            # process-wide cache, so repeated TTPConnection instances in the
            # same process reuse one Logger/FileHandler instead of opening
            # the log file multiple times or duplicating log lines.
            global _SHARED_LOGGER, _SHARED_LOG_FILE_PATH

            if self.logger is not None and self.side_name == side_name:
                return self.logger

            # Log directory can be overridden via the TTP_LOG_DIR env var;
            # otherwise defaults to <project_root>/logs.
            log_dir = Path(os.environ.get("TTP_LOG_DIR", Path(__file__).resolve().parents[1] / "logs"))
            log_dir.mkdir(parents=True, exist_ok=True)
            desired_log_path = log_dir / "ttp_shared.log"

            if _SHARED_LOGGER is None or _SHARED_LOG_FILE_PATH != desired_log_path:
                logger = logging.getLogger("ttp.shared")
                logger.setLevel(logging.INFO)
                logger.propagate = False  # don't also bubble up to the root logger

                # Remove any previously attached handlers (relevant if this
                # runs more than once in the same interpreter, e.g. tests).
                for handler in list(logger.handlers):
                    logger.removeHandler(handler)
                    handler.close()

                formatter = _MicrosecondFormatter("%(asctime)s %(levelname)s %(message)s")
                file_handler = logging.FileHandler(desired_log_path, encoding="utf-8")
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)

                _SHARED_LOGGER = logger
                _SHARED_LOG_FILE_PATH = desired_log_path


                self.logger = _SHARED_LOGGER
                self.log_file_path = desired_log_path
                self.side_name = side_name

            return self.logger

    def log(self, *args, **kwargs) -> None:
        # Lazily initializes the logger on first use, then writes a single
        # INFO-level line prefixed with "[side_name]" so log entries from
        # different TTPConnection sides are easy to tell apart when reading
        # ttp_shared.log.
        if self.logger is None:
            self._setup_logger(self.side_name)

        message = " ".join(str(arg) for arg in args)
        self.logger.info("[%s] %s", self.side_name, message)
