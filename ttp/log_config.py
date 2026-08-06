import datetime
import logging
import os
from pathlib import Path

_SHARED_LOGGER = None
_SHARED_LOG_FILE_PATH = None

class _MicrosecondFormatter(logging.Formatter):
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
            global _SHARED_LOGGER, _SHARED_LOG_FILE_PATH
    
            if self.logger is not None and self.side_name == side_name:
                return self.logger
    
            log_dir = Path(os.environ.get("TTP_LOG_DIR", Path(__file__).resolve().parents[1] / "logs"))
            log_dir.mkdir(parents=True, exist_ok=True)
            desired_log_path = log_dir / "ttp_shared.log"
    
            if _SHARED_LOGGER is None or _SHARED_LOG_FILE_PATH != desired_log_path:
                logger = logging.getLogger("ttp.shared")
                logger.setLevel(logging.INFO)
                logger.propagate = False
            
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
        if self.logger is None:
            self._setup_logger(self.side_name)
    
        message = " ".join(str(arg) for arg in args)
        self.logger.info("[%s] %s", self.side_name, message)