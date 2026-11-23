import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

os.environ.setdefault("TTP_LOG_LEVEL", "OFF")  # testes não escrevem log em disco
