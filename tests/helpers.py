"""Utilitários compartilhados pelos testes do TTP sobre a rede simulada."""

import threading
import time

from ttp.config import TTPConfig
from ttp.connection import TTPConnection
from ttp.server import TTPServer

SERVER_IP, CLIENT_IP = "10.0.0.1", "10.0.0.2"


def fast_config(**overrides) -> TTPConfig:
    """Timers curtos para que cenários de perda terminem em milissegundos."""
    values = dict(rto_initial=0.05, rto_min=0.02, rto_max=0.4, tick=0.005,
                  time_wait=0.1, close_timeout=3.0, connect_timeout=5.0)
    values.update(overrides)
    return TTPConfig(**values)


def connect_pair(net, window=32768, config=None, server_config=None, port=9000):
    """Abre uma conexão cliente<->servidor na rede simulada. Devolve (listener, cliente, servidor)."""
    config = config or fast_config()
    listener = TTPServer(SERVER_IP, port, window_size=window, socket=net.socket(SERVER_IP),
                         config=server_config or config, side_name="S")
    listener.start()

    accepted = {}
    thread = threading.Thread(target=lambda: accepted.update(conn=listener.accept(timeout=15)), daemon=True)
    thread.start()

    client = TTPConnection(CLIENT_IP, 0, SERVER_IP, port, window_size=window,
                           socket=net.socket(CLIENT_IP), owns_socket=False, config=config, side_name="C")
    client.connect(timeout=15)
    thread.join(15)

    return listener, client, accepted["conn"]


def read_in_thread(conn, size, out, key, timeout=30):
    """Lê exatamente `size` bytes de `conn` em uma thread; resultado em out[key]."""
    def run():
        try:
            out[key] = conn.recv_exact(size, timeout=timeout)
        except Exception as error:  # noqa: BLE001
            out[key] = error

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def wait_until(predicate, timeout=5.0, step=0.01):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)

    return predicate()
