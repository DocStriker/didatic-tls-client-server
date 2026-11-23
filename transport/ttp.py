# =============================================================================
# transport/ttp.py
# -----------------------------------------------------------------------------
# Aplicação de demonstração sobre TTP + TTLS, agora com CONEXÃO CONTÍNUA:
#
#   * o servidor aceita vários clientes ao mesmo tempo (uma thread por cliente)
#     e atende cada um em laço até ele fechar -- antes atendia UMA mensagem
#     de UM cliente e encerrava;
#   * o cliente pode mandar N mensagens na mesma conexão (--count/--interval);
#   * cada mensagem leva um NÚMERO DE SEQUÊNCIA de aplicação; o servidor ecoa
#     o número e ambos conferem que nada se perdeu, duplicou ou trocou de
#     ordem (uma 3ª camada de verificação, além da do TTP e da do TTLS);
#   * detecção de par morto via keepalive do TTP.
#
# Mensagem de aplicação = 1 registro TTLS:   | seq (4 bytes) | texto UTF-8 |
# (por isso o texto é limitado a MAX_MESSAGE bytes: cabe em um registro, e
# fronteira de registro = fronteira de mensagem).
# =============================================================================

from __future__ import annotations

import socket
import struct
import threading
import time
from pathlib import Path

from ttls.alert import TTLSAlertError, TTLSClosed, TTLSTruncated
from ttls.identity import fingerprint, generate_identity, load_private_key, load_public_key
from ttls.record import MAX_FRAGMENT
from ttls.session import TTLSSession
from ttp.config import TTPConfig
from ttp.connection import TTPConnection
from ttp.errors import TTPError
from ttp.server import TTPServer

MAX_MESSAGE = MAX_FRAGMENT - 4
CERT_DIR = Path(__file__).resolve().parents[1] / "certs"
KEY_PATH = CERT_DIR / "ttls_identity.key"
PUB_PATH = CERT_DIR / "ttls_identity.pub"

WINDOW = 32768


def _local_ip_for(host: str) -> str:
    """Descobre qual IP local o kernel usaria para falar com `host`."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        probe.connect((host, 9))
        return probe.getsockname()[0]
    except OSError:
        return host
    finally:
        probe.close()


def _pack(seq: int, text: bytes) -> bytes:
    return struct.pack("!I", seq) + text


def _unpack(data: bytes) -> tuple[int, bytes]:
    if len(data) < 4:
        raise ValueError("mensagem de aplicação curta demais")

    return struct.unpack("!I", data[:4])[0], data[4:]


# =============================================================================
# Cliente
# =============================================================================

def client(
    host: str,
    port: int,
    message: str,
    count: int = 1,
    interval: float = 0.0,
    keepalive: float | None = None,
    trusted_key: bytes | None = None,
) -> dict:
    body = message.encode("utf-8")

    if len(body) > MAX_MESSAGE:
        raise ValueError(f"mensagem maior que {MAX_MESSAGE} bytes.")

    if trusted_key is None and PUB_PATH.exists():
        trusted_key = load_public_key(PUB_PATH)

    config = TTPConfig(keepalive_interval=keepalive)

    connection = TTPConnection(
        local_ip=_local_ip_for(host),
        local_port=0,  # porta efêmera: dois clientes na mesma máquina não colidem
        remote_ip=host,
        remote_port=port,
        window_size=WINDOW,
        side_name="Client",
        config=config,
    )

    connection.connect()
    print(f"[Client][TTP] Conectado em {host}:{port}")

    session = TTLSSession(connection, trusted_server_key=trusted_key)
    result = dict(sent=0, received=0, errors=0, rtts=[])

    try:
        session.handshake_client()
        print(f"[Client][TTLS] Cipher suite: {session.cipher_suite.name}")

        if session.server_authenticated:
            print(f"[Client][TTLS] Servidor autenticado (chave {fingerprint(session.peer_public_key)}).")
        else:
            print("[Client][TTLS] AVISO: servidor NÃO autenticado (gere as chaves com generate_certs.py).")

        print("[Client][TTLS] Handshake concluído.")

        for seq in range(1, count + 1):
            started = time.monotonic()
            session.send_application_data(_pack(seq, body))
            result["sent"] += 1

            reply_seq, reply = _unpack(session.recv_application_data(timeout=30))
            rtt = (time.monotonic() - started) * 1000
            result["rtts"].append(rtt)

            if reply_seq != seq:
                result["errors"] += 1
                print(f"[Client][SYNC] ERRO: esperava resposta #{seq}, veio #{reply_seq}")
            else:
                result["received"] += 1
                print(f"[Client][TTLS] #{seq} resposta ({rtt:.2f} ms): {reply.decode('utf-8', 'replace')}")

            if interval and seq < count:
                time.sleep(interval)

        session.close()
        connection.wait_closed(connection.cfg.close_timeout + connection.cfg.time_wait + 1)

    except (TTLSAlertError, TTLSClosed, TTLSTruncated, TTPError, TimeoutError, EOFError) as error:
        result["errors"] += 1
        print(f"[Client] Falha: {type(error).__name__}: {error}")
        connection.abort()

    info = connection.info()
    print(
        f"[Client][TTP] segmentos enviados={info['segments_sent']} "
        f"retransmissões={info['retransmissions']} (fast={info['fast_retransmissions']}) "
        f"RTT suavizado={info['srtt_ms']} ms RTO={info['rto_ms']} ms"
    )

    return result


# =============================================================================
# Servidor
# =============================================================================

def _load_identity():
    if not KEY_PATH.exists():
        generate_identity(CERT_DIR)
        print(f"[Server][TTLS] Chave de identidade gerada em {KEY_PATH}")

    key = load_private_key(KEY_PATH)
    public = key.public_key().public_bytes_raw()
    print(f"[Server][TTLS] Identidade: {fingerprint(public)}")

    return key


def handle_client(connection: TTPConnection, identity_key) -> None:
    peer = f"{connection.remote_ip}:{connection.remote_port}"
    session = TTLSSession(connection, identity_key=identity_key)

    try:
        session.handshake_server()
        print(f"[Server][TTLS] {peer} handshake concluído.")

        expected = 1

        while True:
            seq, text = _unpack(session.recv_application_data())

            if seq != expected:
                # Perda/duplicação/troca de ordem no nível da aplicação.
                print(f"[Server][SYNC] {peer}: esperava #{expected}, recebi #{seq}")

            expected = seq + 1

            print(f"[Server][TTLS] {peer} #{seq}: {text.decode('utf-8', 'replace')}")
            session.send_application_data(_pack(seq, b"eco: " + text))

    except TTLSClosed:
        print(f"[Server][TTLS] {peer} encerrou ordenadamente.")
        connection.close()

    except (TTLSAlertError, TTLSTruncated, TTPError, EOFError, TimeoutError) as error:
        print(f"[Server] {peer}: {type(error).__name__}: {error}")
        connection.abort()


def server(
    host: str,
    port: int,
    stop_event: threading.Event | None = None,
    max_clients: int | None = None,
    identity_key=None,
) -> None:
    identity_key = identity_key or _load_identity()
    listener = TTPServer(local_ip=host, local_port=port, window_size=WINDOW, side_name="Server",
                         config=TTPConfig(keepalive_interval=10.0))
    listener.start()

    print(f"[Server][TTP] Aguardando conexões em {host}:{port}")

    workers = []
    served = 0

    try:
        while not (stop_event and stop_event.is_set()) and (max_clients is None or served < max_clients):
            try:
                connection = listener.accept(timeout=0.5)
            except TimeoutError:
                continue

            served += 1
            worker = threading.Thread(target=handle_client, args=(connection, identity_key), daemon=True)
            worker.start()
            workers.append(worker)

        for worker in workers:
            worker.join()

    except KeyboardInterrupt:
        print("\n[Server] Encerrando...")
    finally:
        listener.close()
