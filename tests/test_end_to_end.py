"""TTLS sobre TTP, com a rede simulada ruim e com raw sockets reais."""

import os
import struct
import threading

import pytest

from helpers import connect_pair, fast_config
from ttls.alert import TTLSClosed
from ttls.identity import generate_identity, load_private_key, load_public_key
from ttls.session import TTLSSession
from ttp.simnet import SimNetwork


def test_conversa_continua_ttls_sobre_ttp_com_rede_ruim(tmp_path):
    """50 mensagens de tamanhos variados na MESMA conexão; respostas na ordem certa."""
    generate_identity(tmp_path)
    private, public = load_private_key(tmp_path / "ttls_identity.key"), load_public_key(tmp_path / "ttls_identity.pub")

    net = SimNetwork(seed=21, loss=0.05, duplicate=0.05, reorder=0.15, corrupt=0.02, jitter=0.002)
    try:
        _, client_conn, server_conn = connect_pair(net)
        client = TTLSSession(client_conn, trusted_server_key=public)
        server = TTLSSession(server_conn, identity_key=private)

        def serve():
            server.handshake_server()
            try:
                while True:
                    data = server.recv_application_data(timeout=30)
                    seq = struct.unpack("!I", data[:4])[0]
                    server.send_application_data(struct.pack("!I", seq) + data[4:][::-1])
            except TTLSClosed:
                server_conn.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        client.handshake_client()
        assert client.server_authenticated

        for seq in range(1, 51):
            body = os.urandom((seq * 997) % 9000 + 1)          # de 1 byte a ~9 KB (cruza vários segmentos)
            client.send_application_data(struct.pack("!I", seq) + body)
            reply = client.recv_application_data(timeout=30)
            assert struct.unpack("!I", reply[:4])[0] == seq     # sincronia: resposta #n para o pedido #n
            assert reply[4:] == body[::-1]

        client.close()
        thread.join(15)
        assert net.stats["dropped"] > 0 and client_conn.stats["retransmissions"] > 0
    finally:
        net.close()


def _raw_sockets_available():
    import socket
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, 253).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _raw_sockets_available(), reason="raw sockets exigem root/CAP_NET_RAW")
def test_loopback_real_com_raw_sockets(tmp_path):
    from transport import ttp as app

    generate_identity(tmp_path)
    private, public = load_private_key(tmp_path / "ttls_identity.key"), load_public_key(tmp_path / "ttls_identity.pub")
    port = 20000 + os.getpid() % 20000
    stop = threading.Event()

    server = threading.Thread(target=app.server, args=("127.0.0.1", port),
                              kwargs=dict(stop_event=stop, max_clients=2, identity_key=private), daemon=True)
    server.start()

    import time
    time.sleep(0.5)

    results = [app.client("127.0.0.1", port, "ola real", count=4, trusted_key=public) for _ in range(2)]
    stop.set()
    server.join(10)

    for result in results:
        assert result["received"] == 4 and result["errors"] == 0
