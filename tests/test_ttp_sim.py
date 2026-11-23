"""
Testes do TTP sobre a rede simulada: cada teste reproduz um defeito de rede
que o código antigo não tratava (ver docs/MELHORIAS.md).
"""

import os
import threading
import time

import pytest

from helpers import CLIENT_IP, SERVER_IP, connect_pair, fast_config, read_in_thread, wait_until
from ttp.connection import TTPConnection
from ttp.errors import TTPRefused, TTPTimeout
from ttp.packet import TTPFlags, TTPState
from ttp.server import TTPServer
from ttp.simnet import SimNetwork


@pytest.fixture
def make_net():
    nets = []

    def factory(**kwargs):
        net = SimNetwork(**kwargs)
        nets.append(net)
        return net

    yield factory

    for net in nets:
        net.close()


def transfer(client, server, payload, timeout=30):
    out = {}
    reader = read_in_thread(server, len(payload), out, "data", timeout)
    client.send(payload)
    reader.join(timeout)
    return out.get("data")


# ----------------------------------------------------------------------------
# Transferência com defeitos de rede
# ----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "conditions",
    [
        dict(),
        dict(loss=0.10),
        dict(duplicate=0.25),
        dict(reorder=0.40, jitter=0.004),
        dict(corrupt=0.10),
        dict(loss=0.05, duplicate=0.10, reorder=0.20, corrupt=0.03, jitter=0.003),
    ],
    ids=["limpa", "perda10%", "duplicacao", "reordenacao", "corrupcao", "tudo-junto"],
)
def test_transferencia_integra_nos_dois_sentidos(make_net, conditions):
    net = make_net(seed=7, **conditions)
    _, client, server = connect_pair(net)

    up, down = os.urandom(150_000), os.urandom(150_000)
    out = {}
    r1 = read_in_thread(server, len(up), out, "up")
    r2 = read_in_thread(client, len(down), out, "down")

    sender = threading.Thread(target=lambda: server.send(down), daemon=True)
    sender.start()
    client.send(up)

    r1.join(30); r2.join(30); sender.join(30)

    assert out["up"] == up
    assert out["down"] == down


def test_pacote_corrompido_nao_mata_a_conexao(make_net):
    """Antes: 1 checksum inválido levantava ValueError e matava a thread receptora."""
    net = make_net(seed=1, corrupt=0.30)
    _, client, server = connect_pair(net)

    payload = os.urandom(40_000)
    assert transfer(client, server, payload) == payload
    assert net.stats["corrupted"] > 10
    assert client.receiver.is_alive() and server.receiver.is_alive()


def test_perda_do_unico_pacote_em_voo_e_retransmitida_por_timeout(make_net):
    """Antes: o timer só era checado quando OUTRO pacote chegava -> nunca retransmitia."""
    dropped = []

    def drop_first_data(src, dst, packet):
        if packet.flags & TTPFlags.DATA and not dropped:
            dropped.append(packet.sequence_number)
            return True
        return False

    net = make_net(drop_filter=drop_first_data)
    _, client, server = connect_pair(net)

    assert transfer(client, server, b"mensagem unica") == b"mensagem unica"
    assert dropped and client.stats["timeouts"] >= 1 and client.stats["retransmissions"] >= 1


def test_fast_retransmit_apos_tres_acks_repetidos(make_net):
    state = {"count": 0}

    def drop_third_data(src, dst, packet):
        if src == CLIENT_IP and packet.flags & TTPFlags.DATA:
            state["count"] += 1
            return state["count"] == 3   # só a 1ª transmissão do 3º segmento
        return False

    net = make_net(drop_filter=drop_third_data, delay=0.003)
    config = fast_config(rto_min=0.5, rto_initial=0.5, rto_max=2)   # RTO grande: só o fast retransmit resolve rápido
    _, client, server = connect_pair(net, config=config)

    payload = os.urandom(1400 * 12)
    started = time.monotonic()
    assert transfer(client, server, payload) == payload
    assert client.stats["fast_retransmissions"] >= 1
    assert client.stats["timeouts"] == 0
    assert time.monotonic() - started < 0.4   # bem antes do RTO de 500 ms


def test_mensagem_maior_que_a_janela_nao_trava(make_net):
    """Antes: com janela 4096, um pacote de 10000 bytes ficava na fila para sempre."""
    net = make_net()
    _, client, server = connect_pair(net, window=4096)

    payload = os.urandom(100_000)
    assert transfer(client, server, payload) == payload


def test_controle_de_fluxo_com_leitor_lento(make_net):
    net = make_net(delay=0.001)
    _, client, server = connect_pair(net, window=4096)

    payload = os.urandom(60_000)
    client.send(payload)

    # Aplicação do servidor não lê: o buffer enche, a janela anunciada vai a zero
    assert wait_until(lambda: client.info()["peer_window"] == 0, 5)
    assert len(server.receive_buffer) <= 4096                    # nunca ultrapassa a capacidade
    assert client.info()["send_buffer"] > 0 or client.info()["in_flight"] >= 0

    # Agora lê devagar, em pedaços: a janela reabre e tudo chega íntegro
    received = bytearray()
    while len(received) < len(payload):
        received += server.recv(1000, timeout=10)
        time.sleep(0.001)
    assert bytes(received) == payload


def test_janela_zero_perdida_e_recuperada_por_sonda(make_net):
    """O ACK de 'janela reaberta' se perde: o persist timer sonda e destrava."""
    state = {"drop_updates": True}

    def drop_window_updates(src, dst, packet):
        return (state["drop_updates"] and src == SERVER_IP and packet.is_pure_ack and packet.window > 0
                and packet.window < 4096)

    net = make_net(drop_filter=drop_window_updates)
    _, client, server = connect_pair(net, window=4096)

    payload = os.urandom(20_000)
    client.send(payload)
    assert wait_until(lambda: client.info()["peer_window"] == 0, 5)

    out = {}
    reader = read_in_thread(server, len(payload), out, "data")
    reader.join(30)
    assert out["data"] == payload


# ----------------------------------------------------------------------------
# Handshake
# ----------------------------------------------------------------------------

def test_handshake_com_syn_e_synack_perdidos(make_net):
    seen = {"syn": 0, "synack": 0}

    def drop_first_of_each(src, dst, packet):
        if packet.flags == TTPFlags.SYN and seen["syn"] == 0:
            seen["syn"] += 1
            return True
        if packet.flags == (TTPFlags.SYN | TTPFlags.ACK) and seen["synack"] == 0:
            seen["synack"] += 1
            return True
        return False

    net = make_net(drop_filter=drop_first_of_each)
    _, client, server = connect_pair(net)
    assert client.state == TTPState.ESTABLISHED and server.state == TTPState.ESTABLISHED
    assert transfer(client, server, b"ok") == b"ok"


def test_dados_funcionam_mesmo_se_o_ack_final_do_handshake_se_perder(make_net):
    """Antes: o servidor, preso em SYN_RECEIVED, ignorava DATA (que não tinha ACK)."""
    state = {"dropped": False}

    def drop_final_ack(src, dst, packet):
        if src == CLIENT_IP and packet.flags == TTPFlags.ACK and not state["dropped"]:
            state["dropped"] = True
            return True
        return False

    net = make_net(drop_filter=drop_final_ack)
    _, client, server = connect_pair(net)
    assert transfer(client, server, b"dados logo apos o handshake") == b"dados logo apos o handshake"
    assert server.state == TTPState.ESTABLISHED


def test_conexao_recusada_falha_rapido(make_net):
    """Servidor que parou de aceitar (mas ainda tem uma conexão viva) responde RST ao SYN novo."""
    net = make_net()
    listener, client, server = connect_pair(net)
    listener.close()                      # para de aceitar; a conexão existente continua

    late = TTPConnection("10.0.0.3", 0, SERVER_IP, 9000, socket=net.socket("10.0.0.3"),
                         owns_socket=False, config=fast_config())
    started = time.monotonic()
    with pytest.raises(TTPRefused):
        late.connect(timeout=5)
    assert time.monotonic() - started < 1.0

    # e a conexão que já existia segue funcionando
    assert transfer(client, server, b"ainda viva") == b"ainda viva"


def test_connect_sem_ninguem_escutando_da_timeout(make_net):
    net = make_net()
    net.partitioned = True
    client = TTPConnection(CLIENT_IP, 0, SERVER_IP, 9000, socket=net.socket(CLIENT_IP),
                           owns_socket=False, config=fast_config(syn_retries=3))
    with pytest.raises(TTPTimeout):
        client.connect(timeout=10)


def test_numeros_de_sequencia_dao_a_volta_em_2_32(make_net, monkeypatch):
    """Antes: ISN alto + alguns bytes estourava struct.pack('!I')."""
    monkeypatch.setattr("ttp.sequence.secrets.randbits", lambda bits: 0xFFFFFFF0)
    net = make_net(seed=3, loss=0.05, reorder=0.2)
    _, client, server = connect_pair(net)
    assert client.sequence.initial_sequence == 0xFFFFFFF0

    payload = os.urandom(30_000)   # atravessa o 2**32
    assert transfer(client, server, payload) == payload
    assert client.sequence.send_next < 0xFFFFFFF0   # deu a volta


# ----------------------------------------------------------------------------
# Fechamento
# ----------------------------------------------------------------------------

def test_close_entrega_tudo_que_estava_no_buffer_e_o_par_recebe_eof(make_net):
    net = make_net(seed=5, loss=0.05)
    _, client, server = connect_pair(net)

    payload = os.urandom(200_000)
    got = bytearray()

    def reader():
        while True:
            chunk = server.recv()
            if not chunk:
                break
            got.extend(chunk)
        server.close()

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()

    client.send(payload)
    assert client.close() is True        # close() logo após send(): nada se perde
    thread.join(30)

    assert bytes(got) == payload
    assert wait_until(lambda: client.state == TTPState.CLOSED and server.state == TTPState.CLOSED, 5)


def test_meio_fechamento_o_outro_lado_ainda_responde(make_net):
    net = make_net()
    _, client, server = connect_pair(net)

    client.send(b"pergunta")
    client.shutdown_write()

    assert server.recv_exact(8, timeout=5) == b"pergunta"
    assert server.recv(timeout=5) == b""           # EOF: sabe que o cliente terminou
    assert server.state == TTPState.CLOSE_WAIT
    server.send(b"resposta")                       # ainda pode enviar
    assert client.recv_exact(8, timeout=5) == b"resposta"
    server.close(); client.close()


def test_fechamento_com_o_ack_final_perdido(make_net):
    """O ACK do último FIN se perde: o FIN é retransmitido e o TIME_WAIT re-ACKa."""
    state = {"dropped": 0}

    def drop_one_final_ack(src, dst, packet):
        if src == CLIENT_IP and packet.is_pure_ack and client_ref and client_ref[0].state == TTPState.TIME_WAIT \
                and state["dropped"] == 0:
            state["dropped"] += 1
            return True
        return False

    client_ref = []
    net = make_net(drop_filter=drop_one_final_ack)
    _, client, server = connect_pair(net)
    client_ref.append(client)

    client.close_thread = threading.Thread(target=client.close, daemon=True)
    client.close_thread.start()
    assert server.recv(timeout=5) == b""
    server.close()
    client.close_thread.join(10)

    assert wait_until(lambda: server.state == TTPState.CLOSED, 5)
    assert wait_until(lambda: client.state == TTPState.CLOSED, 5)


def test_abort_envia_rst_e_o_par_recebe_erro(make_net):
    net = make_net()
    _, client, server = connect_pair(net)
    client.abort()
    with pytest.raises(ConnectionResetError):
        server.recv(timeout=5)
    assert wait_until(lambda: server.state == TTPState.CLOSED, 3)


# ----------------------------------------------------------------------------
# Conexão contínua: par morto
# ----------------------------------------------------------------------------

def test_keepalive_detecta_par_morto_em_conexao_ociosa(make_net):
    net = make_net()
    config = fast_config(keepalive_interval=0.15, keepalive_probes=3, keepalive_probe_interval=0.05)
    _, client, server = connect_pair(net, config=config)

    time.sleep(0.5)                       # ociosa mas viva: sondas são respondidas
    assert client.state == TTPState.ESTABLISHED

    net.partitioned = True                # o enlace cai
    started = time.monotonic()
    with pytest.raises(TTPTimeout):
        client.recv(timeout=10)           # quem estava bloqueado em recv() é acordado com erro
    assert time.monotonic() - started < 2.0


def test_retransmissoes_esgotadas_abortam_e_acordam_quem_espera(make_net):
    net = make_net()
    _, client, server = connect_pair(net, config=fast_config(max_retries=4))
    net.partitioned = True
    client.send(b"ninguem vai receber")
    with pytest.raises(TTPTimeout):
        client.recv(timeout=10)
    assert client.state == TTPState.CLOSED
    with pytest.raises(ConnectionError):
        client.send(b"x")


def test_send_acorda_com_erro_quando_o_buffer_esta_cheio_e_a_rede_cai(make_net):
    net = make_net()
    config = fast_config(max_retries=3, send_buffer=10_000)
    _, client, server = connect_pair(net, window=4096, config=config)
    net.partitioned = True
    with pytest.raises(TTPTimeout):
        client.send(os.urandom(500_000))   # bloqueia por backpressure e depois falha, não trava


# ----------------------------------------------------------------------------
# Servidor com vários clientes
# ----------------------------------------------------------------------------

def test_servidor_atende_varios_clientes_simultaneos(make_net):
    net = make_net(seed=11, loss=0.03, reorder=0.1)
    config = fast_config()
    listener = TTPServer(SERVER_IP, 9000, socket=net.socket(SERVER_IP), config=config, side_name="S")
    listener.start()

    results = {}

    def echo_server():
        workers = []
        for _ in range(3):
            conn = listener.accept(timeout=15)

            def serve(c=conn):
                data = c.recv_exact(20_000, timeout=30)
                c.send(data[::-1])
                c.close()

            t = threading.Thread(target=serve, daemon=True); t.start(); workers.append(t)
        for t in workers:
            t.join(30)

    threading.Thread(target=echo_server, daemon=True).start()

    def run_client(index):
        ip = f"10.0.1.{index}"
        client = TTPConnection(ip, 0, SERVER_IP, 9000, socket=net.socket(ip), owns_socket=False,
                               config=config, side_name=f"C{index}")
        client.connect(timeout=15)
        data = os.urandom(20_000)
        client.send(data)
        results[index] = (data, client.recv_exact(20_000, timeout=30))
        client.close()

    threads = [threading.Thread(target=run_client, args=(i,), daemon=True) for i in range(1, 4)]
    for t in threads: t.start()
    for t in threads: t.join(40)

    assert len(results) == 3
    for data, reply in results.values():
        assert reply == data[::-1]     # cada cliente recebe SÓ a resposta dele
