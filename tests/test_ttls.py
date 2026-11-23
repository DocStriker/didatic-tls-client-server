"""Testes do TTLS sobre um transporte em memória que permite ATACAR o canal."""

import os
import queue
import threading

import pytest

from ttls.alert import AlertDescription, TTLSAlertError, TTLSClosed, TTLSTruncated
from ttls.identity import generate_identity, load_private_key, load_public_key
from ttls.record import MAX_FRAGMENT, MAX_RECORD_PAYLOAD, TTLSRecord, RecordType
from ttls.session import TTLSSession, TTLSState


class Pipe:
    """Uma ponta de um canal em memória. `tamper(data) -> [bytes]` pode alterar/descartar/duplicar o que ela envia."""

    def __init__(self):
        self.inbox = queue.Queue()
        self.peer = None
        self.tamper = None
        self.closed = False
        self.sent = []

    def send(self, data):
        self.sent.append(data)
        for chunk in (self.tamper(data) if self.tamper else [data]):
            self.peer.inbox.put(chunk)

    def recv(self, max_bytes, timeout=None):
        try:
            data = self._leftover
        except AttributeError:
            data = b""
        if not data:
            try:
                data = self.inbox.get(timeout=timeout)
            except queue.Empty:
                raise TimeoutError("timeout")
        if data is None:
            return b""
        self._leftover = data[max_bytes:]
        return data[:max_bytes]

    def close(self):
        if not self.closed:
            self.closed = True
            self.peer.inbox.put(None)   # EOF para o outro lado


def pipes():
    a, b = Pipe(), Pipe()
    a.peer, b.peer = b, a
    return a, b


@pytest.fixture
def keys(tmp_path):
    generate_identity(tmp_path)
    return load_private_key(tmp_path / "ttls_identity.key"), load_public_key(tmp_path / "ttls_identity.pub")


def run_handshake(client, server):
    errors = {}

    def run(name, fn):
        try:
            fn()
        except Exception as error:  # noqa: BLE001
            errors[name] = error

    t = threading.Thread(target=run, args=("server", server.handshake_server), daemon=True)
    t.start()
    run("client", client.handshake_client)
    t.join(10)
    return errors


def established(keys, tamper_c2s=None, tamper_s2c=None):
    private, public = keys
    c, s = pipes()
    c.tamper, s.tamper = tamper_c2s, tamper_s2c
    client = TTLSSession(c, trusted_server_key=public)
    server = TTLSSession(s, identity_key=private)
    assert run_handshake(client, server) == {}
    return client, server, c, s


# ---------------------------------------------------------------------------

def test_handshake_e_troca_de_dados(keys):
    client, server, _, _ = established(keys)
    assert client.state == server.state == TTLSState.ESTABLISHED
    assert client.server_authenticated
    client.send_application_data(b"ola servidor")
    assert server.recv_application_data(timeout=2) == b"ola servidor"
    server.send_application_data(b"ola cliente")
    assert client.recv_application_data(timeout=2) == b"ola cliente"


def test_dado_cifrado_nao_aparece_na_rede_e_sessoes_tem_chaves_diferentes(keys):
    secret = b"SEGREDO-QUE-NAO-PODE-VAZAR"
    wires = []
    for _ in range(2):
        client, server, c, _ = established(keys)
        client.send_application_data(secret)
        wires.append(c.sent[-1])
        assert secret not in wires[-1]
    assert wires[0] != wires[1]       # antes: mesma chave fixa em toda sessão


def test_mensagem_maior_que_um_registro_e_remontada(keys):
    client, server, _, _ = established(keys)
    data = os.urandom(MAX_FRAGMENT * 3 + 123)
    client.send_application_data(data)
    got = b""
    while len(got) < len(data):
        got += server.recv_application_data(timeout=2)
    assert got == data


def test_registros_coalescidos_ou_fatiados_pelo_transporte(keys):
    """O transporte entrega bytes em pedaços arbitrários (fluxo): o enquadramento tem que aguentar."""
    private, public = keys
    c, s = pipes()

    def slice_into_3_byte_chunks(data):
        return [data[i:i + 3] for i in range(0, len(data), 3)]

    c.tamper = s.tamper = slice_into_3_byte_chunks
    client, server = TTLSSession(c, trusted_server_key=public), TTLSSession(s, identity_key=private)
    assert run_handshake(client, server) == {}
    client.send_application_data(b"fatiado")
    assert server.recv_application_data(timeout=2) == b"fatiado"


def test_timeout_no_meio_do_registro_nao_perde_o_enquadramento(keys):
    client, server, c, s = established(keys)
    client.send_application_data(b"mensagem inteira")
    wire = c.sent[-1]
    # Entrega só metade, deixa estourar o timeout, depois entrega o resto.
    s.inbox.queue.clear()
    s.inbox.put(wire[:8])
    with pytest.raises(TimeoutError):
        server.recv_application_data(timeout=0.1)
    s.inbox.put(wire[8:])
    assert server.recv_application_data(timeout=2) == b"mensagem inteira"


# --- ataques ---------------------------------------------------------------

def test_adulteracao_de_um_bit_e_detectada(keys):
    def flip(data):
        broken = bytearray(data)
        broken[-1] ^= 1
        return [bytes(broken)]

    client, server, c, _ = established(keys)
    c.tamper = flip
    client.send_application_data(b"transferir R$10")
    with pytest.raises(TTLSAlertError) as error:
        server.recv_application_data(timeout=2)
    assert error.value.description == AlertDescription.BAD_RECORD_MAC


def test_adulteracao_do_cabecalho_tambem_e_detectada(keys):
    """O cabeçalho é AAD: trocar o tipo do registro invalida a tag."""
    def change_type(data):
        broken = bytearray(data)
        broken[0] = RecordType.HEARTBEAT
        return [bytes(broken)]

    client, server, c, _ = established(keys)
    c.tamper = change_type
    client.send_application_data(b"x")
    with pytest.raises(TTLSAlertError):
        server.recv_application_data(timeout=2)


def test_replay_de_registro_e_detectado(keys):
    """Antes (nonce aleatório): o registro repetido era decifrado de novo sem reclamar."""
    client, server, c, _ = established(keys)
    c.tamper = lambda data: [data, data]        # a rede entrega o mesmo registro duas vezes
    client.send_application_data(b"pague 100")
    assert server.recv_application_data(timeout=2) == b"pague 100"
    with pytest.raises(TTLSAlertError) as error:
        server.recv_application_data(timeout=2)
    assert error.value.description == AlertDescription.BAD_RECORD_MAC


def test_reordenacao_de_registros_e_detectada(keys):
    client, server, c, _ = established(keys)
    held = []

    def swap(data):
        if not held:
            held.append(data)
            return []
        return [data, held.pop()]

    c.tamper = swap
    client.send_application_data(b"primeiro")
    client.send_application_data(b"segundo")
    with pytest.raises(TTLSAlertError):
        server.recv_application_data(timeout=2)


def test_registro_removido_no_meio_e_detectado(keys):
    client, server, c, _ = established(keys)
    count = {"n": 0}

    def drop_second(data):
        count["n"] += 1
        return [] if count["n"] == 2 else [data]

    c.tamper = drop_second
    for text in (b"um", b"dois", b"tres"):
        client.send_application_data(text)
    assert server.recv_application_data(timeout=2) == b"um"
    with pytest.raises(TTLSAlertError):       # "tres" chega como se fosse o #2
        server.recv_application_data(timeout=2)


def test_reflexao_de_registro_do_cliente_de_volta_ao_cliente_e_detectada(keys):
    client, server, c, s = established(keys)
    client.send_application_data(b"eco?")
    s.inbox.get(timeout=1)                    # o atacante captura o registro...
    c.inbox.put(c.sent[-1])                   # ...e o devolve ao próprio cliente
    with pytest.raises(TTLSAlertError):
        client.recv_application_data(timeout=2)


def test_mitm_com_chave_diferente_e_rejeitado_pelo_cliente(keys, tmp_path):
    _, pinned_public = keys
    impostor_dir = tmp_path / "impostor"
    generate_identity(impostor_dir)
    impostor = load_private_key(impostor_dir / "ttls_identity.key")

    c, s = pipes()
    client = TTLSSession(c, trusted_server_key=pinned_public)
    server = TTLSSession(s, identity_key=impostor)
    errors = run_handshake(client, server)
    assert isinstance(errors["client"], TTLSAlertError)
    assert "MITM" in str(errors["client"])


def test_servidor_anonimo_e_recusado_quando_ha_chave_fixada(keys):
    _, public = keys
    c, s = pipes()
    errors = run_handshake(TTLSSession(c, trusted_server_key=public), TTLSSession(s))
    assert isinstance(errors["client"], TTLSAlertError)


def test_servidor_anonimo_funciona_sem_pinning_mas_nao_conta_como_autenticado():
    c, s = pipes()
    client, server = TTLSSession(c), TTLSSession(s)
    assert run_handshake(client, server) == {}
    assert not client.server_authenticated


def test_finished_adulterado_derruba_o_handshake(keys):
    private, public = keys
    c, s = pipes()

    def corrupt_finished(data):
        if len(data) > 6 and data[0] == RecordType.HANDSHAKE and data[6] == 0x03:   # tipo FINISHED
            broken = bytearray(data); broken[-1] ^= 1; return [bytes(broken)]
        return [data]

    c.tamper = corrupt_finished
    errors = run_handshake(TTLSSession(c, trusted_server_key=public), TTLSSession(s, identity_key=private))
    assert "server" in errors


def test_registro_com_length_gigante_e_recusado_sem_alocar(keys):
    client, server, c, s = established(keys)
    s.inbox.put(TTLSRecord.build_header(RecordType.APPLICATION_DATA, TTLSRecord.VERSION, 4_000_000_000))
    with pytest.raises(TTLSAlertError) as error:
        server.recv_application_data(timeout=2)
    assert error.value.description == AlertDescription.RECORD_OVERFLOW


def test_versao_antiga_e_recusada(keys):
    client, server, c, s = established(keys)
    s.inbox.put(TTLSRecord.build_header(RecordType.APPLICATION_DATA, 1, 10) + b"0" * 10)
    with pytest.raises(TTLSAlertError) as error:
        server.recv_application_data(timeout=2)
    assert error.value.description == AlertDescription.PROTOCOL_VERSION


# --- ciclo de vida ----------------------------------------------------------

def test_nao_envia_dados_antes_do_handshake():
    c, _ = pipes()
    with pytest.raises(Exception):
        TTLSSession(c).send_application_data(b"cedo demais")


def test_close_notify_e_distinguido_de_truncamento(keys):
    client, server, c, s = established(keys)
    client.close()
    with pytest.raises(TTLSClosed):
        server.recv_application_data(timeout=2)

    client, server, c, s = established(keys)
    c.close()                                  # transporte cai SEM close_notify (ex.: FIN injetado)
    with pytest.raises(TTLSTruncated):
        server.recv_application_data(timeout=2)


def test_heartbeat_mede_rtt_com_outra_thread_lendo(keys):
    client, server, _, _ = established(keys)

    def serve():
        try:
            while True:
                server.recv_application_data(timeout=5)
        except Exception:
            pass

    threading.Thread(target=serve, daemon=True).start()
    reader = threading.Thread(target=lambda: _drain(client), daemon=True)
    reader.start()
    rtt = client.ping(timeout=3)
    assert 0 <= rtt < 1


def _drain(session):
    try:
        while True:
            session.recv_application_data(timeout=5)
    except Exception:
        pass
