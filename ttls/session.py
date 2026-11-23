# =============================================================================
# ttls/session.py
# -----------------------------------------------------------------------------
# TTLSSession: o "cliente/servidor TLS-like" propriamente dito, em cima de
# qualquer transporte de FLUXO confiável (TTPConnection, ou um socket TCP via
# ttls.transport.SocketTransport).
#
# Contrato do transporte:
#     send(data: bytes)
#     recv(max_bytes: int, timeout: float | None) -> bytes     (b"" = EOF)
#     close()
#
# PROBLEMAS DA VERSÃO ANTERIOR RESOLVIDOS AQUI
#   1. Segredo FIXO no código (sha256(b"TTLS TEST SECRET")): qualquer um
#      derivava a chave, e toda sessão usava a MESMA. Agora: ECDHE X25519
#      efêmero (sigilo futuro) + HKDF amarrado ao transcript.
#   2. `Finished` era sha256(transcript), sem chave: qualquer atacante
#      calcula. Agora é HMAC com chave derivada do segredo, um por sentido
#      (e o transcript do servidor inclui o Finished do cliente).
#   3. Sem autenticação do servidor -> MITM trivial. Agora: assinatura
#      Ed25519 do transcript + pinning da chave pública no cliente.
#   4. Assumia "1 segmento = 1 registro" -> quebrava com registro > MSS.
#      Agora lê do fluxo com buffer próprio (um timeout no meio de um registro
#      não corrompe o enquadramento).
#   5. Replay/reordenação/remoção de registros passavam batido -> agora o
#      nonce da cifra é o número de sequência (ver ttls/cipher.py).
#   6. `state` era atributo solto, nunca verificado: dava para enviar dados
#      antes do handshake. Agora a máquina de estados é imposta.
#   7. Sem encerramento ordenado -> agora close_notify + detecção de
#      truncamento.
#   8. Conexão contínua: HEARTBEAT (ping/pong com RTT) e send/recv
#      thread-safe (um thread lê, outro escreve).
# =============================================================================

from __future__ import annotations

import hmac
import hashlib
import os
import threading
import time
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from ttls.alert import (
    Alert,
    AlertDescription,
    AlertLevel,
    TTLSAlertError,
    TTLSClosed,
    TTLSError,
    TTLSTruncated,
)
from ttls.cipher import TTLSCipher, derive_traffic_keys
from ttls.handshake import (
    CipherSuite,
    ClientHello,
    Finished,
    HandshakeMessage,
    HandshakeType,
    ServerAuth,
    ServerHello,
    select_cipher_suite,
)
from ttls.record import MAX_FRAGMENT, TTLSRecord, RecordType
from ttls.transcript import HandshakeTranscript

AUTH_CONTEXT = b"TTLS v2 server auth\x00"
_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)

_HB_REQUEST = 1
_HB_RESPONSE = 2


class TTLSState(Enum):
    NEW = 0

    CLIENT_HELLO_SENT = 1
    SERVER_HELLO_RECEIVED = 2

    SERVER_WAIT_CLIENT_HELLO = 3
    SERVER_HELLO_SENT = 4
    SERVER_WAIT_FINISHED = 5

    ESTABLISHED = 6
    CLOSED = 7


def _finished_mac(key: bytes, transcript_hash: bytes) -> bytes:
    return hmac.new(key, b"TTLS v2 finished" + transcript_hash, hashlib.sha256).digest()


class TTLSSession:
    def __init__(
        self,
        transport,
        identity_key: Ed25519PrivateKey | None = None,
        trusted_server_key: bytes | None = None,
        handshake_timeout: float = 10.0,
    ):
        self.transport = transport
        self.identity_key = identity_key              # servidor: prova quem é
        self.trusted_server_key = trusted_server_key  # cliente: chave pública esperada
        self.handshake_timeout = handshake_timeout

        self.state = TTLSState.NEW
        self.transcript = HandshakeTranscript()
        self.cipher_suite: CipherSuite | None = None
        self.server_authenticated = False
        self.peer_public_key: bytes | None = None

        self._cipher_out: TTLSCipher | None = None
        self._cipher_in: TTLSCipher | None = None

        self._rx = bytearray()           # bytes lidos do transporte e ainda não consumidos
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()
        self._pings: dict[bytes, list] = {}

        self.records_sent = 0
        self.records_received = 0

    # =========================================================================
    # Enquadramento: leitura de registros em cima de um FLUXO
    # =========================================================================

    def _fill(self, size: int, timeout: float | None) -> None:
        """Garante `size` bytes no buffer. Um timeout deixa o buffer INTACTO."""
        deadline = None if timeout is None else time.monotonic() + timeout

        while len(self._rx) < size:
            left = None if deadline is None else max(0.0, deadline - time.monotonic())
            chunk = self.transport.recv(size - len(self._rx), left)

            if not chunk:
                raise EOFError

            self._rx += chunk

    def _read_record(self, timeout: float | None) -> TTLSRecord:
        header_size = TTLSRecord.HEADER_SIZE

        try:
            self._fill(header_size, timeout)

            try:
                _, _, length = TTLSRecord.parse_header(bytes(self._rx[:header_size]))
            except OverflowError as error:
                raise self._fatal(AlertDescription.RECORD_OVERFLOW, str(error))
            except ValueError as error:
                raise self._fatal(AlertDescription.PROTOCOL_VERSION, str(error))

            self._fill(header_size + length, timeout)

        except EOFError:
            self.state = TTLSState.CLOSED
            raise TTLSTruncated(
                "Transporte encerrado sem close_notify: a conversa pode ter sido truncada."
            ) from None

        raw = bytes(self._rx[: header_size + length])
        del self._rx[: header_size + length]

        record = TTLSRecord.unpack(raw)
        record.raw_header = raw[:header_size]
        self.records_received += 1

        return record

    # =========================================================================
    # Envio de registros
    # =========================================================================

    def _send_record(self, record_type: RecordType, payload: bytes, encrypt: bool) -> None:
        with self._send_lock:
            if encrypt:
                header = TTLSRecord.build_header(
                    record_type, TTLSRecord.VERSION, len(payload) + TTLSCipher.TAG_SIZE
                )
                # O cabeçalho vai como AAD: adulterar tipo/tamanho invalida a tag.
                data = header + self._cipher_out.encrypt(payload, associated_data=header)
            else:
                data = TTLSRecord(record_type, payload).pack()

            self.transport.send(data)
            self.records_sent += 1

    def _send_handshake(self, message_type: HandshakeType, payload: bytes) -> None:
        message = HandshakeMessage(message_type, payload).pack()
        self.transcript.add(message)
        self._send_record(RecordType.HANDSHAKE, message, encrypt=False)

    def _recv_handshake(self, expected: HandshakeType) -> HandshakeMessage:
        record = self._read_record(self.handshake_timeout)

        if record.record_type == RecordType.ALERT:
            alert = Alert.unpack(record.payload)
            self.state = TTLSState.CLOSED
            raise TTLSAlertError(alert.description, f"alerta do par durante o handshake: {alert.description.name}")

        if record.record_type != RecordType.HANDSHAKE:
            raise self._fatal(AlertDescription.UNEXPECTED_MESSAGE, "esperado um registro HANDSHAKE")

        try:
            message = HandshakeMessage.unpack(record.payload)
        except ValueError as error:
            raise self._fatal(AlertDescription.DECODE_ERROR, str(error))

        if message.message_type != expected:
            raise self._fatal(
                AlertDescription.UNEXPECTED_MESSAGE,
                f"esperado {expected.name}, recebido {message.message_type.name}",
            )

        return message

    def _fatal(self, description: AlertDescription, message: str) -> TTLSAlertError:
        """Envia um alerta fatal (melhor esforço), derruba o transporte e devolve a exceção."""
        encrypted = self.state == TTLSState.ESTABLISHED

        try:
            payload = Alert(AlertLevel.FATAL, description).pack()
            self._send_record(RecordType.ALERT, payload, encrypt=encrypted)
        except Exception:
            pass

        self.state = TTLSState.CLOSED

        try:
            self.transport.close()
        except Exception:
            pass

        return TTLSAlertError(description, message)

    def _install_ciphers(self, keys, is_client: bool) -> None:
        if is_client:
            self._cipher_out = TTLSCipher(keys.client_write_key, keys.client_write_iv)
            self._cipher_in = TTLSCipher(keys.server_write_key, keys.server_write_iv)
        else:
            self._cipher_out = TTLSCipher(keys.server_write_key, keys.server_write_iv)
            self._cipher_in = TTLSCipher(keys.client_write_key, keys.client_write_iv)

    # =========================================================================
    # Handshake
    # =========================================================================

    def handshake_client(self) -> None:
        if self.state != TTLSState.NEW:
            raise TTLSError("handshake já iniciado.")

        offered = [CipherSuite.TTLS_AES_256_GCM]
        private = X25519PrivateKey.generate()

        # 1) ClientHello
        hello = ClientHello(os.urandom(32), offered, private.public_key().public_bytes(*_RAW))
        self._send_handshake(HandshakeType.CLIENT_HELLO, hello.pack())
        self.state = TTLSState.CLIENT_HELLO_SENT

        # 2) ServerHello -> já dá para derivar as chaves
        message = self._recv_handshake(HandshakeType.SERVER_HELLO)
        self.transcript.add(message.pack())

        try:
            server_hello = ServerHello.unpack(message.payload)
        except ValueError as error:
            raise self._fatal(AlertDescription.DECODE_ERROR, str(error))

        if server_hello.cipher_suite not in offered:
            raise self._fatal(AlertDescription.ILLEGAL_PARAMETER, "o servidor escolheu uma suite que não oferecemos")

        self.cipher_suite = server_hello.cipher_suite
        keys = self._key_agreement(private, server_hello.key_share)
        self.state = TTLSState.SERVER_HELLO_RECEIVED

        # 3) ServerAuth: confere QUEM é o servidor
        hello_hash = self._hello_hash_for_auth
        message = self._recv_handshake(HandshakeType.SERVER_AUTH)

        try:
            auth = ServerAuth.unpack(message.payload)
        except ValueError as error:
            raise self._fatal(AlertDescription.DECODE_ERROR, str(error))

        self._verify_server_auth(auth, hello_hash)
        self.transcript.add(message.pack())

        # 4) Finished do cliente (prova que temos a mesma chave e o mesmo transcript)
        self._send_handshake(
            HandshakeType.FINISHED,
            Finished(_finished_mac(keys.client_finished_key, self.transcript.digest())).pack(),
        )

        # 5) Finished do servidor
        expected = _finished_mac(keys.server_finished_key, self.transcript.digest())
        message = self._recv_handshake(HandshakeType.FINISHED)

        try:
            received = Finished.unpack(message.payload).verify_data
        except ValueError as error:
            raise self._fatal(AlertDescription.DECODE_ERROR, str(error))

        if not hmac.compare_digest(received, expected):
            raise self._fatal(AlertDescription.DECRYPT_ERROR, "Finished do servidor inválido")

        self.transcript.add(message.pack())
        self._install_ciphers(keys, is_client=True)
        self.state = TTLSState.ESTABLISHED

    def handshake_server(self) -> None:
        if self.state != TTLSState.NEW:
            raise TTLSError("handshake já iniciado.")

        self.state = TTLSState.SERVER_WAIT_CLIENT_HELLO

        # 1) ClientHello
        message = self._recv_handshake(HandshakeType.CLIENT_HELLO)
        self.transcript.add(message.pack())

        try:
            client_hello = ClientHello.unpack(message.payload)
            self.cipher_suite = select_cipher_suite(client_hello.cipher_suites)
        except ValueError as error:
            raise self._fatal(AlertDescription.HANDSHAKE_FAILURE, str(error))

        # 2) ServerHello + chaves
        private = X25519PrivateKey.generate()
        hello = ServerHello(os.urandom(32), self.cipher_suite, private.public_key().public_bytes(*_RAW))
        self._send_handshake(HandshakeType.SERVER_HELLO, hello.pack())

        keys = self._key_agreement(private, client_hello.key_share)
        self.state = TTLSState.SERVER_HELLO_SENT

        # 3) ServerAuth: assina o hash dos Hellos
        if self.identity_key is not None:
            signature = self.identity_key.sign(AUTH_CONTEXT + self._hello_hash_for_auth)
            auth = ServerAuth(self.identity_key.public_key().public_bytes(*_RAW), signature)
        else:
            auth = ServerAuth()  # anônimo

        self._send_handshake(HandshakeType.SERVER_AUTH, auth.pack())
        self.state = TTLSState.SERVER_WAIT_FINISHED

        # 4) Finished do cliente
        expected = _finished_mac(keys.client_finished_key, self.transcript.digest())
        message = self._recv_handshake(HandshakeType.FINISHED)

        try:
            received = Finished.unpack(message.payload).verify_data
        except ValueError as error:
            raise self._fatal(AlertDescription.DECODE_ERROR, str(error))

        if not hmac.compare_digest(received, expected):
            raise self._fatal(AlertDescription.DECRYPT_ERROR, "Finished do cliente inválido")

        self.transcript.add(message.pack())

        # 5) Finished do servidor (inclui o do cliente no transcript)
        self._send_handshake(
            HandshakeType.FINISHED,
            Finished(_finished_mac(keys.server_finished_key, self.transcript.digest())).pack(),
        )

        self._install_ciphers(keys, is_client=False)
        self.state = TTLSState.ESTABLISHED

    def _key_agreement(self, private: X25519PrivateKey, peer_share: bytes):
        try:
            shared = private.exchange(X25519PublicKey.from_public_bytes(peer_share))
        except ValueError:
            raise self._fatal(AlertDescription.ILLEGAL_PARAMETER, "key_share inválido")

        if shared == bytes(32):
            # Ponto de ordem baixa: o segredo sairia previsível (tudo zero).
            raise self._fatal(AlertDescription.ILLEGAL_PARAMETER, "key_share de ordem baixa")

        # H(ClientHello || ServerHello): é o que a assinatura do servidor cobre.
        self._hello_hash_for_auth = self.transcript.digest()

        return derive_traffic_keys(shared, self._hello_hash_for_auth)

    def _verify_server_auth(self, auth: ServerAuth, hello_hash: bytes) -> None:
        if auth.anonymous:
            if self.trusted_server_key is not None:
                raise self._fatal(AlertDescription.HANDSHAKE_FAILURE, "o servidor não se autenticou, mas esperávamos uma chave fixada")

            self.server_authenticated = False
            return

        try:
            Ed25519PublicKey.from_public_bytes(auth.public_key).verify(auth.signature, AUTH_CONTEXT + hello_hash)
        except (InvalidSignature, ValueError):
            raise self._fatal(AlertDescription.DECRYPT_ERROR, "assinatura do servidor inválida")

        self.peer_public_key = auth.public_key

        if self.trusted_server_key is None:
            # Assinatura válida, mas não sabemos se a chave é a do servidor real.
            self.server_authenticated = False
            return

        if not hmac.compare_digest(auth.public_key, self.trusted_server_key):
            raise self._fatal(AlertDescription.HANDSHAKE_FAILURE, "a chave do servidor não é a esperada (possível MITM)")

        self.server_authenticated = True

    # =========================================================================
    # Dados de aplicação
    # =========================================================================

    def _require_established(self) -> None:
        if self.state != TTLSState.ESTABLISHED:
            raise TTLSError(f"sessão não está estabelecida (estado: {self.state.name}).")

    def send_application_data(self, data: bytes) -> None:
        """Envia `data`, quebrando em registros de até 16 KiB (fronteiras NÃO são preservadas)."""
        self._require_established()

        data = bytes(data)

        if not data:
            self._send_record(RecordType.APPLICATION_DATA, b"", encrypt=True)
            return

        for offset in range(0, len(data), MAX_FRAGMENT):
            self._send_record(RecordType.APPLICATION_DATA, data[offset : offset + MAX_FRAGMENT], encrypt=True)

    def recv_application_data(self, timeout: float | None = None) -> bytes:
        """
        Devolve o conteúdo do PRÓXIMO registro de dados. Heartbeats são
        tratados aqui dentro (responde pedidos, resolve pings). Levanta
        TTLSClosed no close_notify do par, TTLSTruncated se o transporte
        cair sem ele, TTLSAlertError em alerta fatal / registro adulterado.
        """
        self._require_established()

        with self._recv_lock:
            while True:
                record = self._read_record(timeout)

                if record.record_type == RecordType.HANDSHAKE:
                    raise self._fatal(AlertDescription.UNEXPECTED_MESSAGE, "handshake após o estabelecimento")

                try:
                    plaintext = self._cipher_in.decrypt(record.payload, associated_data=record.raw_header)
                except TTLSAlertError as error:
                    raise self._fatal(error.description, str(error))

                if record.record_type == RecordType.APPLICATION_DATA:
                    return plaintext

                if record.record_type == RecordType.HEARTBEAT:
                    self._on_heartbeat(plaintext)
                    continue

                if record.record_type == RecordType.ALERT:
                    alert = Alert.unpack(plaintext)
                    self.state = TTLSState.CLOSED

                    try:
                        self.transport.close()
                    except Exception:
                        pass

                    if alert.description == AlertDescription.CLOSE_NOTIFY:
                        raise TTLSClosed("O par encerrou a sessão (close_notify).")

                    raise TTLSAlertError(alert.description, f"alerta do par: {alert.description.name}")

    # nomes curtos
    send = send_application_data
    recv = recv_application_data

    # ---- heartbeat -----------------------------------------------------------

    def _on_heartbeat(self, payload: bytes) -> None:
        if len(payload) != 9:
            raise self._fatal(AlertDescription.DECODE_ERROR, "heartbeat inválido")

        kind, nonce = payload[0], payload[1:]

        if kind == _HB_REQUEST:
            self._send_record(RecordType.HEARTBEAT, bytes([_HB_RESPONSE]) + nonce, encrypt=True)
        elif kind == _HB_RESPONSE:
            waiter = self._pings.get(nonce)

            if waiter is not None:
                waiter[1] = time.monotonic()
                waiter[0].set()

    def ping(self, timeout: float = 5.0) -> float:
        """
        Mede o RTT ponta a ponta (já com a criptografia no meio). Exige que
        OUTRA thread esteja consumindo recv_application_data() -- é ela que
        recebe e resolve o heartbeat de resposta.
        """
        self._require_established()

        nonce = os.urandom(8)
        waiter = [threading.Event(), 0.0]
        self._pings[nonce] = waiter
        started = time.monotonic()

        try:
            self._send_record(RecordType.HEARTBEAT, bytes([_HB_REQUEST]) + nonce, encrypt=True)

            if not waiter[0].wait(timeout):
                raise TimeoutError("ping sem resposta.")

            return waiter[1] - started
        finally:
            self._pings.pop(nonce, None)

    # =========================================================================
    # Encerramento
    # =========================================================================

    def close(self) -> None:
        """Encerramento ordenado: close_notify e depois fecha o transporte."""
        if self.state == TTLSState.ESTABLISHED:
            try:
                self._send_record(
                    RecordType.ALERT,
                    Alert(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY).pack(),
                    encrypt=True,
                )
            except Exception:
                pass

        self.state = TTLSState.CLOSED

        try:
            self.transport.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
