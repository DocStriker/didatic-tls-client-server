# =============================================================================
# ttls/cipher.py
# -----------------------------------------------------------------------------
# AES-256-GCM de UM sentido, com nonce derivado do NÚMERO DE SEQUÊNCIA do
# registro (mesma ideia do TLS 1.3):
#
#       nonce_i = IV  XOR  i          (i = contador de registros, 96 bits)
#
# POR QUE ISSO IMPORTA PARA A SINCRONIA
#   A versão anterior gerava um nonce ALEATÓRIO por registro e o mandava junto.
#   Funcionava, mas o registro não dizia nada sobre "qual é o i-ésimo": um
#   registro REPETIDO (replay), REORDENADO ou REMOVIDO no meio do caminho era
#   decifrado normalmente. Agora emissor e receptor mantêm, cada um, um
#   contador implícito; o nonce depende dele. Se um registro some, se repete
#   ou troca de lugar, o contador do receptor deixa de bater com o do
#   emissor, a TAG GCM falha e a sessão é derrubada (BAD_RECORD_MAC).
#
#   Bônus: o nonce não vai mais na rede (-12 bytes por registro).
#
#   Cada sentido tem chave e IV PRÓPRIOS (client_write / server_write): senão
#   o mesmo i usaria o mesmo nonce nos dois sentidos com a mesma chave --
#   catastrófico para o GCM -- e um registro do cliente poderia ser refletido
#   de volta como se fosse do servidor.
# =============================================================================

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ttls.alert import AlertDescription, TTLSAlertError


class TTLSCipher:
    KEY_SIZE = 32
    IV_SIZE = 12
    TAG_SIZE = 16
    MAX_RECORDS = 1 << 40   # bem abaixo do limite seguro do GCM; depois disso, renegociar

    def __init__(self, key: bytes, iv: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError("A chave AES-256 deve possuir 32 bytes.")

        if len(iv) != self.IV_SIZE:
            raise ValueError("O IV deve possuir 12 bytes.")

        self._aes = AESGCM(key)
        self._iv = int.from_bytes(iv, "big")
        self.sequence = 0

    def _nonce(self) -> bytes:
        return (self._iv ^ self.sequence).to_bytes(self.IV_SIZE, "big")

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        if self.sequence >= self.MAX_RECORDS:
            raise TTLSAlertError(AlertDescription.INTERNAL_ERROR, "limite de registros por chave atingido")

        ciphertext = self._aes.encrypt(self._nonce(), plaintext, associated_data)
        self.sequence += 1

        return ciphertext

    def decrypt(self, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        if len(ciphertext) < self.TAG_SIZE:
            raise TTLSAlertError(AlertDescription.DECODE_ERROR, "registro menor que a tag")

        try:
            plaintext = self._aes.decrypt(self._nonce(), ciphertext, associated_data)
        except InvalidTag:
            raise TTLSAlertError(
                AlertDescription.BAD_RECORD_MAC,
                f"tag inválida no registro #{self.sequence}: adulterado, repetido, reordenado ou removido",
            ) from None

        self.sequence += 1

        return plaintext


@dataclass(frozen=True)
class TrafficKeys:
    client_write_key: bytes
    server_write_key: bytes
    client_write_iv: bytes
    server_write_iv: bytes
    client_finished_key: bytes
    server_finished_key: bytes


def derive_traffic_keys(shared_secret: bytes, transcript_hash: bytes) -> TrafficKeys:
    """
    Key schedule: um HKDF-SHA256 sobre o segredo ECDHE, com o hash do
    transcript (ClientHello||ServerHello) como salt. Amarrar o salt ao
    transcript significa que duas sessões nunca derivam as mesmas chaves, e
    que se alguém alterou os Hellos as chaves divergem.

        okm = HKDF(secret=ECDHE, salt=H(CH||SH), info="TTLS v2 keys", len=152)
        okm = cw_key(32) | sw_key(32) | cw_iv(12) | sw_iv(12) | cf_key(32) | sf_key(32)
    """
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=32 + 32 + 12 + 12 + 32 + 32,
        salt=transcript_hash,
        info=b"TTLS v2 keys",
    ).derive(shared_secret)

    return TrafficKeys(
        client_write_key=okm[0:32],
        server_write_key=okm[32:64],
        client_write_iv=okm[64:76],
        server_write_iv=okm[76:88],
        client_finished_key=okm[88:120],
        server_finished_key=okm[120:152],
    )


if __name__ == "__main__":
    # Teste rápido
    import os

    keys = derive_traffic_keys(os.urandom(32), os.urandom(32))
    sender = TTLSCipher(keys.client_write_key, keys.client_write_iv)
    receiver = TTLSCipher(keys.client_write_key, keys.client_write_iv)

    first = sender.encrypt(b"Hello, TTLS!", b"hdr")
    print("Ciphertext:", first.hex())
    print("Plaintext :", receiver.decrypt(first, b"hdr"))

    try:
        receiver.decrypt(first, b"hdr")  # replay do mesmo registro
    except TTLSAlertError as error:
        print("Replay detectado:", error)
