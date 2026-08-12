from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class TTLSCipher:

    KEY_SIZE = 32
    NONCE_SIZE = 12

    def __init__(self, key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError("A chave AES-256 deve possuir 32 bytes.")

        self.key = key
        self.aes = AESGCM(key)

    @classmethod
    def from_shared_secret(cls, shared_secret: bytes, info: bytes = b"TTLS v1 AES-256-GCM"):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=cls.KEY_SIZE,
            salt=None,
            info=info,
        )

        key = hkdf.derive(shared_secret)

        return cls(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None,) -> bytes:
        nonce = os.urandom(self.NONCE_SIZE)

        ciphertext = self.aes.encrypt(nonce, plaintext, associated_data)

        return nonce + ciphertext

    def decrypt(self, data: bytes, associated_data: bytes | None = None,) -> bytes:
        if len(data) < self.NONCE_SIZE:
            raise ValueError("Ciphertext inválido.")

        nonce = data[:self.NONCE_SIZE]
        ciphertext = data[self.NONCE_SIZE:]

        return self.aes.decrypt(nonce, ciphertext, associated_data)

if __name__ == "__main__":
    # Teste rápido
    shared_secret = os.urandom(32)
    cipher = TTLSCipher.from_shared_secret(shared_secret)
    ciphertext = cipher.encrypt(b"Hello, TTLS!")
    print(f"Ciphertext: {ciphertext.hex()}")
    plaintext = cipher.decrypt(ciphertext, associated_data=None)
    print(f"Plaintext: {plaintext}")