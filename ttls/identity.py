# =============================================================================
# ttls/identity.py
# -----------------------------------------------------------------------------
# Identidade do servidor TTLS = par de chaves Ed25519.
#
# Sem isso, ECDHE sozinho protege contra quem ESCUTA, mas não contra quem se
# coloca NO MEIO (man-in-the-middle): o atacante faz uma troca de chaves com
# o cliente e outra com o servidor. A assinatura prova "quem tem a chave
# privada X assinou ESTA conversa", e o cliente só confia na chave pública
# que ele conhece de antemão (pinning) -- versão simples do que um certificado
# + CA fazem no TLS de verdade.
#
#   certs/ttls_identity.key   chave privada (PEM)  -> fica no SERVIDOR
#   certs/ttls_identity.pub   chave pública (hex)  -> entregue ao CLIENTE
# =============================================================================

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_identity(directory: str | Path, name: str = "ttls_identity") -> tuple[Path, Path]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()

    private_path = directory / f"{name}.key"
    public_path = directory / f"{name}.pub"

    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    try:
        private_path.chmod(0o600)
    except OSError:
        pass

    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public_path.write_text(public_bytes.hex() + "\n")

    return private_path, public_path


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)

    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("A chave de identidade TTLS deve ser Ed25519.")

    return key


def load_public_key(path: str | Path) -> bytes:
    """Lê a chave pública (32 bytes) de um arquivo com 64 caracteres hex."""
    raw = bytes.fromhex(Path(path).read_text().strip())

    if len(raw) != 32:
        raise ValueError("Chave pública Ed25519 deve ter 32 bytes.")

    return raw


def fingerprint(public_key: bytes) -> str:
    """Impressão digital curta para conferir a chave 'a olho' (como no SSH)."""
    digest = hashlib.sha256(public_key).hexdigest()

    return ":".join(digest[i : i + 4] for i in range(0, 32, 4))
