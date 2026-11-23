# =============================================================================
# ttp/errors.py
# -----------------------------------------------------------------------------
# Hierarquia de exceções do TTP. Todas herdam de ConnectionError (logo de
# OSError), então código que já faz `except OSError` / `except TimeoutError`
# continua funcionando; e quem quiser pode capturar só `TTPError`.
# =============================================================================


class TTPError(ConnectionError):
    """Base de todos os erros de conexão do TTP."""


class TTPClosed(TTPError):
    """A conexão já foi (ou está sendo) encerrada; não dá para enviar mais."""


class TTPTimeout(TTPError, TimeoutError):
    """O par parou de responder (retransmissões esgotadas / keepalive)."""


class TTPReset(TTPError, ConnectionResetError):
    """O par enviou um RST: a conexão foi derrubada abruptamente."""


class TTPRefused(TTPError, ConnectionRefusedError):
    """Ninguém está escutando nessa porta (o SYN foi respondido com RST)."""
