# =============================================================================
# ttls/record.py
# -----------------------------------------------------------------------------
# "Tarek Transport Layer Security" (TTLS) v2 -- camada de REGISTROS, inspirada
# no TLS Record Protocol. Resolve o problema "onde termina uma mensagem e
# começa a próxima?" sobre um FLUXO de bytes: todo registro tem um cabeçalho
# fixo com tipo e tamanho exato do payload.
#
#   +--------+---------+------------+------------------+
#   | Type   | Version | Length     | Payload          |
#   | 1 byte | 1 byte  | 4 bytes    | N bytes          |
#   +--------+---------+------------+------------------+
#
# O QUE MUDOU:
#   * A docstring antiga dizia que "recv_record() é a versão segura para
#     streaming", mas essa função não existia: a sessão assumia que cada
#     segmento TTP continha exatamente UM registro. Basta um registro maior
#     que o MSS (ou dois pequenos coalescidos) para quebrar. Agora
#     `read_from()` lê o cabeçalho (6 bytes) e depois EXATAMENTE `length`
#     bytes, venham em quantos segmentos vierem.
#   * `length` tem 4 bytes e vem da rede: sem limite, um par malicioso
#     anuncia 4 GB e a memória do receptor vai embora. Agora é limitado a
#     MAX_RECORD_PAYLOAD (RECORD_OVERFLOW se passar).
#   * VERSION = 2 (o formato dos handshakes e da cifra mudou: um peer v1 é
#     recusado em vez de falhar de forma confusa).
# =============================================================================

import struct
from enum import IntEnum

from ttp.constants import TTLS_HEADER_FORMAT


class RecordType(IntEnum):
    APPLICATION_DATA = 0x01
    HANDSHAKE = 0x02
    ALERT = 0x03
    HEARTBEAT = 0x04


# Máximo de bytes de TEXTO CLARO por registro (como o TLS: 2^14).
MAX_FRAGMENT = 16384

# Máximo aceito no campo Length: texto claro + tag GCM (16) + folga.
MAX_RECORD_PAYLOAD = MAX_FRAGMENT + 256


class TTLSRecord:
    """Um registro TTLS (cabeçalho de 6 bytes + payload)."""

    HEADER_SIZE = struct.calcsize(TTLS_HEADER_FORMAT)

    VERSION = 2

    def __init__(self, record_type: RecordType, payload: bytes):
        self.record_type = RecordType(record_type)
        self.version = self.VERSION
        self.payload = payload

    def pack_header(self) -> bytes:
        return self.build_header(self.record_type, self.version, len(self.payload))

    def pack(self) -> bytes:
        return self.pack_header() + self.payload

    @classmethod
    def build_header(cls, record_type: RecordType, version: int, payload_length: int) -> bytes:
        return struct.pack(TTLS_HEADER_FORMAT, record_type, version, payload_length)

    @classmethod
    def parse_header(cls, header: bytes) -> tuple[RecordType, int, int]:
        """Valida um cabeçalho vindo da rede e devolve (tipo, versão, tamanho)."""
        record_type, version, length = struct.unpack(TTLS_HEADER_FORMAT, header)

        if version != cls.VERSION:
            raise ValueError(f"Versão TTLS não suportada: {version}")

        if length > MAX_RECORD_PAYLOAD:
            raise OverflowError(f"Registro grande demais: {length} bytes.")

        return RecordType(record_type), version, length

    @classmethod
    def read_from(cls, read_exact) -> "TTLSRecord":
        """
        Lê UM registro de um fluxo. `read_exact(n)` deve devolver exatamente
        n bytes (ou levantar EOFError). Devolve o registro com o `header`
        original guardado em `raw_header` (ele é o AAD da cifra).
        """
        header = read_exact(cls.HEADER_SIZE)
        record_type, _, length = cls.parse_header(header)
        payload = read_exact(length) if length else b""

        record = cls(record_type, payload)
        record.raw_header = header

        return record

    @classmethod
    def unpack(cls, data: bytes):
        # Reconstrói um registro a partir de bytes que já contêm cabeçalho +
        # payload completos (usado pelo sniffer e em testes).
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("TTLS Header incompleto.")

        record_type, _, length = cls.parse_header(data[: cls.HEADER_SIZE])
        payload = data[cls.HEADER_SIZE :]

        if len(payload) != length:
            raise ValueError(f"Payload inválido. Esperado {length} bytes, recebido {len(payload)}.")

        return cls(record_type, payload)
