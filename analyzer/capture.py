from scapy.all import sniff
from scapy.layers.inet import IP, TCP

SERVER_PORT = 8443


class TLSRecord:
    """Representa um TLS Record."""

    HEADER_SIZE = 5

    def __init__(self, data: bytes):

        if len(data) < self.HEADER_SIZE:
            raise ValueError("TLS Record incompleto.")

        self.content_type = data[0]
        self.version = data[1:3]
        self.length = int.from_bytes(data[3:5], "big")
        self.body = data[5:5 + self.length]

    def __repr__(self):
        return (
            f"TLSRecord("
            f"type={self.content_type}, "
            f"length={self.length})"
        )


class HandshakeMessage:
    """Representa uma mensagem de Handshake TLS."""

    HEADER_SIZE = 4

    def __init__(self, data: bytes):

        if len(data) < self.HEADER_SIZE:
            raise ValueError("Handshake incompleto.")

        self.handshake_type = data[0]
        self.length = int.from_bytes(b"\x00" + data[1:4], "big")
        self.body = data[4:4 + self.length]

    def __repr__(self):
        return (
            f"Handshake("
            f"type={self.handshake_type}, "
            f"length={self.length})"
        )

def hexdump(data: bytes, width: int = 16):

    for offset in range(0, len(data), width):

        chunk = data[offset:offset + width]

        hex_bytes = " ".join(f"{b:02X}" for b in chunk)

        ascii_bytes = "".join(
            chr(b) if 32 <= b <= 126 else "."
            for b in chunk
        )

        print(
            f"{offset:04X}  "
            f"{hex_bytes:<48}  "
            f"{ascii_bytes}"
        )

def print_encrypted_record(record: TLSRecord):

    print("\U0001F512 Registro Criptografado")

    print()

    preview = record.body[:64]

    print(
        f"Primeiros {len(preview)} bytes:"
    )

    hexdump(preview)

    if len(record.body) > 64:

        print()

        print(
            f"... ({len(record.body)-64} bytes omitidos)"
        )

    print()
    print("Conteúdo protegido por criptografia.")
    print("Não é possível interpretar sem a chave da sessão.")

def parse_tls_records(payload: bytes):
    """
    Percorre todos os TLS Records presentes
    em um único segmento TCP.
    """

    offset = 0

    while offset + TLSRecord.HEADER_SIZE <= len(payload):

        try:
            record = TLSRecord(payload[offset:])

        except ValueError:
            break

        yield record

        offset += TLSRecord.HEADER_SIZE + record.length


def get_record_name(content_type: int):

    mapping = {
        20: "Change Cipher Spec",
        21: "Alert",
        22: "Handshake",
        23: "Application Data"
    }

    return mapping.get(content_type, "Desconhecido")


def get_handshake_name(handshake_type: int):

    mapping = {
        1: "ClientHello",
        2: "ServerHello",
        8: "EncryptedExtensions",
        11: "Certificate",
        15: "CertificateVerify",
        20: "Finished"
    }

    return mapping.get(handshake_type, "Handshake Desconhecido")


seen = set()


def callback(pkt):

    if IP not in pkt or TCP not in pkt:
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    if SERVER_PORT not in (tcp.sport, tcp.dport):
        return

    key = (
        ip.src,
        ip.dst,
        tcp.sport,
        tcp.dport,
        tcp.seq,
        tcp.ack,
        str(tcp.flags),
        len(tcp.payload),
    )

    if key in seen:
        return

    seen.add(key)

    print("=" * 70)

    direction = (
        "CLIENTE → SERVIDOR"
        if tcp.dport == SERVER_PORT
        else "SERVIDOR → CLIENTE"
    )

    print(direction)
    print(pkt.summary())

    flags = str(tcp.flags)

    if flags == "S":
        print("Evento : SYN")

    elif flags == "SA":
        print("Evento : SYN-ACK")

    elif flags == "A":
        print("Evento : ACK")

    elif "F" in flags:
        print("Evento : FIN")

    elif "R" in flags:
        print("Evento : RST")

    payload = bytes(tcp.payload)

    print(f"Payload : {len(payload)} bytes")

    if not payload:
        return

    print()

    for index, record in enumerate(parse_tls_records(payload), start=1):

        print(f"TLS Record #{index}")

        print(f"Tipo    : {get_record_name(record.content_type)}")

        print(f"Versão  : {record.version[0]}.{record.version[1]} (0x{record.version.hex()})")

        print(f"Tamanho : {record.length} Bytes")

        print()

        if record.content_type == 22:

            try:

                handshake = HandshakeMessage(record.body)

                print(
                    f"Handshake : "
                    f"{get_handshake_name(handshake.handshake_type)}"
                )

                print(
                    f"HS Length : "
                    f"{handshake.length}"
                )

            except ValueError:

                print("Handshake incompleto.")

        else:

            print_encrypted_record(record)

        print()


sniff(
    iface="lo",
    prn=callback,
    store=False
)