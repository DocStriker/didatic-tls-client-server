from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


SERVER_PORT = 8443
TTP_PROTOCOL = 253

seen = set()

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ShortField,
    IntField,
    ByteField
)

class TTP(Packet):

    name = "TTP"

    fields_desc = [

        ShortField("source_port", 0),

        ShortField("destination_port", 0),

        IntField("sequence_number", 0),

        IntField("acknowledgment_number", 0),

        ByteField("flags", 0),

        ShortField("window_size", 0),

        ShortField("checksum", 0),
    ]


bind_layers(
    IP,
    TTP,
    proto=253
)


def hexdump(data: bytes, width: int = 16):

    for offset in range(0, len(data), width):

        chunk = data[offset:offset + width]

        hex_bytes = " ".join(
            f"{byte:02X}"
            for byte in chunk
        )

        ascii_bytes = "".join(
            chr(byte) if 32 <= byte <= 126 else "."
            for byte in chunk
        )

        print(
            f"{offset:04X}  "
            f"{hex_bytes:<48}  "
            f"{ascii_bytes}"
        )


def identify_payload(data: bytes):

    if not data:
        return "Sem payload"

    try:

        text = data.decode("utf-8")

        if text.isprintable():
            return "Texto UTF-8"

    except UnicodeDecodeError:

        pass

    if data.startswith(b"GET"):
        return "HTTP Request"

    if data.startswith(b"POST"):
        return "HTTP Request"

    if data.startswith(b"HTTP"):
        return "HTTP Response"

    if data.startswith(b"{"):
        return "JSON"

    if data.startswith(b"["):
        return "JSON"

    return "Dados Binários"


def get_direction(ip, source_port, destination_port):

    if destination_port == SERVER_PORT:

        return "CLIENTE → SERVIDOR"

    return "SERVIDOR → CLIENTE"


def print_payload(payload: bytes):

    print(
        f"Payload     : "
        f"{len(payload)} bytes"
    )

    if not payload:
        return

    try:
        payload_type = identify_payload(payload)

        print(
            f"Tipo        : "
            f"{payload_type}"
        )

        print()

        if payload_type == "Texto UTF-8":
            print("Conteúdo")
            print("-" * 40)
            print(
                payload.decode(
                    "utf-8",
                    errors="replace"
                )
            )
            print("-" * 40)

        else:
            print("Hexdump")
            print("-" * 40)
            hexdump(payload)
            print("-" * 40)
    except Exception as e:
        print(f"Erro ao processar payload: {e}")
        print("Hexdump")
        print("-" * 40)
        hexdump(payload)
        print("-" * 40)


def analyze_tcp(pkt):

    ip = pkt[IP]
    tcp = pkt[TCP]

    key = (
        "TCP",

        ip.src,
        ip.dst,

        tcp.sport,
        tcp.dport,

        tcp.seq,
        tcp.ack,

        str(tcp.flags),

        len(tcp.payload)
    )

    if key in seen:

        return

    seen.add(key)

    print("=" * 80)

    print("TCP")

    print(
        get_direction(
            ip,
            tcp.sport,
            tcp.dport
        )
    )

    print()

    print(
        f"Origem      : "
        f"{ip.src}:{tcp.sport}"
    )

    print(
        f"Destino     : "
        f"{ip.dst}:{tcp.dport}"
    )

    print(
        f"SEQ         : "
        f"{tcp.seq}"
    )

    print(
        f"ACK         : "
        f"{tcp.ack}"
    )

    print(
        f"Janela      : "
        f"{tcp.window}"
    )

    print(
        f"Flags       : "
        f"{tcp.flags}"
    )

    flags = str(tcp.flags)

    if flags == "S":

        print("Evento      : SYN")

    elif flags == "SA":

        print("Evento      : SYN-ACK")

    elif flags == "A":

        print("Evento      : ACK")

    elif flags == "F":

        print("Evento      : FIN")

    elif flags == "FA":

        print("Evento      : FIN-ACK")

    elif flags == "R":

        print("Evento      : RST")

    elif flags == "PA":

        print("Evento      : PUSH-ACK")

    payload = bytes(tcp.payload)

    print_payload(payload)


def analyze_udp(pkt):

    ip = pkt[IP]
    udp = pkt[UDP]

    key = (
        "UDP",

        ip.src,
        ip.dst,

        udp.sport,
        udp.dport,

        len(udp.payload)
    )

    if key in seen:

        return

    seen.add(key)

    print("=" * 80)

    print("UDP")

    print(
        get_direction(
            ip,
            udp.sport,
            udp.dport
        )
    )

    print()

    print(
        f"Origem      : "
        f"{ip.src}:{udp.sport}"
    )

    print(
        f"Destino     : "
        f"{ip.dst}:{udp.dport}"
    )

    print(
        f"Comprimento : "
        f"{udp.len}"
    )

    print(
        f"Checksum    : "
        f"0x{udp.chksum:04X}"
    )

    print(
        "Evento      : "
        "Datagrama UDP"
    )

    payload = bytes(udp.payload)

    print_payload(payload)


def analyze_ttp(pkt):

    ip = pkt[IP]
    ttp = pkt[TTP]

    key = (
        "TTP",

        ip.src,
        ip.dst,

        ttp.source_port,
        ttp.destination_port,

        ttp.sequence_number,
        ttp.acknowledgment_number,

        str(ttp.flags),

        len(ttp.payload)
    )

    if key in seen:

        return

    seen.add(key)

    print("=" * 80)

    print("TTP")

    print(
        get_direction(
            ip,
            ttp.source_port,
            ttp.destination_port
        )
    )

    print()

    print(
        f"Origem      : "
        f"{ip.src}:{ttp.source_port}"
    )

    print(
        f"Destino     : "
        f"{ip.dst}:{ttp.destination_port}"
    )

    print()

    print(
        f"SEQ         : "
        f"{ttp.sequence_number}"
    )

    print(
        f"ACK         : "
        f"{ttp.acknowledgment_number}"
    )

    print(
        f"Flags       : "
        f"{ttp.flags}"
    )

    print(
        f"Janela      : "
        f"{ttp.window_size}"
    )

    print(
        f"Checksum    : "
        f"0x{ttp.checksum:04X}"
    )

    print()
    # if TTPFlags.SYN in str(ttp.flags):
    #     print("Evento      : SYN")
    # elif TTPFlags.FIN in str(ttp.flags):
    #     print("Evento      : FIN")
    # elif TTPFlags.RST in str(ttp.flags):
    #     print("Evento      : RST")
    # elif TTPFlags.ACK in str(ttp.flags):
    #     print("Evento      : ACK")
    # elif TTPFlags.DATA in str(ttp.flags):
    #     print("Evento      : DATA")

    print_payload(
        bytes(ttp.payload)
    )


def callback(pkt):
    try:
        if IP not in pkt:
            return

        ip = pkt[IP]

        # TTP possui prioridade porque não é TCP nem UDP
        if ip.proto == TTP_PROTOCOL:
            analyze_ttp(pkt)
            return

        if TCP in pkt:
            tcp = pkt[TCP]

            if SERVER_PORT not in (
                tcp.sport,
                tcp.dport
            ):
                return

            analyze_tcp(pkt)
            return

        if UDP in pkt:
            udp = pkt[UDP]

            if SERVER_PORT not in (
                udp.sport,
                udp.dport
            ):
                return

            analyze_udp(pkt)
            return
    except Exception as e:
        print(f"Erro ao processar pacote: {e}")
        return


try:
    sniff(
        iface="lo",
        prn=callback,
        store=False
    )
except KeyboardInterrupt:
    print("\nCaptura interrompida pelo usuário")
except Exception as e:
    print(f"Erro durante a captura: {e}")