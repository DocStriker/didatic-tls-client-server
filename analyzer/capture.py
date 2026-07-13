from scapy.all import sniff
from scapy.layers.inet import IP, TCP

SERVER_PORT = 8443

seen = set()


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
        len(tcp.payload)
    )

    if key in seen:
        return

    seen.add(key)

    print("=" * 80)

    direction = (
        "CLIENTE → SERVIDOR"
        if tcp.dport == SERVER_PORT
        else "SERVIDOR → CLIENTE"
    )

    print(direction)

    print()

    print(f"Origem      : {ip.src}:{tcp.sport}")
    print(f"Destino     : {ip.dst}:{tcp.dport}")

    print(f"SEQ         : {tcp.seq}")
    print(f"ACK         : {tcp.ack}")

    print(f"Janela      : {tcp.window}")
    print(f"Flags       : {tcp.flags}")

    flags = str(tcp.flags)

    if flags == "S":
        print("Evento : SYN")

    elif flags == "SA":
        print("Evento : SYN-ACK")

    elif flags == "A":
        print("Evento : ACK")

    elif flags == "F":
        print("Evento : FIN")

    elif flags == "FA":
        print("Evento : FIN-ACK")

    elif flags == "R":
        print("Evento : RST")

    elif flags == "PA":
        print("Evento : PUSH-ACK")

    payload = bytes(tcp.payload)

    print(f"Payload     : {len(payload)} bytes")

    if not payload:
        return

    payload_type = identify_payload(payload)

    print(f"Tipo        : {payload_type}")

    print()

    if payload_type == "Dados Binários":

        print("Conteúdo")

        print("-" * 40)

        print(payload.decode())

        print("-" * 40)

    else:

        print("Hexdump")

        print("-" * 40)

        hexdump(payload)

        print("-" * 40)


sniff(
    iface="lo",
    filter=f"tcp port {SERVER_PORT}",
    prn=callback,
    store=False
)