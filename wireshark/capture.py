from scapy.all import IP, TCP, UDP
from wireshark.utils import print_payload
from scapy.fields import (ShortField, IntField, ByteField)
from scapy.packet import Packet
from ttp.packet import TTPFlags
from ttp.constants import SERVER_PORT

seen = set()

class TTP(Packet):
    name = "TTP"

    fields_desc = [
        ShortField("source_port", 0),
        ShortField("destination_port", 0),
        IntField("sequence_number", 0),
        IntField("acknowledgment_number", 0),
        ByteField("flags", 0),
        ByteField("header_length", 24),
        ShortField("reserved", 0),
        ShortField("window_size", 0),
        ShortField("payload_length", 0),
        IntField("checksum", 0),
    ]

def get_direction(destination_port):
    if destination_port == SERVER_PORT:
        return "CLIENTE → SERVIDOR"

    return "SERVIDOR → CLIENTE"

def capture_tcp(pkt):

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

    print(get_direction(tcp.dport))

    print()

    print(f"Origem      : " f"{ip.src}:{tcp.sport}")

    print(f"Destino     : " f"{ip.dst}:{tcp.dport}")

    print(f"SEQ         : " f"{tcp.seq}")

    print(f"ACK         : " f"{tcp.ack}")

    print(f"Janela      : " f"{tcp.window}")

    print(f"Flags       : " f"{tcp.flags}")

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

def capture_udp(pkt):

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

    print(get_direction(udp.dport))

    print()

    print(f"Origem      : " f"{ip.src}:{udp.sport}")

    print(f"Destino     : " f"{ip.dst}:{udp.dport}")

    print(f"Comprimento : " f"{udp.len}")

    print(f"Checksum    : " f"0x{udp.chksum:04X}")

    print("Evento      : " "Datagrama UDP")

    payload = bytes(udp.payload)

    print_payload(payload)

def capture_ttp(pkt):

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
        ttp.payload_length
    )

    if key in seen:
        return

    seen.add(key)

    print("=" * 80)

    print("TTP")

    print(get_direction(ttp.destination_port))

    print()

    print(f"Origem      : " f"{ip.src}:{ttp.source_port}")

    print(f"Destino     : " f"{ip.dst}:{ttp.destination_port}")

    print()

    print(f"SEQ         : " f"{ttp.sequence_number}")

    print(f"ACK         : " f"{ttp.acknowledgment_number}")

    print(f"Flags       : " f"{ttp.flags}")

    print(f"Janela      : " f"{ttp.window_size}")

    print(f"Checksum    : " f"0x{ttp.checksum:04X}")

    flags = TTPFlags(ttp.flags)

    print(f"Flags       : " f"{flags}")

    if flags == TTPFlags.NONE:
        print("Evento      : NONE")

    else:
        events = []

        if TTPFlags.SYN in flags:
            events.append("SYN")
        if TTPFlags.ACK in flags:
            events.append("ACK")
        if TTPFlags.FIN in flags:
            events.append("FIN")
        if TTPFlags.RST in flags:
            events.append("RST")
        if TTPFlags.DATA in flags:
            events.append("DATA")

        print("Evento      : " + ", ".join(events))

    print("Payload     : " + str(len(ttp.payload)) + " bytes")

    print_payload(bytes(ttp.payload))