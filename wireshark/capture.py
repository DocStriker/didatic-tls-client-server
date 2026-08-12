# =============================================================================
# wireshark/capture.py
# -----------------------------------------------------------------------------
# Pretty-printers for the three protocols this project cares about: TCP,
# UDP and TTP. Each capture_* function receives a Scapy packet, extracts
# the relevant header fields, and prints a human-readable, Wireshark-like
# summary to the console (used by wireshark/sniffer.py's live capture
# loop). A custom Scapy `Packet` subclass (`TTP`) teaches Scapy how to
# parse our custom TTP header, since Scapy has no built-in knowledge of it.
# =============================================================================

from scapy.all import IP, TCP, UDP
from wireshark.utils import print_payload, hexdump, identify_payload
from scapy.fields import (ShortField, IntField, ByteField)
from scapy.packet import Packet
from ttp.packet import TTPFlags
from ttp.constants import SERVER_PORT
from ttls.record import TTLSRecord
from ttls.handshake import HandshakeType
from ttp.constants import TTLS_HEADER_FORMAT, HEADER_FORMAT
import struct

# Simple de-duplication set: Scapy's `sniff()` callback can sometimes see
# the same packet more than once on the loopback interface (e.g. one
# capture at the "outgoing" point and one at the "incoming" point). Storing
# a fingerprint of every printed packet avoids printing duplicates.
seen = set()

class TTP(Packet):
    # Scapy packet definition mirroring the TTP header layout from
    # ttp/constants.py's HEADER_FORMAT ("!HHIIBBHHHI"), field for field,
    # so Scapy can dissect raw TTP segments captured off the wire the same
    # way it already knows how to dissect TCP/UDP/IP.
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
    # Since this demo always uses SERVER_PORT (8443) as the well-known
    # server port, we can infer traffic direction just by checking which
    # side the destination port matches.
    if destination_port == SERVER_PORT:
        return "CLIENTE → SERVIDOR"

    return "SERVIDOR → CLIENTE"

def capture_tcp(pkt):

    ip = pkt[IP]
    tcp = pkt[TCP]

    # Fingerprint used for the `seen` de-duplication set.
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

    # Translate Scapy's compact flag-letter string (e.g. "S", "SA", "PA")
    # into a friendlier, named "Evento" (Event) label.
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

    # UDP has no connection concept, so there's only one possible "event".
    print("Evento      : " "Datagrama UDP")

    payload = bytes(udp.payload)

    print_payload(payload)

def capture_ttp(pkt):

    ip = pkt[IP]
    ttp = pkt[TTP]  # dissected using the custom TTP class defined above

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

    TTLS_HEADER_SIZE = struct.calcsize(TTLS_HEADER_FORMAT)
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    print("=" * 80)

    print("TTP v2")

    print(get_direction(ttp.destination_port))

    print()

    print(f"Raw Header  : " f"{hexdump(bytes(ttp)[:HEADER_SIZE], ascii=False, offset_space=14)}")  # prints the dissected TTP header fields in a Scapy-friendly format

    print(f"Header      : " f"{ttp.header_length} bytes")

    print(f"Origem      : " f"{ip.src}:{ttp.source_port}")

    print(f"Destino     : " f"{ip.dst}:{ttp.destination_port}")

    print(f"SEQ         : " f"{ttp.sequence_number}")

    print(f"ACK         : " f"{ttp.acknowledgment_number}")

    print(f"Flags       : " f"{ttp.flags}")

    print(f"Janela      : " f"{ttp.window_size}")

    print(f"Checksum    : " f"0x{ttp.checksum:04X}")

    # Reconstructs the TTPFlags IntFlag from the raw integer, so it can
    # print a friendly comma-separated list of active flag names
    # (SYN, ACK, FIN, RST, DATA) instead of a bare number.
    flags = TTPFlags(ttp.flags)

    if flags == TTPFlags.NONE:
        print("Evento      : NONE")

    else:
        events = []

        if TTPFlags.SYN in flags:
            events.append("SYN")
        if TTPFlags.FIN in flags:
            events.append("FIN")
        if TTPFlags.ACK in flags:
            events.append("ACK")
        if TTPFlags.RST in flags:
            events.append("RST")
        if TTPFlags.DATA in flags:
            events.append("DATA")

        print("Evento      : " + "-".join(events))

    print("Payload     : " + str(len(ttp.payload)) + " bytes")

    ttls_data = bytes(ttp.payload)

    if len(ttls_data) >= TTLS_HEADER_SIZE:
        record = TTLSRecord.unpack(ttls_data)

        payload_type = identify_payload(bytes(record.payload))
    
        print(f"Tipo           : " f"{payload_type}")
        print()
        print(f"TTLS:")
        print(f"  Raw Header     : " f"{hexdump(ttls_data[:TTLS_HEADER_SIZE], ascii=False, offset_space=17)}")
        print(f"  Header         : " f"{TTLS_HEADER_SIZE} bytes")
        print(f"  Version        : " f"v{record.version}.0")
        print(f"  Type           : " f"{record.record_type.name}")

        if record.record_type == record.record_type.HANDSHAKE:
            if record.payload == b"\x01":
                print(f"  Handshake Type : " f"ClientHello")
            elif record.payload == b"\x02":
                print(f"  Handshake Type : " f"ServerHello")
            elif record.payload == b"\x03":
                print(f"  Handshake Type : " f"Finished")
                
        print(f"  Payload        : " f"{len(record.payload)} bytes")
        print(f"  Raw Payload    : " f"{hexdump(ttls_data[TTLS_HEADER_SIZE:], ascii=False, offset_space=17)}")

        if record.record_type != record.record_type.HANDSHAKE:
            print_payload(bytes(record.payload), type_hint=payload_type)
    