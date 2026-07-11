from scapy.all import sniff
from scapy.layers.inet import IP, TCP

SERVER_PORT = 8443

seen = set()   # <-- Aqui

def callback(pkt):

    if IP not in pkt or TCP not in pkt:
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    if SERVER_PORT not in (tcp.sport, tcp.dport):
        return
    
    print("=" * 60)

    direction = (
        "CLIENTE → SERVIDOR"
        if tcp.dport == SERVER_PORT
        else "SERVIDOR → CLIENTE"
    )

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

        print(direction)
        print(f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}")

        flags = tcp.flags

        if flags == "S":
            print("Evento: SYN")

        elif flags == "SA":
            print("Evento: SYN-ACK")

        elif flags == "A":
            print("Evento: ACK")

        elif "F" in flags:
            print("Evento: FIN")

        elif "R" in flags:
            print("Evento: RST")
        return

    seen.add(key)

    #print(pkt.summary())

sniff(iface="lo", prn=callback)