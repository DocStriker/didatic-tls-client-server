from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP

print(get_if_list())

SERVER_PORT = 8443

def callback(pkt):
    if IP not in pkt or TCP not in pkt:
        return

    tcp = pkt[TCP]

    if tcp.sport == SERVER_PORT or tcp.dport == SERVER_PORT:
        print(pkt.summary())

sniff(iface='lo',prn=callback)