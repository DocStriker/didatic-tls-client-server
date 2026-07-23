import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import bind_layers
from wireshark.capture import capture_tcp, capture_udp, capture_ttp, SERVER_PORT, TTP_PROTOCOL, TTP

bind_layers(IP, TTP, proto=253)

def callback(pkt):
    try:
        if IP not in pkt:
            return

        ip = pkt[IP]

        # TTP possui prioridade porque não é TCP nem UDP
        if ip.proto == TTP_PROTOCOL:
            capture_ttp(pkt)
            return

        if TCP in pkt:
            tcp = pkt[TCP]

            if SERVER_PORT not in (
                tcp.sport,
                tcp.dport
            ):
                return

            capture_tcp(pkt)
            return

        if UDP in pkt:
            udp = pkt[UDP]

            if SERVER_PORT not in (
                udp.sport,
                udp.dport
            ):
                return

            capture_udp(pkt)
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