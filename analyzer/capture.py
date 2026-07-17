from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import bind_layers
from utils import print_payload
from analyzers import analyze_tcp, analyze_udp, analyze_ttp, SERVER_PORT, TTP_PROTOCOL, TTP

bind_layers(IP, TTP, proto=253)

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