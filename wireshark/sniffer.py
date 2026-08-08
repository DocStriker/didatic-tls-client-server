# =============================================================================
# wireshark/sniffer.py
# -----------------------------------------------------------------------------
# Live packet sniffer script (Scapy-based) that acts like a tiny, purpose
# built "Wireshark for this project": it listens on the loopback interface
# and prints a decoded, colour-free summary of every TCP/UDP/TTP packet
# relevant to this demo, using the printers defined in wireshark/capture.py.
#
# Run it (as root/administrator, since packet sniffing requires raw access)
# in its own terminal *before* running the client/server, so you can watch
# the handshake and data exchange happen live:
#
#   sudo python -m wireshark.sniffer
# =============================================================================

import sys
from pathlib import Path

# Ensures the project root is on sys.path so `from ttp...` / `from
# wireshark...` absolute imports work even if this script is executed
# directly (e.g. `python wireshark/sniffer.py`) rather than as a module.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import bind_layers
from wireshark.capture import capture_tcp, capture_udp, capture_ttp, TTP
from ttp.constants import TTP_PROTOCOL, SERVER_PORT

# Registers the custom TTP class as the payload dissector for any IP packet
# whose "proto" field equals 253 -- this is what lets Scapy automatically
# parse pkt[TTP] fields for TTP traffic, the same way it already knows how
# to dissect pkt[TCP] or pkt[UDP].
bind_layers(IP, TTP, proto=253)

def callback(pkt):
    # Invoked by Scapy's sniff() for every captured packet. Filters down to
    # just the traffic this project cares about and dispatches it to the
    # matching capture_* printer.
    try:
        if IP not in pkt:
            return

        ip = pkt[IP]

        # TTP possui prioridade porque não é TCP nem UDP
        # (TTP is checked first since it is neither TCP nor UDP -- it's
        # identified purely by the custom IP protocol number.)
        if ip.proto == TTP_PROTOCOL:
            capture_ttp(pkt)
            return

        if TCP in pkt:
            tcp = pkt[TCP]

            # Only show TCP traffic actually belonging to this demo (i.e.
            # involving SERVER_PORT), to avoid drowning the output in
            # unrelated loopback traffic from other applications.
            if SERVER_PORT not in (tcp.sport, tcp.dport):
                return

            capture_tcp(pkt)
            return

        if UDP in pkt:
            udp = pkt[UDP]

            if SERVER_PORT not in (udp.sport, udp.dport):
                return

            capture_udp(pkt)
            return
    except Exception as e:
        print(f"Erro ao processar pacote: {e}")
        return

try:
    # Captures on "lo" (loopback), since this demo always runs client and
    # server on 127.0.0.1. store=False avoids buffering every packet in
    # memory (we only need to print them as they arrive).
    sniff(iface="lo", prn=callback, store=False)

except KeyboardInterrupt:
    print("\nCaptura interrompida pelo usuário")

except Exception as e:
    print(f"Erro durante a captura: {e}")
