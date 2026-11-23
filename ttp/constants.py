# =============================================================================
# ttp/constants.py
# -----------------------------------------------------------------------------
# Central place for the "magic numbers" and struct layout strings shared by
# every module in the ttp/ package. Keeping them here means the wire format
# is defined exactly once.
# =============================================================================

# Custom IP protocol number used to tag TTP datagrams inside the IPv4
# header's "Protocol" field. Real protocols use well-known numbers (TCP=6,
# UDP=17, ICMP=1, ...); 253 and 254 are officially reserved by IANA for
# "experimentation and testing", which is exactly what this project is.
TTP_PROTOCOL = 253

# Tamanho máximo da janela anunciada. O campo "Window" do cabeçalho tem 16
# bits, então 65535 é o teto absoluto.
DEFAULT_WINDOW_SIZE = 65535

# MSS (Maximum Segment Size): maior payload de UM segmento TTP.
#
# O valor antigo (65535) estava errado por dois motivos:
#   1) IP total_length é 16 bits: 20 (IP) + 24 (TTP) + 65535 > 65535, então
#      struct.pack estourava;
#   2) em uma rede real o MTU é ~1500: 1500 - 20 (IP) - 24 (TTP) = 1456.
# 1400 deixa folga para túneis/VPN e evita fragmentação IP.
MAX_SEGMENT_SIZE = 1400
MAX_PACKET_SIZE = MAX_SEGMENT_SIZE  # nome antigo, mantido por compatibilidade

# Aritmética de números de sequência de 32 bits (módulo 2**32).
SEQ_MOD = 1 << 32
SEQ_MASK = SEQ_MOD - 1
SEQ_HALF = 1 << 31

# struct format string for the TTP header (see ttp/packet.py):
#   H  source_port            (2 bytes, unsigned short)
#   H  destination_port       (2 bytes, unsigned short)
#   I  sequence_number        (4 bytes, unsigned int)
#   I  acknowledgment_number  (4 bytes, unsigned int)
#   B  flags                  (1 byte)
#   B  header_length          (1 byte)
#   H  reserved               (2 bytes)
#   H  window                 (2 bytes)
#   H  payload_length         (2 bytes)
#   I  checksum               (4 bytes)
# "!" forces network byte order (big-endian), matching real network headers.
HEADER_FORMAT = "!HHIIBBHHHI"

# struct format string for a (simplified) IPv4 header, used by ttp/ipv4.py
# to hand-craft raw IP datagrams carrying TTP segments:
#   B  version_ihl
#   B  tos
#   H  total_length
#   H  identification
#   H  flags_fragment_offset
#   B  ttl
#   B  protocol
#   H  header_checksum
#   4s source_address (raw 4-byte IPv4 address)
#   4s destination_address (raw 4-byte IPv4 address)
HEADER_FORMAT_IPV4 = "!BBHHHBBH4s4s"

# struct format string for the TTLS header (see ttls/record.py):
#   B  type
#   B  version
#   I  length
TTLS_HEADER_FORMAT = "!BBI"

# Default TCP/UDP/TTP port used across the demo scripts and the Wireshark
# helper (wireshark/sniffer.py) to recognize which packets belong to this
# project's traffic.
SERVER_PORT = 8443
