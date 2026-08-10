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

# Default flow-control window (in bytes) advertised/used when a
# TTPConnection is created without an explicit window_size.
DEFAULT_WINDOW_SIZE = 65535

# Largest single TTP segment payload allowed by the packet format
# (payload_length is a 16-bit field, so 65535 is the hard ceiling).
MAX_PACKET_SIZE = 65535

# struct format string for the TTP header (see ttp/packet.py):
#   H  source_port            (2 bytes, unsigned short)
#   H  destination_port       (2 bytes, unsigned short)
#   I  sequence_number        (4 bytes, unsigned int)
#   I  acknowledgment_number  (4 bytes, unsigned int)
#   B  flags                  (1 byte)
#   B  header_length          (1 byte)
#   H  reserved                (2 bytes)
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

# Internal module-level cache used by ttp/log_config.py so that every
# TTPConnection instance in the same process shares a single logging.Logger
# (and therefore a single ttp_shared.log file) instead of creating duplicate
# handlers.
_SHARED_LOGGER = None
_SHARED_LOG_FILE_PATH = None
