# =============================================================================
# wireshark/utils.py
# -----------------------------------------------------------------------------
# Small formatting helpers used by wireshark/capture.py to pretty-print
# captured packet payloads on the terminal, similar to how Wireshark's
# "Bytes" pane shows a hex + ASCII dump, plus a best-effort payload
# type sniffer so the output is easier to read at a glance.
# =============================================================================

def hexdump(data: bytes, width: int = 16):
    # Classic hex + ASCII dump, `width` bytes per line:
    #   OFFSET  HEX BYTES...                                    ASCII
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]

        hex_bytes = " ".join(f"{byte:02X}" for byte in chunk)

        # Printable ASCII range is 32-126; anything else shown as '.'.
        ascii_bytes = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)

        print(f"{offset:04X}  " f"{hex_bytes:<48}  " f"{ascii_bytes}")

def identify_payload(data: bytes):
    # Heuristic content-type sniffer: tries UTF-8 text first, then checks
    # for a handful of recognizable byte prefixes (HTTP verbs/response,
    # JSON), falling back to "binary data" otherwise. This is only meant
    # for human-readable console output, not a real protocol detector.
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

def print_payload(payload: bytes):
    # Prints either the decoded text or a hexdump, depending on what
    # identify_payload() guessed, wrapped in a small "-----" separator so
    # it stands out in the console alongside the packet header fields
    # printed by wireshark/capture.py.
    if not payload:
        return

    try:
        payload_type = identify_payload(payload)

        print(f"Tipo        : " f"{payload_type}")

        print()

        if payload_type == "Texto UTF-8":
            print("Conteúdo")
            print("-" * 40)
            print(payload.decode("utf-8",errors="replace"))
            print("-" * 40)

        else:
            print("Hexdump")
            print("-" * 40)
            hexdump(payload)
            print("-" * 40)

    except Exception as e:
        # Defensive fallback: if anything above raises unexpectedly, still
        # show a hexdump rather than crashing the sniffer.
        print(f"Erro ao processar payload: {e}")
        print("Hexdump")
        print("-" * 40)
        hexdump(payload)
        print("-" * 40)
