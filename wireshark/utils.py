def hexdump(data: bytes, width: int = 16):

    for offset in range(0, len(data), width):

        chunk = data[offset:offset + width]

        hex_bytes = " ".join(
            f"{byte:02X}"
            for byte in chunk
        )

        ascii_bytes = "".join(
            chr(byte) if 32 <= byte <= 126 else "."
            for byte in chunk
        )

        print(
            f"{offset:04X}  "
            f"{hex_bytes:<48}  "
            f"{ascii_bytes}"
        )

def identify_payload(data: bytes):

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

    print(
        f"Payload     : "
        f"{len(payload)} bytes"
    )

    if not payload:
        return

    try:
        payload_type = identify_payload(payload)

        print(
            f"Tipo        : "
            f"{payload_type}"
        )

        print()

        if payload_type == "Texto UTF-8":
            print("Conteúdo")
            print("-" * 40)
            print(
                payload.decode(
                    "utf-8",
                    errors="replace"
                )
            )
            print("-" * 40)

        else:
            print("Hexdump")
            print("-" * 40)
            hexdump(payload)
            print("-" * 40)
    except Exception as e:
        print(f"Erro ao processar payload: {e}")
        print("Hexdump")
        print("-" * 40)
        hexdump(payload)
        print("-" * 40)