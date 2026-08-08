# =============================================================================
# utils/test.py
# -----------------------------------------------------------------------------
# Not an automated test despite the "test" name -- just a scratch/sanity
# script that prints a lock emoji to confirm the interpreter's stdout can
# correctly render UTF-8 / non-ASCII characters (useful when debugging
# console encoding issues on Windows terminals, which is relevant since
# this project ships PowerShell launch scripts).
# =============================================================================

print("\U0001F512")  # 🔒 lock emoji
#print(payload.decode("utf-8", errors="ignore"))
