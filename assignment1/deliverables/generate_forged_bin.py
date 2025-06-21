#!/usr/bin/env python3
"""
generate_forged_bin.py

Takes the two-line output from HashPump (Windows or Linux) and
packs it into a binary file forged.bin:

  [16-byte MD5 MAC][forged-payload-bytes]

Usage:
  1. Run hashpump and capture its two-line output:
       dec3fcbc4323eab0e2659229a24a4c2500000000
       CMD=SET_QUOTA&USER=bob&LIMIT=100\x80\x00...\x00&CMD=GRANT_ADMIN&USER=attacker
  2. Paste those lines into mac_hex and payload_str below.
  3. Run this script:
       python3 generate_forged_bin.py
  4. forged.bin will be created in the current directory.
"""

from binascii import unhexlify

# === PASTE YOUR HASHPUMP OUTPUT HERE =======================
# First line: hashpump's signature (hex). May include extra zeros at end.
mac_hex = "dec3fcbc4323eab0e2659229a24a4c2500000000"

# Second line: the exact forged message, including Python-style \x.. escapes.
payload_str = (
    "CMD=SET_QUOTA&USER=bob&LIMIT=100"
    "\x80\x00\x00\x00\xa0\x01\x00\x00\x00\x00\x00\x00"
    "&CMD=GRANT_ADMIN&USER=attacker"
)
# ============================================================

def main():
    # Trim to exactly 16 bytes (32 hex chars) in case mac_hex is longer
    mac_hex_clean = mac_hex.strip()[:32]
    try:
        mac_bytes = unhexlify(mac_hex_clean)
    except Exception as e:
        print(f"Error decoding MAC hex (‘{mac_hex_clean}’): {e}")
        return 1

    # Encode the payload exactly as raw bytes
    payload_bytes = payload_str.encode("latin1", errors="strict")

    # Write out forged.bin
    out_path = "forged.bin"
    try:
        with open(out_path, "wb") as f:
            f.write(mac_bytes)
            f.write(payload_bytes)
        print(f"[✓] Wrote {len(mac_bytes)}-byte MAC + {len(payload_bytes)}-byte payload → {out_path}")
    except IOError as e:
        print(f"Error writing {out_path}: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
