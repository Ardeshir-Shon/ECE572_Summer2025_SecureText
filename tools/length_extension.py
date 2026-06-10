#!/usr/bin/env python3
"""
Reference length-extension attack against the flawed MAC  MAC(k, m) = MD5(k || m).

This is provided for Assignment 1, Task 3, Part C so that you don't lose a day
fighting with `hash_extender` (needs compiling from source) or `HashPump`
(stale, often won't build on current systems). You may use this, the maintained
`hashpumpy` pip package, or your own implementation -- but you must understand
why the attack works and be able to explain it.

WHY IT WORKS
------------
MD5 is a Merkle-Damgard hash. It processes the message in 512-bit blocks,
folding each block into a 128-bit internal state. The final state IS the digest
-- nothing is done to "close it off." So if you know MD5(k || m), you know the
internal state of the hash *after* it absorbed (k || m) plus MD5's padding. You
can set MD5's registers to that state and keep hashing additional bytes, exactly
as if the original hasher had continued. The result is a valid digest for

    k || m || glue_padding || suffix

without ever knowing k. You only need to know len(k) (or guess it -- the script
makes that easy to brute force).

This file deliberately implements MD5 from scratch, because Python's hashlib
won't let you resume from a chosen internal state. Read `_md5_compress` and
`forge` together: the attack is the last ~15 lines, the rest is just MD5.

Usage as a library:
    from length_extension import forge, md5_mac
    forged_msg, forged_mac = forge(original_msg, original_mac, suffix, key_len)

Run `python3 length_extension.py` to see the self-test (it forges a MAC and
verifies it against a real secret key the "attacker" half never sees).
"""

import struct
import hashlib

# ---------------------------------------------------------------------------
# MD5 from scratch, written so the internal state can be set by the attacker.
# ---------------------------------------------------------------------------

_S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
_K = [int(abs(__import__("math").sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
_MASK = 0xFFFFFFFF


def _rotl(x, c):
    return ((x << c) | (x >> (32 - c))) & _MASK


def _md5_compress(state, block):
    """Fold one 512-bit block into the four-word state (the MD5 round function)."""
    a, b, c, d = state
    m = struct.unpack("<16I", block)
    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d)
            g = i
        elif i < 32:
            f = (d & b) | (~d & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | ~d)
            g = (7 * i) % 16
        f = (f + a + _K[i] + m[g]) & _MASK
        a, d, c = d, c, b
        b = (b + _rotl(f, _S[i])) & _MASK
    return [(state[0] + a) & _MASK, (state[1] + b) & _MASK,
            (state[2] + c) & _MASK, (state[3] + d) & _MASK]


def _md_padding(msg_len):
    """The 1-bit, zeros, and 64-bit length that MD5 appends to a message of msg_len bytes."""
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack("<Q", (msg_len * 8) & 0xFFFFFFFFFFFFFFFF)
    return pad


def md5_from_state(state, tail, prior_len_bytes):
    """
    Continue an MD5 whose internal state is `state`, having already absorbed
    `prior_len_bytes` bytes (the original (k||m) plus its glue padding), then
    hash `tail` and return the final hex digest.
    """
    # Everything before `tail` is a whole number of blocks, so only `tail`
    # plus the final length field remains to be processed.
    msg = tail
    total_len = prior_len_bytes + len(tail)
    msg += _md_padding(total_len)
    for off in range(0, len(msg), 64):
        state = _md5_compress(state, msg[off:off + 64])
    return "".join(struct.pack("<I", w).hex() for w in state)


def md5_mac(key, message):
    """The flawed MAC the assignment attacks:  MD5(key || message)."""
    if isinstance(message, str):
        message = message.encode()
    if isinstance(key, str):
        key = key.encode()
    return hashlib.md5(key + message).hexdigest()


# ---------------------------------------------------------------------------
# The attack.
# ---------------------------------------------------------------------------

def forge(original_message, original_mac, suffix, key_len):
    """
    Given MAC = MD5(key || original_message), produce (forged_message, forged_mac)
    such that  MD5(key || forged_message) == forged_mac, without knowing the key.

    key_len is the byte length of the secret key (brute-force it if unknown).
    Returns the forged message as bytes (it contains the binary glue padding).
    """
    if isinstance(original_message, str):
        original_message = original_message.encode()
    if isinstance(suffix, str):
        suffix = suffix.encode()

    # Recover the hash state the original MAC left off in.
    state = list(struct.unpack("<4I", bytes.fromhex(original_mac)))

    # The original hasher saw (key || original_message), then padded it.
    glue = _md_padding(key_len + len(original_message))
    prior_len = key_len + len(original_message) + len(glue)  # a multiple of 64

    forged_mac = md5_from_state(state, suffix, prior_len)
    forged_message = original_message + glue + suffix
    return forged_message, forged_mac


def _self_test():
    secret = b"super-secret-shared-key"          # the attacker never sees this
    original = b"CMD=SET_QUOTA&USER=bob&LIMIT=100"
    suffix = b"&CMD=GRANT_ADMIN&USER=attacker"

    # Server computes the legitimate MAC; attacker captures (original, mac) on the wire.
    captured_mac = md5_mac(secret, original)

    # Attacker forges, knowing only original, captured_mac, suffix, and len(secret).
    forged_message, forged_mac = forge(original, captured_mac, suffix, len(secret))

    # Server verifies the forgery by recomputing the MAC over key || forged_message.
    server_recompute = md5_mac(secret, forged_message)

    print("original message :", original)
    print("captured MAC     :", captured_mac)
    print("forged message   :", forged_message)
    print("forged MAC       :", forged_mac)
    print("server recompute :", server_recompute)
    ok = (forged_mac == server_recompute) and (b"GRANT_ADMIN" in forged_message)
    print("\nFORGERY VALID   :", ok)
    if not ok:
        raise SystemExit("self-test FAILED")

    # Also brute-force the key length the way a real attacker would (1..40 bytes).
    for guess in range(1, 41):
        fm, fmac = forge(original, captured_mac, suffix, guess)
        if md5_mac(secret, fm) == fmac:
            print(f"brute-forced key length: {guess} (true length {len(secret)})")
            break


if __name__ == "__main__":
    _self_test()
