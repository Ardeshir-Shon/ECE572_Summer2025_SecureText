#!/usr/bin/env python3
"""
Reference length-extension attack against the flawed MAC  MAC(k, m) = SHA-256(k || m).

This matches the length-extension example in the course notes (the
`X-Auth: SHA256(secret_key || path || query || body)` construction). It is provided for
Assignment 1, Task 3, Part C so that you don't lose a day fighting with `hash_extender`
(needs compiling from source) or `HashPump` (stale, often won't build on current systems).
You may use this, the maintained `hashpumpy` pip package, or your own implementation -- but
you must understand why the attack works and be able to explain it.

WHY IT WORKS
------------
SHA-256 is a Merkle-Damgard hash. It processes the message in 512-bit blocks, folding each
block into a 256-bit internal state (eight 32-bit words). The final state IS the digest --
nothing is done to "close it off." So if you know SHA-256(k || m), you know the internal
state of the hash *after* it absorbed (k || m) plus SHA-256's padding. You can set the
eight state words to that digest and keep hashing additional bytes, exactly as if the
original hasher had continued. The result is a valid digest for

    k || m || glue_padding || suffix

without ever knowing k. You only need to know len(k) (or guess it -- the script makes that
easy to brute force).

This file deliberately implements SHA-256 from scratch, because Python's hashlib won't let
you resume from a chosen internal state. Read `_sha256_compress` and `forge` together: the
attack is the last ~15 lines, the rest is just SHA-256. (Note SHA-256 is big-endian and
appends a 64-bit big-endian bit length; MD5 was little-endian -- that's the only structural
difference relevant here.)

Usage as a library:
    from length_extension import forge, sha256_mac
    forged_msg, forged_mac = forge(original_msg, original_mac, suffix, key_len)

Run `python3 length_extension.py` to see the self-test (it forges a MAC and verifies it
against a real secret key the "attacker" half never sees).
"""

import struct
import hashlib

# ---------------------------------------------------------------------------
# SHA-256 from scratch, written so the internal state can be set by the attacker.
# ---------------------------------------------------------------------------

# Initial hash values: first 32 bits of the fractional parts of the square roots
# of the first 8 primes.
_H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# Round constants: first 32 bits of the fractional parts of the cube roots of the
# first 64 primes.
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

_MASK = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK


def _sha256_compress(state, block):
    """Fold one 512-bit block into the eight-word state (the SHA-256 round function)."""
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK)

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _K[i] + w[i]) & _MASK
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _MASK
        h, g, f = g, f, e
        e = (d + t1) & _MASK
        d, c, b = c, b, a
        a = (t1 + t2) & _MASK

    return [(state[i] + v) & _MASK for i, v in enumerate((a, b, c, d, e, f, g, h))]


def _sha_padding(msg_len):
    """The 1-bit, zeros, and 64-bit BIG-endian length SHA-256 appends to a msg_len-byte message."""
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack(">Q", (msg_len * 8) & 0xFFFFFFFFFFFFFFFF)
    return pad


def sha256_from_state(state, tail, prior_len_bytes):
    """
    Continue a SHA-256 whose internal state is `state`, having already absorbed
    `prior_len_bytes` bytes (the original (k||m) plus its glue padding), then hash `tail`
    and return the final hex digest.
    """
    # Everything before `tail` is a whole number of blocks, so only `tail` plus the final
    # length field remains to be processed.
    msg = tail
    total_len = prior_len_bytes + len(tail)
    msg += _sha_padding(total_len)
    for off in range(0, len(msg), 64):
        state = _sha256_compress(state, msg[off:off + 64])
    return "".join(struct.pack(">I", word).hex() for word in state)


def sha256_mac(key, message):
    """The flawed MAC the assignment attacks:  SHA-256(key || message)."""
    if isinstance(message, str):
        message = message.encode()
    if isinstance(key, str):
        key = key.encode()
    return hashlib.sha256(key + message).hexdigest()


# ---------------------------------------------------------------------------
# The attack.
# ---------------------------------------------------------------------------

def forge(original_message, original_mac, suffix, key_len):
    """
    Given MAC = SHA-256(key || original_message), produce (forged_message, forged_mac)
    such that  SHA-256(key || forged_message) == forged_mac, without knowing the key.

    key_len is the byte length of the secret key (brute-force it if unknown).
    Returns the forged message as bytes (it contains the binary glue padding).
    """
    if isinstance(original_message, str):
        original_message = original_message.encode()
    if isinstance(suffix, str):
        suffix = suffix.encode()

    # Recover the hash state the original MAC left off in (8 big-endian 32-bit words).
    state = list(struct.unpack(">8I", bytes.fromhex(original_mac)))

    # The original hasher saw (key || original_message), then padded it.
    glue = _sha_padding(key_len + len(original_message))
    prior_len = key_len + len(original_message) + len(glue)  # a multiple of 64

    forged_mac = sha256_from_state(state, suffix, prior_len)
    forged_message = original_message + glue + suffix
    return forged_message, forged_mac


def _self_test():
    secret = b"super-secret-shared-key"          # the attacker never sees this
    original = b"CMD=SET_QUOTA&USER=bob&LIMIT=100"
    suffix = b"&CMD=GRANT_ADMIN&USER=attacker"

    # Server computes the legitimate MAC; attacker captures (original, mac) on the wire.
    captured_mac = sha256_mac(secret, original)

    # Attacker forges, knowing only original, captured_mac, suffix, and len(secret).
    forged_message, forged_mac = forge(original, captured_mac, suffix, len(secret))

    # Server verifies the forgery by recomputing the MAC over key || forged_message.
    server_recompute = sha256_mac(secret, forged_message)

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
        if sha256_mac(secret, fm) == fmac:
            print(f"brute-forced key length: {guess} (true length {len(secret)})")
            break


if __name__ == "__main__":
    _self_test()
