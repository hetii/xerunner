"""How a key is made from another key, and the two things XeCrypt does to a key itself.

Every sealed thing in a flash image -- each bootloader stage, the keyvault, the files
that carry a console's own secrets -- is unwrapped with a key derived rather than
stored: HMAC-SHA1 over something that is in the clear, keyed with something that is
not, cut to sixteen bytes. The console calls it `XeCryptHmacSha`.

It parts company with the HMAC in any standard library in one place, and only for input
this code has never been handed: a key longer than the hash's own block is **truncated**
to it here, where the standard hashes it down first. Read out of `xecrypt.c`, released
with xeBuild's source in September 2026. Every key in this domain is sixteen bytes, so
the two agree on everything real; the truncation is done anyway, because a difference
that only shows on input nobody has passed yet is exactly the kind that surfaces later.
"""

from __future__ import annotations

import hmac
import hashlib


def hmacsha(secret: bytes, message: bytes) -> bytes:
    """A sixteen-byte key from a secret and something in the clear. XeCrypt's
    `XeCryptHmacSha`."""
    hash_block, length = 64, 16
    secret = bytes(secret)[:hash_block]
    return hmac.new(secret, bytes(message), hashlib.sha1).digest()[:length]


def hammingweight(data: bytes) -> int:
    """How many bits of `data` are set. XeCrypt's `XeCryptHammingWeight`."""
    return sum(bin(one).count("1") for one in bytes(data))


def uideccencode(key: bytes) -> bytes:
    """A CPU key with its 22 check bits recomputed from its 106 key bits: the key
    itself where the check bits are right. XeCrypt's `XeCryptUidEccEncode`
    (`xecrypt.c`, released with xeBuild's source), which J-Runner spells out too."""
    out, one, parity = bytearray(key), 0, 0
    for at in range(0x6A):
        bit = (out[at >> 3] >> (at & 7)) & 1
        one ^= bit
        one ^= (one & 1) * 0x360325
        parity ^= bit
        one >>= 1
    for at in range(0x6A, 0x7F):
        bit = (out[at >> 3] >> (at & 7)) & 1
        low = one & 1
        out[at >> 3] ^= ((bit ^ low) & 1) << (at & 7)
        parity ^= low
        one >>= 1
    bit = (out[15] >> 7) & 1
    out[15] ^= ((bit ^ (parity & 1)) & 1) << 7
    return bytes(out)
