"""How a key is made from another key, which in this domain is always the same way.

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

import hashlib
import hmac


def derive(secret: bytes, message: bytes) -> bytes:
    """A sixteen-byte key from a secret and something in the clear."""
    hash_block, length = 64, 16
    secret = bytes(secret)[:hash_block]
    return hmac.new(secret, bytes(message), hashlib.sha1).digest()[:length]
