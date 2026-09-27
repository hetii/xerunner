"""How each thing a flash image carries is encrypted and decrypted, in one place.

Bytes in, bytes out, and nothing else: no stamp, no lockdown value, no choice of where
anything comes from -- that is a build's, and `build.security` and `build.build` do it
with these. The schemes, one per thing:

    keyvault      sixteen bytes of nonce, then RC4 under HMAC(CPU key, nonce); the
                  nonce is HMAC(CPU key, plaintext + 07 12)
    extended.bin  the keyvault's scheme, nonce and all
    secdata.bin   the keyvault's scheme, but its nonce is HMAC(CPU key, plaintext)
                  with nothing behind it
    crl.bin       a signed record: AES-128-CBC under a file key, which is itself kept
                  wrapped under a master key at 0x130, with the vector at 0x120
    dae.bin       a chain of the same records, each under the master key directly with
                  a zero vector
    fcrt.bin      0x4000 bytes: a header, then AES-128-CBC under the CPU key with the
                  vector at 0x100, from where the header's word at 0x11C says
    SMC           its own self-feeding byte stream under a four-byte seed
    bootloader    a stage's body under RC4; its header is never encrypted, and its key
                  is `chain.sealing`'s to derive

The master key a security file opens under is the console's CPU key or, for the two a
release ships inside its update container, the XEX key; the console's is tried first,
as the original does: "crl appears crypted, attempting to decrypt with CPU key...
failed! Trying alternate key...success!".

The primitives underneath are XeCrypt's, each named for its XeCrypt function: `aes`,
`rc4` and `keys`.
"""

import hashlib

from . import aes
from .rc4 import rc4
from .keys import hmacsha

# The generic key a release ships crl.bin and dae.bin under. Not a secret: the XEX key,
# which the original prints at startup and keeps beside the CPU key at 0x47A12C.
XEX_KEY = bytes.fromhex("20B185A59D28FDC340583FBB0896BF91")

# The layout of a signed record, which crl.bin is one of and dae.bin a chain of.
IV_AT = 0x120
WRAPPED_KEY_AT = 0x130
BODY_AT = 0x140
DAE_BODY_AT = 0x130

# The nonce every keyvault-style file begins with.
NONCE_LENGTH = 0x10


# --- the keyvault and the two files sealed its way ---------------------------------

def _decrypt_under_nonce(blob: bytes, cpu_key: bytes) -> bytes:
    """What follows the nonce, opened under HMAC(CPU key, nonce)."""
    return rc4(hmacsha(cpu_key, blob[:NONCE_LENGTH]), blob[NONCE_LENGTH:])


def _encrypt_under_nonce(plain: bytes, nonce: bytes, cpu_key: bytes) -> bytes:
    return nonce + rc4(hmacsha(cpu_key, nonce), plain)


def decrypt_keyvault(sealed: bytes, cpu_key: bytes) -> bytes:
    """A keyvault in the clear, its sixteen bytes of nonce kept at the head as the
    keyvault's own layout counts them. Any key opens it to something; only its own
    opens it to one whose nonce it derives again."""
    sealed = bytes(sealed)
    return sealed[:NONCE_LENGTH] + _decrypt_under_nonce(sealed, cpu_key)


def encrypt_keyvault(plain: bytes, cpu_key: bytes) -> bytes:
    """A keyvault sealed, its nonce derived from what it holds -- so the console's own
    keyvault seals back to its own bytes. The sixteen bytes at the head of `plain` are
    the old nonce's place and are replaced."""
    body = bytes(plain)[NONCE_LENGTH:]
    # 0x07 0x12 is what the derivation takes beyond the plaintext itself.
    return _encrypt_under_nonce(body, hmacsha(cpu_key, body + b"\x07\x12"), cpu_key)


def decrypt_extended(blob: bytes, cpu_key: bytes) -> bytes:
    """extended.bin in the clear, the nonce taken off."""
    return _decrypt_under_nonce(blob, cpu_key)


def encrypt_extended(plain: bytes, cpu_key: bytes) -> bytes:
    """extended.bin sealed; its nonce is HMAC(CPU key, plaintext + 07 12), exactly as a
    keyvault's is."""
    return _encrypt_under_nonce(plain, hmacsha(cpu_key, bytes(plain) + b"\x07\x12"),
                                cpu_key)


def decrypt_secdata(blob: bytes, cpu_key: bytes) -> bytes:
    """secdata.bin in the clear, the nonce taken off."""
    return _decrypt_under_nonce(blob, cpu_key)


def encrypt_secdata(plain: bytes, cpu_key: bytes) -> bytes:
    """secdata.bin sealed; its nonce is HMAC(CPU key, plaintext) with **no** two bytes
    behind it, the one way it differs from extended.bin's -- a `-norandom` build,
    handed nothing, showed it by coming out with 1,023 of 1,024 bytes different while
    it was thought to be drawn."""
    return _encrypt_under_nonce(plain, hmacsha(cpu_key, bytes(plain)), cpu_key)


# --- crl.bin and dae.bin: signed records --------------------------------------------

def vouched(record: bytes, body: bytes, body_at: int) -> bool:
    """Whether a signed record's body, in the clear, is what its header hashes.

    SHA-1 over everything from the record's 0x150 on against the twenty bytes at 0x0C:
    the original's own test for crl.bin at 0x41DCB8 and for each record of dae.bin at
    0x41E2A2, before it decrypts and again after. `body` starts at `body_at` of the
    record -- 0x140 for crl.bin, 0x130 for dae.bin -- and what lies before 0x150 is the
    stamp and preamble a build rewrites, which is why the hash stays true.
    """
    hashed = bytes(body[0x150 - body_at:])
    return hashlib.sha1(hashed).digest() == bytes(record[0x0C:0x20])


def _unwrapped(blob: bytes, master: bytes) -> bytes:
    """A signed record's own key, taken out from under the master key."""
    return aes.decrypt_aesecb(aes.aeskey(master), blob[WRAPPED_KEY_AT:BODY_AT])


def decrypt_crl(blob: bytes, cpu_key: bytes) -> tuple:
    """A crl.bin's body in the clear: `(body, master key, file key)` -- the master that
    opened it, the console's or the XEX key, and the file key it unwrapped -- or
    ValueError where neither opens it."""
    for master in (cpu_key, XEX_KEY):
        file_key = _unwrapped(blob, master)
        body = aes.decrypt_aescbc(file_key, blob[BODY_AT:],
                                  blob[IV_AT:IV_AT + aes.BLOCK])
        if vouched(blob, body, BODY_AT):
            return body, master, file_key
    raise ValueError(
        "neither this console's key nor the shipped one opens this crl.bin"
    )


def encrypt_crl(header: bytes, body: bytes, cpu_key: bytes, iv: bytes,
                file_key: bytes) -> bytes:
    """A crl.bin sealed: the header's first 0x140 bytes carried, the vector put at
    0x120 and the file key wrapped under the CPU key at 0x130, and the body under the
    file key."""
    out = bytearray(header[:BODY_AT])
    out[IV_AT:IV_AT + aes.BLOCK] = iv
    out[WRAPPED_KEY_AT:BODY_AT] = aes.encrypt_aesecb(aes.aeskey(cpu_key), file_key)
    return bytes(out) + aes.encrypt_aescbc(file_key, bytes(body), iv)


def records(blob: bytes) -> list:
    """Where each DAEP record of a dae.bin starts and how long it is.

    The chain is walked by the length each record states at 0x04, as the original does
    at 0x41E1CA -- check the magic, take the length, advance -- and it tiles every
    specimen measured with nothing left over.
    """
    out, at = [], 0
    while at + 0x150 <= len(blob) and blob[at:at + 4] == b"DAEP":
        length = int.from_bytes(blob[at + 4:at + 6], "big")
        if length < 0x150 or at + length > len(blob):
            break
        out.append((at, length))
        at += length
    return out


def _decrypt_dae_record(record: bytes, cpu_key: bytes) -> tuple:
    """One record's body in the clear and the key that opened it -- None for a record
    already in the clear -- or ValueError.

    In the clear if the header's hash vouches for it as it stands; otherwise opened
    under the console's key and then the XEX key, each with its own zero vector, and
    taken when the hash vouches (0x41E1CA).
    """
    if vouched(record, record[DAE_BODY_AT:], DAE_BODY_AT):
        return record[DAE_BODY_AT:], None
    for master in (cpu_key, XEX_KEY):
        body = aes.decrypt_aescbc(master, record[DAE_BODY_AT:], bytes(aes.BLOCK))
        if vouched(record, body, DAE_BODY_AT):
            return body, master
    raise ValueError("neither key opens this dae.bin")


def decrypt_dae(blob: bytes, cpu_key: bytes) -> list:
    """Every record of a dae.bin in the clear, in order: `(header, body, master key)`,
    the header being the record's first 0x130 bytes. Record by record, because each
    has its own zero vector; ValueError where any one does not open, and where the
    records do not cover the whole file -- the original stops at the first header that
    is not a record's, "dae segment does not have the expected header!" (0x41E1D9),
    and takes the file for one it cannot open."""
    found = records(blob)
    if not found or sum(length for _at, length in found) != len(blob):
        raise ValueError("dae segment does not have the expected header")
    out = []
    for at, length in found:
        record = blob[at:at + length]
        body, master = _decrypt_dae_record(record, cpu_key)
        out.append((record[:DAE_BODY_AT], body, master))
    return out


def encrypt_dae(opened: list, cpu_key: bytes) -> bytes:
    """A dae.bin sealed from `(header, body)` pairs: each body under the CPU key with a
    zero vector, behind its header."""
    out = bytearray()
    for header, body in opened:
        out += bytes(header) + aes.encrypt_aescbc(cpu_key, bytes(body),
                                                  bytes(aes.BLOCK))
    return bytes(out)


# --- fcrt.bin ------------------------------------------------------------------------

def fcrt_body_at(blob: bytes) -> int:
    """Where fcrt.bin's sealed part starts: the big-endian word its header keeps at
    0x11C, which the original reads rather than assumes (0x41E685, 0x402850). 0x140
    in every copy measured."""
    return int.from_bytes(blob[0x11C:0x120], "big")


def decrypt_fcrt(blob: bytes, cpu_key: bytes) -> bytes:
    """fcrt.bin's sealed part in the clear, from `fcrt_body_at` to the end."""
    return aes.decrypt_aescbc(cpu_key, blob[fcrt_body_at(blob):], blob[0x100:0x110])


def encrypt_fcrt(blob: bytes, cpu_key: bytes) -> bytes:
    """fcrt.bin sealed: everything before `fcrt_body_at` carried, the rest under the CPU
    key with the vector at 0x100."""
    at = fcrt_body_at(blob)
    return blob[:at] + aes.encrypt_aescbc(cpu_key, blob[at:], blob[0x100:0x110])


# --- the SMC -------------------------------------------------------------------------
# Nothing like the rest. A byte-at-a-time stream whose key is four 32-bit accumulators,
# each byte that comes out feeding the two after it, so the stream depends on
# everything already written. No key material from outside: the accumulators start
# from the same four bytes in every image, and what makes one image's stream differ is
# the four bytes at its head -- a seed, stored in the clear, and **not** the
# plaintext's first four bytes, which are discarded. Measured both ways on three images
# the original built from a plaintext of this side's choosing and on two real
# consoles' dumps. The seed is per image: the two consoles carry `fbd75a10` and
# `4552c477`, and the original under `-norandom` writes `cc7ac1e7`.

SMC_KEY = (0x42, 0x75, 0x4E, 0x79)
SEED_LENGTH = 4


def _advanced(keys: list, index: int, cipher: int) -> None:
    """Feed one sealed byte back into the two accumulators after it."""
    mask = 0xFFFFFFFF
    # The byte is multiplied before it is fed in, and the two accumulators take the
    # two halves of that product: the one after this byte's takes the low half, the one
    # after that the high half.
    product = cipher * 0xFB
    keys[(index + 1) & 3] = (keys[(index + 1) & 3] + product) & mask
    keys[(index + 2) & 3] = (keys[(index + 2) & 3] + (product >> 8)) & mask


def decrypt_smc(sealed: bytes) -> bytes:
    """An SMC image as it runs, out of the bytes flash holds.

    The whole buffer comes back, its own length. **Its first four bytes are not
    plaintext** -- they are what the seed happens to decrypt to, and nothing means
    anything by them. Everything that identifies or patches an SMC counts from four.
    """
    keys, out = list(SMC_KEY), bytearray(len(sealed))
    for index, cipher in enumerate(sealed):
        out[index] = cipher ^ (keys[index & 3] & 0xFF)
        _advanced(keys, index, cipher)
    return bytes(out)


def encrypt_smc(plain: bytes, seed: bytes) -> bytes:
    """An SMC image as flash holds it, under a seed of the caller's choosing.

    The plaintext's first four bytes go nowhere: the seed takes their place, and the
    accumulators advance over the seed before the first real byte is reached. Which is
    the whole reason two images of the same SMC under different seeds share no bytes.
    """
    if len(seed) != SEED_LENGTH:
        raise ValueError(
            "an SMC's seed is %d bytes and this is %d" % (SEED_LENGTH, len(seed))
        )
    if len(plain) < SEED_LENGTH:
        raise ValueError("an SMC is longer than its seed; this one is %d" % len(plain))
    keys, out = list(SMC_KEY), bytearray(len(plain))
    for index in range(SEED_LENGTH):
        out[index] = seed[index]
        _advanced(keys, index, seed[index])
    for index in range(SEED_LENGTH, len(plain)):
        cipher = plain[index] ^ (keys[index & 3] & 0xFF)
        out[index] = cipher
        _advanced(keys, index, cipher)
    return bytes(out)


# --- bootloader stages -------------------------------------------------------------

def decrypt_bootloader(body: bytes, key: bytes) -> bytes:
    """A bootloader stage's body in the clear under its key. RC4, so the same run over
    it either way; the header in front of it is never encrypted, and the key --
    HMAC over a secret and the stage's nonce, or a chain's -- is `chain.sealing`'s."""
    return rc4(key, body)


def encrypt_bootloader(body: bytes, key: bytes) -> bytes:
    """A bootloader stage's body sealed under its key -- see `decrypt_bootloader`."""
    return rc4(key, body)
