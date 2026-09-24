"""The five security files, opened under whatever key fits and sealed for one console.

`crl.bin`, `dae.bin`, `extended.bin`, `secdata.bin` and `fcrt.bin` go into every image
as files. A release ships two of them inside its update container under a generic key --
the XEX key -- and a console carries all five in its own flash under its own. A build
takes the content from one place and the sealing parameters from another, and four
schemes cover the five:

    crl.bin       a signed record: AES-128-CBC under a file key, which is itself kept
                  wrapped under the master key at 0x130, with the vector at 0x120
    dae.bin       a chain of the same records, each sealed directly under the master
                  key from 0x130 with a zero vector
    extended.bin  the keyvault's scheme: sixteen bytes of nonce, then RC4 under
                  HMAC(cpu key, nonce)
    secdata.bin   likewise
    fcrt.bin      a 0x140 header, then AES-128-CBC under the CPU key with the vector at
                  0x100 -- and a copy that is already sealed is carried as it stands

Every rule here was measured by x360mcp, mostly by opening both sides of a build and
diffing the plaintexts, and several by reading the original's code; the addresses are
kept beside the rules they came from. Each is then held here against the files of the
reference images, byte for byte.

**Where things come from, for a build from a dump:**

    content     crl and dae from the update container; extended, secdata and fcrt from
                the dump. The container has no copy of the other three.
    parameters  the console's own copies, out of its dump: crl's vector and file key,
                dae's seven-byte head and the sixteen its header carries at 0x120,
                secdata's eight-byte head. extended.bin's head is the **keyvault's**.
    the clock   a Windows FILETIME at the head of three of the plaintexts, which is the
                build's own time and not the console's
    lockdown    one byte in three of them, the console's value unless `cfldv` says

**Nothing here is drawn on a build from a dump.** Two nonces are derived rather than
drawn -- extended's and secdata's, each an HMAC over its own plaintext -- and
everything else is the console's. That is what makes a build reproducible, and it was
found the hard way: while those were thought to be drawn, every comparison handed the
reference's own bytes in, and a handed-in drawn value looks exactly like a derived one.
"""

from __future__ import annotations

import hashlib
import math

from ..crypto import aes
from ..crypto.keys import derive
from ..crypto.rc4 import rc4

# The generic key a release ships these under. Not a secret: the XEX key, which the
# original prints at startup and keeps beside the CPU key at 0x47A12C.
XEX_KEY = bytes.fromhex("20B185A59D28FDC340583FBB0896BF91")

# The layout of a signed record, which crl.bin is one of and dae.bin a chain of.
IV_AT = 0x120
WRAPPED_KEY_AT = 0x130
BODY_AT = 0x140
DAE_BODY_AT = 0x130

# The eight bytes of head every keyvault-style plaintext begins with.
HEAD_LENGTH = 8
NONCE_LENGTH = 0x10


def stamp(when: int) -> bytes:
    """The eight bytes of clock the original writes: a FILETIME, big-endian.

    Measured against a frozen clock: `(time() + 2) * 10_000_000 + the FILETIME epoch`,
    with nothing below the second. The two seconds are the original's and are reproduced
    rather than explained.
    """
    return ((when + 2 + 11644473600) * 10_000_000).to_bytes(8, "big")


def when_in(plain: bytes) -> int:
    """The build time a plaintext's stamp says, which is `stamp` the other way round."""
    return int.from_bytes(plain[:8], "big") // 10_000_000 - 11644473600 - 2


def _unwrapped(blob: bytes, master: bytes) -> bytes:
    """A signed record's own key, taken out from under the master key."""
    return aes.decrypt_block(aes.expand(master), blob[WRAPPED_KEY_AT:BODY_AT])


def _states_its_length(body: bytes) -> bool:
    """Whether a crl body opened: past the stamp it states its own length, and fits."""
    stated = int.from_bytes(body[0x10:0x14], "big")
    return 0 < stated <= len(body)


def opened_crl(blob: bytes, cpu_key: bytes) -> tuple:
    """A crl.bin's plaintext body and the master key that opened it.

    The console's key is tried first and the shipped one second -- the order the
    original tries them in and says out loud: "crl appears crypted, attempting to
    decrypt with CPU key...failed! Trying alternate key...success!".
    """
    for master in (cpu_key, XEX_KEY):
        body = aes.cbc_decrypt(_unwrapped(blob, master), blob[BODY_AT:],
                               blob[IV_AT:IV_AT + aes.BLOCK])
        if _states_its_length(body):
            return body, master
    raise ValueError(
        "neither this console's key nor the shipped one opens this crl.bin"
    )


def crl_parameters(own: bytes, cpu_key: bytes) -> tuple:
    """The vector and file key a console's own crl.bin was sealed under."""
    if opened_crl(own, cpu_key)[1] != cpu_key:
        raise ValueError("the console's own crl.bin does not open under its own key, "
                         "so its sealing parameters cannot be carried")
    return own[IV_AT:IV_AT + aes.BLOCK], _unwrapped(own, cpu_key)


def crl(content: bytes, cpu_key: bytes, when: int, ldv: int, iv: bytes,
        file_key: bytes) -> bytes:
    """crl.bin: a body opened, restamped and sealed under a vector and file key.

    The header -- magic, hash, signature -- is the content's and is carried. The body is
    opened, gets the build's stamp at 0 and the lockdown value at 0x0F, and is sealed
    under the vector and file key given: the console's own, out of its dump -- "a 17559
    build takes crl.bin's body out of the update container and still seals it under the
    vector and file key sitting in the copy the console already had" -- or the ones
    compiled into the original, under `nosecurity`.
    """
    body, _ = opened_crl(content, cpu_key)
    plain = bytearray(body)
    plain[0:8] = stamp(when)
    plain[0x0F] = ldv & 0xFF
    out = bytearray(content[:BODY_AT])
    out[IV_AT:IV_AT + aes.BLOCK] = iv
    out[WRAPPED_KEY_AT:BODY_AT] = aes.encrypt_block(aes.expand(cpu_key), file_key)
    return bytes(out) + aes.cbc_encrypt(file_key, bytes(plain), iv)


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


def _dae_opened_by(blob: bytes, cpu_key: bytes) -> bytes:
    """Which master key opens a dae.bin, told apart by entropy.

    It has no length word in the clear to check, and its plaintext is dense: about 6.5
    under the right key against 7.6 under the wrong one.
    """
    best, best_entropy = None, 8.0
    first = blob[:records(blob)[0][1]]
    for master in (cpu_key, XEX_KEY):
        body = aes.cbc_decrypt(master, first[DAE_BODY_AT:], bytes(aes.BLOCK))[:2048]
        counts = [0] * 256
        for byte in body:
            counts[byte] += 1
        entropy = -sum(n / len(body) * math.log2(n / len(body)) for n in counts if n)
        if entropy < best_entropy:
            best, best_entropy = master, entropy
    if best is None or best_entropy > 7.0:
        raise ValueError("neither key opens this dae.bin")
    return best


def dae_parameters(own: bytes, cpu_key: bytes) -> tuple:
    """The seven bytes of head and sixteen of field a console's own dae.bin carries.

    Read out of the original by x360mcp: at 0x40D298 it takes the copy it has just
    opened, adds 0x120, and copies thirty-two bytes -- the header's field and the first
    sixteen of the opened body, whose bytes 8 to 0x0E are the head.
    """
    if _dae_opened_by(own, cpu_key) != cpu_key:
        raise ValueError("the console's own dae.bin does not open under its own key, "
                         "so its head and field cannot be carried")
    first = own[:records(own)[0][1]]
    plain = aes.cbc_decrypt(cpu_key, first[DAE_BODY_AT:], bytes(aes.BLOCK))
    return plain[0x08:0x0F], own[0x120:0x130]


def dae(content: bytes, cpu_key: bytes, when: int, ldv: int, head: bytes,
        field: bytes) -> bytes:
    """dae.bin: a chain of records, each resealed under the console's key.

    Record by record, because each has its own zero vector. The first 0x20 bytes of
    every record's body are a preamble the build rewrites, from 0x41DFA0:

        0x00  the stamp
        0x08  seven bytes of head
        0x0F  the lockdown value
        0x10  HMAC(cpu key, field + plain[0:0x10])

    and the sixteen bytes of header at 0x120, the "field", go in with bit 0 of their
    second byte set -- `or BYTE [ebx+0x121],1` -- which every image measured shows. The
    head and field are the console's own, or the ones compiled into the original under
    `nosecurity`. The content behind the preamble is untouched, which is why the hash
    each record carries stays true.
    """
    master = _dae_opened_by(content, cpu_key)
    field = bytearray(field)
    field[1] |= 0x01
    out = bytearray()
    for at, length in records(content):
        record = content[at:at + length]
        plain = bytearray(aes.cbc_decrypt(master, record[DAE_BODY_AT:],
                                          bytes(aes.BLOCK)))
        plain[0:8] = stamp(when)
        plain[0x08:0x0F] = head
        plain[0x0F] = ldv & 0xFF
        plain[0x10:0x20] = derive(cpu_key, bytes(field) + bytes(plain[:0x10]))
        one = bytearray(record[:DAE_BODY_AT])
        one[0x120:0x130] = field
        out += one + aes.cbc_encrypt(cpu_key, bytes(plain), bytes(aes.BLOCK))
    return bytes(out)


# What the original seals with when it is told not to read the dump for these files:
# constants in its own .data, which x360mcp read out and confirmed twice -- by poisoning
# each slot in a copy of the binary and watching the file move, and by finding the
# built image's field back at that address and nowhere else. `nosecurity` is the one
# situation they are used in; the reference images built with it agree to the byte.
#
#   crl.bin      0x44A630 the vector, 0x44A620 the file key
#   dae.bin      0x44A618 the seven-byte head, 0x44A600 the header's field
#   secdata.bin  0x44A5E0 the eight-byte head
COMPILED_IN = {
    "crl.bin": (bytes.fromhex("d97598a6f85d9b867bc43499e33da4aa"),
                bytes.fromhex("c703b932d4077d416052a8135ede6818")),
    "dae.bin": (bytes.fromhex("f424ed2ad36283"),
                bytes.fromhex("a1b2695058f4ed05e580c7ee189a27b5")),
    "secdata.bin": bytes.fromhex("5aa4d1d27de4453e"),
}

# How long a keyvault-style file is when the build makes one up from nothing -- "Making
# up an clean/empty extended.bin!" -- nonce included.
CLEAN_LENGTH = {"extended.bin": 0x4000, "secdata.bin": 0x400}


def _opened_like_a_keyvault(blob: bytes, cpu_key: bytes) -> bytes:
    """extended.bin or secdata.bin, the nonce taken off and the rest opened."""
    return rc4(derive(cpu_key, blob[:NONCE_LENGTH]), blob[NONCE_LENGTH:])


def _sealed_like_a_keyvault(plain: bytes, nonce: bytes, cpu_key: bytes) -> bytes:
    return nonce + rc4(derive(cpu_key, nonce), plain)


def extended(own: bytes | None, keyvault_head: bytes, cpu_key: bytes) -> bytes:
    """extended.bin: the console's own, or a clean one, with the keyvault's head.

    It keeps the keyvault's overflow, and its eight bytes of head are the **keyvault's**
    rather than its own previous copy's -- the two agree on both consoles measured, and
    it holds under `nosecurity` too, where the file itself is made up clean: zeros but
    for that head. No stamp, no lockdown value. Its nonce is `HMAC(cpu key, plaintext +
    07 12)`, exactly as a keyvault's is, so it follows from the content.
    """
    if own is None:
        plain = bytearray(CLEAN_LENGTH["extended.bin"] - NONCE_LENGTH)
    else:
        plain = bytearray(_opened_like_a_keyvault(own, cpu_key))
    plain[:HEAD_LENGTH] = keyvault_head[:HEAD_LENGTH]
    nonce = derive(cpu_key, bytes(plain) + b"\x07\x12")
    return _sealed_like_a_keyvault(bytes(plain), nonce, cpu_key)


def secdata(own: bytes | None, cpu_key: bytes, when: int, ldv: int,
            head: bytes = b"") -> bytes:
    """secdata.bin: the console's own, or a clean one, restamped, its nonce derived.

    Its head is its own previous copy's -- not the keyvault's -- or `head` when one is
    given, which under `nosecurity` is the original's compiled-in one over a file made
    up clean. A one at 0x08 that the build writes whatever was there, the lockdown value
    at 0x09 and the stamp at 0x10. Its nonce is `HMAC(cpu key, plaintext)` with **no**
    two bytes behind it, the one way it differs from extended.bin's -- and a `-norandom`
    build, handed nothing, showed it by coming out with 1,023 of 1,024 bytes different
    while it was thought to be drawn.
    """
    if own is None:
        plain = bytearray(CLEAN_LENGTH["secdata.bin"] - NONCE_LENGTH)
    else:
        plain = bytearray(_opened_like_a_keyvault(own, cpu_key))
    if head:
        plain[:HEAD_LENGTH] = head
    plain[0x08] = 0x01
    plain[0x09] = ldv & 0xFF
    plain[0x10:0x18] = stamp(when)
    nonce = derive(cpu_key, bytes(plain))
    return _sealed_like_a_keyvault(bytes(plain), nonce, cpu_key)


def fcrt(own: bytes, cpu_key: bytes) -> bytes:
    """fcrt.bin: sealed if what was handed over is still in the clear, else carried.

    Whether it is clear is in the file: four bytes at 0x12C are the start of SHA-1 over
    the **decrypted** body, so hashing the body as it stands answers it. Measured both
    ways -- a clear copy is sealed under the CPU key with the vector at 0x100, and
    handed an already sealed copy the original writes it back unchanged rather than
    twice.
    """
    clear = hashlib.sha1(own[0x140:]).digest()[:4] == own[0x12C:0x130]
    if not clear:
        return own
    return own[:0x140] + aes.cbc_encrypt(cpu_key, own[0x140:], own[0x100:0x110])
