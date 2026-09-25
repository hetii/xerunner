"""The five security files, opened under whatever key fits and sealed for one console.

`crl.bin`, `dae.bin`, `extended.bin`, `secdata.bin` and `fcrt.bin` go into every image
as files. A release ships two of them inside its update container under a generic key --
the XEX key -- and a console carries all five in its own flash under its own. A build
takes the content from one place and the sealing parameters from another. How each is
encrypted is `crypto.formats`'s; what goes into them -- the stamp, the lockdown value,
the console's own parameters -- is this module's.

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

import hashlib
import logging

from ..crypto import aes
from ..crypto.keys import hmacsha
from ..crypto.formats import decrypt_extended, decrypt_fcrt, decrypt_secdata
from ..crypto.formats import encrypt_secdata, fcrt_body_at, records, vouched
from ..crypto.formats import BODY_AT, IV_AT, NONCE_LENGTH, decrypt_crl, decrypt_dae
from ..crypto.formats import encrypt_crl, encrypt_dae, encrypt_extended, encrypt_fcrt

logger = logging.getLogger(__name__)

# The eight bytes of head every keyvault-style plaintext begins with.
HEAD_LENGTH = 8


def stamp(when: int) -> bytes:
    """The eight bytes of clock the original writes: a FILETIME, big-endian.

    `time() + 2`, and then down to an even second -- the directory's FAT time, which
    counts seconds in twos, turned back into a FILETIME. Measured against a frozen
    clock both ways: at 0x5A123456 the stamp says 0x5A123458, and at 0x5A123457 the
    same, in build mode and in update mode. The two seconds are the original's and are
    reproduced rather than explained.
    """
    return ((((when + 2) & ~1) + 11644473600) * 10_000_000).to_bytes(8, "big")


def when_in(plain: bytes) -> int:
    """The build time a plaintext's stamp says, which is `stamp` the other way round --
    to the even second the stamp keeps."""
    return int.from_bytes(plain[:8], "big") // 10_000_000 - 11644473600 - 2


def crl_parameters(own: bytes, cpu_key: bytes) -> tuple:
    """The vector and file key a console's own crl.bin was sealed under."""
    _body, master, file_key = decrypt_crl(own, cpu_key)
    if master != cpu_key:
        raise ValueError("the console's own crl.bin does not open under its own key, "
                         "so its sealing parameters cannot be carried")
    return own[IV_AT:IV_AT + aes.BLOCK], file_key


def crl(content: bytes, cpu_key: bytes, when: int, ldv: int, iv: bytes,
        file_key: bytes, clear: bool = False) -> bytes:
    """crl.bin: a body opened, restamped and sealed under a vector and file key.

    The header -- magic, hash, signature -- is the content's and is carried. The body is
    opened, gets the build's stamp at 0 and the lockdown value at 0x0F, and is sealed
    under the vector and file key given: the console's own, out of its dump -- "a 17559
    build takes crl.bin's body out of the update container and still seals it under the
    vector and file key sitting in the copy the console already had" -- or the ones
    compiled into the original, under `nosecurity`.
    """
    body = content[BODY_AT:] if clear else decrypt_crl(content, cpu_key)[0]
    plain = bytearray(body)
    plain[0:8] = stamp(when)
    plain[0x0F] = ldv & 0xFF
    return encrypt_crl(content, bytes(plain), cpu_key, iv, file_key)


def dae_parameters(own: bytes, cpu_key: bytes) -> tuple:
    """The seven bytes of head and sixteen of field a console's own dae.bin carries.

    Read out of the original by x360mcp: at 0x40D298 it takes the copy it has just
    opened, adds 0x120, and copies thirty-two bytes -- the header's field and the first
    sixteen of the opened body, whose bytes 8 to 0x0E are the head.
    """
    found = records(own)
    if not found:
        raise ValueError("this is no dae.bin")
    _header, plain, master = decrypt_dae(own[:found[0][1]], cpu_key)[0]
    if master != cpu_key:
        raise ValueError("the console's own dae.bin does not open under its own key, "
                         "so its head and field cannot be carried")
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
    field = bytearray(field)
    field[1] |= 0x01
    out = []
    for header, body, _master in decrypt_dae(content, cpu_key):
        plain = bytearray(body)
        plain[0:8] = stamp(when)
        plain[0x08:0x0F] = head
        plain[0x0F] = ldv & 0xFF
        plain[0x10:0x20] = hmacsha(cpu_key, bytes(field) + bytes(plain[:0x10]))
        one = bytearray(header)
        one[0x120:0x130] = field
        out.append((bytes(one), bytes(plain)))
    return encrypt_dae(out, cpu_key)


# The staging area the original keeps its drawn material in, with what it was compiled
# with: twelve buffers in its .data, from file offset 0x491E0. `init_nonces` (0x41AA00)
# draws over all twelve unless `-norandom` or a finished nonce walk over the dump has
# cleared its flag, and reading the console's own files overwrites the ones it can --
# so each value is drawn, the console's, or this, in that order of precedence. See
# `Build.drawing`. x360mcp read them out and confirmed each twice: by poisoning the slot
# in a copy of the binary and watching the image move, and by building with `-norandom`
# and finding every one of them back in the image.
#
#   crl.bin      0x44A630 the vector, 0x44A620 the file key
#   dae.bin      0x44A618 the seven-byte head, 0x44A600 the header's field
#   secdata.bin  0x44A5E0 the eight-byte head
#   kv.bin       0x44A644 the keyvault's eight-byte head
#   smc.bin      0x44A640 the four bytes an SMC is sealed under
#   CG ... CB_A  0x44A654 up, the six stage nonces, last stage first
COMPILED_IN = {
    "crl.bin": (bytes.fromhex("d97598a6f85d9b867bc43499e33da4aa"),
                bytes.fromhex("c703b932d4077d416052a8135ede6818")),
    "dae.bin": (bytes.fromhex("f424ed2ad36283"),
                bytes.fromhex("a1b2695058f4ed05e580c7ee189a27b5")),
    "secdata.bin": bytes.fromhex("5aa4d1d27de4453e"),
    "kv.bin": bytes.fromhex("36cab0878b83b7f6"),
    "smc.bin": bytes.fromhex("8e0375cc"),
    "CG": bytes.fromhex("b9a21e3bfc2eabb419812d8a85aaa8ce"),
    "CF": bytes.fromhex("cee504ee9f612b9ba520f8eb0b64682a"),
    "CE": bytes.fromhex("56a981cd8cbc0729dd0b7bbc76e57998"),
    "CD": bytes.fromhex("b338641cebd01e102cdde0f319a19f84"),
    "CB_B": bytes.fromhex("fbe2709ae7a13f42cfec45928e3f0e37"),
    "CB_A": bytes.fromhex("3710a2f22ed5f0a8e49cb4c7a1395daa"),
}

# How long a keyvault-style file is when the build makes one up from nothing -- "Making
# up an clean/empty extended.bin!" -- nonce included.
CLEAN_LENGTH = {"extended.bin": 0x4000, "secdata.bin": 0x400}


def extended(own: bytes | None, keyvault_head: bytes, cpu_key: bytes,
             clear: bool = False) -> bytes:
    """extended.bin: the console's own, or a clean one, with the keyvault's head.

    It keeps the keyvault's overflow, and its eight bytes of head are the **keyvault's**
    rather than its own previous copy's -- the two agree on both consoles measured, and
    it holds under `nosecurity` too, where the file itself is made up clean: zeros but
    for that head. No stamp, no lockdown value. Its nonce is `HMAC(cpu key, plaintext +
    07 12)`, exactly as a keyvault's is, so it follows from the content.
    """
    if own is None:
        plain = bytearray(CLEAN_LENGTH["extended.bin"] - NONCE_LENGTH)
    elif clear:
        plain = bytearray(own[NONCE_LENGTH:])
    else:
        plain = bytearray(decrypt_extended(own, cpu_key))
    plain[:HEAD_LENGTH] = keyvault_head[:HEAD_LENGTH]
    return encrypt_extended(bytes(plain), cpu_key)


def secdata_head(own: bytes, cpu_key: bytes) -> bytes:
    """The eight bytes of head a console's own secdata.bin carries."""
    return decrypt_secdata(own, cpu_key)[:HEAD_LENGTH]


def secdata(own: bytes | None, cpu_key: bytes, when: int, ldv: int,
            head: bytes = b"", clear: bool = False) -> bytes:
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
    elif clear:
        # Handed in already open: its first sixteen bytes are a stale nonce.
        plain = bytearray(own[NONCE_LENGTH:])
    else:
        plain = bytearray(decrypt_secdata(own, cpu_key))
    if head:
        plain[:HEAD_LENGTH] = head
    plain[0x08] = 0x01
    plain[0x09] = ldv & 0xFF
    plain[0x10:0x18] = stamp(when)
    return encrypt_secdata(bytes(plain), cpu_key)


def _fcrt_hashed(blob: bytes) -> bool:
    """Whether fcrt.bin's part from `fcrt_body_at` on, as it stands, is what the twenty
    bytes at 0x12C hash -- that is, whether it is in the clear."""
    return hashlib.sha1(blob[fcrt_body_at(blob):]).digest() == blob[0x12C:0x140]


def fcrt(own: bytes, cpu_key: bytes) -> bytes:
    """fcrt.bin: sealed if what was handed over is still in the clear, else carried.

    The original's own steps (0x41E620), in place:

    * a file of any length but 0x4000 is left as it is -- "FCRT encrypt invalid
      size!", measured with one five bytes longer;
    * so is one whose header puts the sealed part past 0x3FFF -- "FCRT encrypt
      invalid offset!";
    * in the clear -- the part from `fcrt_body_at` hashes to the twenty bytes at 0x12C
      -- it is sealed under the CPU key;
    * otherwise it is opened (0x402720) and, where that vouches for it, sealed again
      under the same key and vector, which gives back the same bytes: carried.

    Where it will not open the original says "FCRT data appears to be crypted or
    damaged!! Skipping encryption." and writes what its failed decryption left, which
    no console can read. This carries it as it stands instead -- a deliberate
    divergence, the same as `taken_beside` makes for dae.bin.
    """
    if len(own) != 0x4000:
        logger.error("FCRT encrypt invalid size!")
        return own
    if fcrt_body_at(own) > 0x3FFF:
        logger.error("FCRT encrypt invalid offset!")
        return own
    if _fcrt_hashed(own):
        return encrypt_fcrt(own, cpu_key)
    if not verifies("fcrt.bin", own, cpu_key):
        logger.warning("FCRT data appears to be crypted or damaged!! Skipping "
                       "encryption.")
    return own


def in_the_clear(name: str, blob: bytes, cpu_key: bytes) -> bool:
    """Whether a file handed in beside the build is taken as plaintext.

    Each by the original's own test. crl.bin: the header's hash vouches for the body
    as it stands (0x41DCB8). extended.bin: its first sixteen bytes are zero, or they
    are the nonce its body as it stands derives -- HMAC(CPU key, body + 07 12) --
    both read out of 0x41D6A0; anything else "appears to be encrypted" and is opened.
    secdata.bin: always, since its handler at 0x41D9B0 never decrypts. dae.bin is
    asked record by record inside `dae` and so is not asked here.
    """
    if name == "crl.bin":
        return vouched(blob, blob[BODY_AT:], BODY_AT)
    if name == "extended.bin":
        nonce, body = blob[:NONCE_LENGTH], blob[NONCE_LENGTH:]
        return not any(nonce) or hmacsha(cpu_key, body + b"\x07\x12") == nonce
    return name == "secdata.bin"


def opens(name: str, blob: bytes, cpu_key: bytes) -> bool:
    """Whether a file handed in beside the build opens under a key this build has:
    the console's, or for the two a release ships, the shipped one."""
    try:
        if name == "crl.bin":
            decrypt_crl(blob, cpu_key)
        elif name == "dae.bin":
            decrypt_dae(blob, cpu_key)
        elif name in ("extended.bin", "secdata.bin"):
            return verifies(name, blob, cpu_key)
    except (ValueError, IndexError):
        return False
    return True


def verifies(name: str, own: bytes, cpu_key: bytes) -> bool:
    """Whether a console's own copy of a security file opens under this CPU key.

    What the original asks of each before it will take anything from one -- "crl.bin
    found in sector 0x38d size 0xa00...verify failed! Discarding data." under a key one
    bit wrong, measured -- and each by its own check: crl.bin and dae.bin open or do
    not, extended.bin and secdata.bin carry a nonce their plaintext derives, fcrt.bin
    the start of SHA-1 over its opened body at 0x12C.
    """
    try:
        if name == "crl.bin":
            decrypt_crl(own, cpu_key)
        elif name == "dae.bin":
            dae_parameters(own, cpu_key)
        elif name in ("extended.bin", "secdata.bin"):
            plain = (decrypt_extended(own, cpu_key) if name == "extended.bin"
                     else decrypt_secdata(own, cpu_key))
            tail = b"\x07\x12" if name == "extended.bin" else b""
            return hmacsha(cpu_key, plain + tail) == own[:NONCE_LENGTH]
        elif name == "fcrt.bin":
            # 0x402720: exactly 0x4000 bytes, the sealed part starting no later than
            # 0x3FFF, and its twenty-byte hash at 0x12C true as it stands ("FCRT was
            # already decrypted") or once opened.
            if len(own) != 0x4000 or fcrt_body_at(own) > 0x3FFF:
                return False
            if _fcrt_hashed(own):
                return True
            body = decrypt_fcrt(own, cpu_key)
            return hashlib.sha1(body).digest() == own[0x12C:0x140]
    except (ValueError, IndexError):
        return False
    return True


def taken_beside(name: str, blob: bytes, cpu_key: bytes) -> tuple:
    """What a build does with a security file handed in beside it: `(verdict, clear)`.

    Each kind by its own test, all measured with files made for the purpose:

    * `clean` -- the wrong length, where the original checks it: "extended.bin is not
      the correct size! Making up an clean/empty extended.bin!", and the same of
      secdata.bin (0x41D6B4, 0x41D9BF); and an extended.bin no key opens, "could not
      be decrypted, filling clean/empty data".
    * `as is` -- a crl.bin no key opens goes in as it stands, "crl data appears to be
      crypted with the wrong key or damaged". A dae.bin likewise, which is a
      deliberate divergence: the original says "Skipping encryption" and then writes
      what its failed decryption left of the first record -- as it does for fcrt.bin,
      whose `fcrt` carries a copy it cannot vouch for as it stands too -- which no
      console can read.
    * `use` -- anything else, sealed again; `clear` says it was handed in open --
      `in_the_clear` -- and secdata.bin always is.
    """
    if len(blob) != CLEAN_LENGTH.get(name, len(blob)):
        return "clean", False
    clear = in_the_clear(name, blob, cpu_key)
    if not clear and name in ("crl.bin", "dae.bin", "extended.bin") and \
            not opens(name, blob, cpu_key):
        return ("clean" if name == "extended.bin" else "as is"), False
    return "use", clear
