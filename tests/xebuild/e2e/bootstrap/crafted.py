"""Inputs no console and no release carries, made from the console's own.

Each is one thing changed: a file the dump holds, taken out open or sealed or cut short;
a dump with a block marked bad or a page that fails its code; a big block part, its
memory-unit pages written; a release with a loader or a section of its own. Each one
was first made by hand while a question about the original was being settled, and is
made here the same way, so that on the console it was made from it comes out the same
to the byte. The exceptions are said where they are: bytes that were drawn at random
then are drawn from a fixed seed now.
"""

import struct
import hashlib

from xebuild.image import Image
from xebuild.crypto import formats
from xebuild.boards import for_name
from xebuild.crypto.rc4 import rc4
from xebuild.crypto.keys import hmacsha

# Where the original carries its two loaders inside itself: payload.bin, freeboot.bin.
BUILTIN = {"payload.bin": (0x49360, 0x200), "freeboot.bin": (0x49560, 0xD40)}

# A `.meta`'s four bytes: the stamp the file it sits beside is given.
META = bytes.fromhex("46cf645c")

# A 64-byte step, 0x00 to 0x3F, which a few changed files carry.
COUNTING = bytes(range(0x40))


def image(raw: bytes, board: str = "trinity") -> Image:
    return Image(raw, for_name(board)[0].flash)


def security_file(raw: bytes, name: str) -> bytes:
    """One of the dump's security files as the flash holds it, sealed."""
    return image(raw).read(name)


def opened(raw: bytes, name: str, cpu_key: bytes, xex_key: bytes) -> bytes:
    """A security file of the dump laid out open, as a console's tools leave one.

    crl.bin keeps its header and carries the body in the clear; dae.bin each record
    likewise; extended.bin and secdata.bin keep their nonce in front of the clear text.
    """
    sealed = security_file(raw, name)
    if name == "crl.bin":
        return sealed[:formats.BODY_AT] + formats.decrypt_crl(sealed, cpu_key,
                                                              xex_key)[0]
    if name == "dae.bin":
        return b"".join(head + body for head, body, _ in
                        formats.decrypt_dae(sealed, cpu_key, xex_key))
    if name == "extended.bin":
        return sealed[:0x10] + formats.decrypt_extended(sealed, cpu_key)
    return sealed[:0x10] + formats.decrypt_secdata(sealed, cpu_key)


def mixed_dae(raw: bytes, cpu_key: bytes, xex_key: bytes) -> bytes:
    """dae.bin with its first record open and the rest sealed."""
    sealed = security_file(raw, "dae.bin")
    plain = opened(raw, "dae.bin", cpu_key, xex_key)
    at, length = formats.records(sealed)[0]
    return plain[at:at + length] + sealed[at + length:]


def keyvault(raw: bytes) -> bytes:
    """The dump's keyvault, sealed, as the flash holds it."""
    return bytes(image(raw).flat[0x4000:0x8000])


def mobile(raw: bytes, last: int) -> bytes:
    """The dump's MobileB.dat with its last byte made `last`; a donor's image carries
    none, and 0x800 drawn bytes stand in for it."""
    found = image(raw)
    blob = bytearray(found.blob("MobileB.dat") if "MobileB.dat" in found.blobs
                     else drawn("MobileB.dat", 0x800))
    blob[-1] = last
    return bytes(blob)


def drawn(label: str, length: int) -> bytes:
    """Bytes that stand for random ones: SHA-512 over a label and a counter."""
    out = bytearray()
    for count in range(-(-length // 64)):
        out += hashlib.sha512(b"%s:%d" % (label.encode(), count)).digest()
    return bytes(out[:length])


def bad_blocks(raw: bytes) -> bytes:
    """A 16 MB dump with block 0x100 marked bad and a page of block 0x120 failing
    its code: the mark byte of the block's first spare zeroed, and one byte of the
    page's data inverted, neither code recomputed."""
    flash = for_name("trinity")[0].flash
    step = 0x200 + flash.spare.length
    per = flash.spare.pages_a_block
    out = bytearray(raw)
    out[0x100 * per * step + 0x200 + flash.spare.mark_at] = 0
    out[(0x120 * per + 3) * step + 0x10] ^= 0xFF
    return bytes(out)


def big_bad_block(raw: bytes) -> bytes:
    """A big block dump with block 0x170 marked bad in its first page's spare."""
    out = bytearray(raw)
    out[0x17000 * 0x210 + 0x200] = 0
    return bytes(out)


def memory_units(raw: bytes, whole: int) -> bytes:
    """A big block dump with memory-unit pages in it, and grown to `whole` bytes.

    Every erased block from 0x10 below 0x15C whose number three does not divide gets
    256 pages of one 64-byte pattern, and every block past the dump's end one of its
    own; each page's spare names its block and carries 0x28 at 0x0C, ECC computed.
    That byte's low six bits are what the original takes for memory-unit data when it
    reads a big block dump (0x415B8A): between 1 and 0x29.
    """
    spare = for_name("jasper256")[0].flash.spare
    step, per = 0x210, 256
    span = step * per
    out = bytearray(raw)
    for block in range(0x10, 0x15C):
        if block % 3 == 0 or out[block * span:(block + 1) * span] != b"\xff" * span:
            continue
        out[block * span:(block + 1) * span] = _unit_block(spare, block, per)
    for block in range(len(raw) // span, whole // span):
        out += _unit_block(spare, block, per)
    return bytes(out)


def _unit_block(spare, block: int, per: int) -> bytes:
    data = drawn("memory unit %d" % block, 64) * 8
    fields = bytes([0xFF]) + struct.pack("<H", block) + bytes(9) + b"\x28" + bytes(3)
    return (data + spare.with_ecc(data, fields)) * per


def manufacturing(raw: bytes) -> bytes:
    """A 16 MB dump whose block 0x3DD holds a Manufacturing.data: eight pages of 0x5A,
    each spare naming the block, ECC computed."""
    flash = for_name("trinity")[0].flash
    step = 0x200 + flash.spare.length
    per = flash.spare.pages_a_block
    out = bytearray(raw)
    data = b"\x5a" * 0x200
    fields = flash.spare.write(0x3DD)
    for page in range(8):
        at = (0x3DD * per + page) * step
        out[at:at + step] = data + flash.spare.with_ecc(data, fields)
    return bytes(out)


def builtin(exe: bytes, name: str) -> bytes:
    """One of the loaders the original carries inside itself."""
    at, length = BUILTIN[name]
    return exe[at:at + length]


def flipped(blob: bytes, at: int, value: bytes | None = None) -> bytes:
    """`blob` with the byte at `at` inverted, or with `value` written there."""
    out = bytearray(blob)
    if value is None:
        out[at] ^= 0xFF
    else:
        out[at:at + len(value)] = value
    return bytes(out)


# --- RGH3 ----------------------------------------------------------------------------
# J-Runner's own step after a glitch2 build (Classes/RGH2to3.cs): the exploit's CB_A
# and CB_B from `common/xell-images/glitch2/<BOARD>_RGH3.ecc` take the place of the
# console's CB_A, its CB_B is opened with the console's key and left behind them in the
# clear, and everything after moves along. The exploit's CB_B is opened under a zero
# key, four words of it rewritten when it asks for that, and sealed again.

_STAGE = struct.Struct(">2sHIII")
_PATCH = {0x354: 0x64690002, 0x368: 0x7D8C482A, 0x370: 0x64690006, 0x37C: 0xF8491010}
_HEAD = 0x73800             # the raw length before XeLL on a 16 MB part


def rgh3(raw: bytes, ecc: bytes, cpu_key: bytes, one_bl_key: bytes) -> bytes:
    """A 16 MB dump converted to boot by RGH3, its own SMC kept."""
    flash = for_name("trinity")[0].flash
    exploit = flash.flatten(ecc)
    first = struct.unpack_from(">I", exploit, 0x08)[0]
    cba = _stage(exploit, first)
    cbb = _stage(exploit, first + len(cba))
    head = bytearray(flash.flatten(raw[:_HEAD]))
    own_at = struct.unpack_from(">I", head, 0x08)[0]
    own_a = _stage(head, own_at)
    own_b = _stage(head, own_at + len(own_a))
    plain = _crypt(own_b, _key(_open_a(own_a, one_bl_key), own_b, cpu_key))
    out = bytearray(head)
    out[own_at:own_at + len(own_a) + len(own_b)] = (
        cba + _payload(cba, cbb, one_bl_key) + plain)
    del out[len(head):]
    spares = [raw[at + 0x200:at + 0x210] for at in range(0, _HEAD, 0x210)]
    return flash.unflatten(bytes(out), spares) + raw[_HEAD:]


def _stage(flat: bytes, at: int) -> bytes:
    return bytes(flat[at:at + _STAGE.unpack_from(flat, at)[4]])


def _open_a(cba: bytes, one_bl_key: bytes) -> bytes:
    return _crypt(cba, hmacsha(one_bl_key, cba[0x10:0x20]))


def _key(cba_plain: bytes, cbb: bytes, cpu_key: bytes) -> bytes:
    return hmacsha(cba_plain[0x10:0x20], cbb[0x10:0x20] + cpu_key)


def _crypt(stage: bytes, key: bytes) -> bytes:
    return stage[:0x10] + key + rc4(key, stage[0x20:])


def _payload(cba: bytes, cbb: bytes, one_bl_key: bytes) -> bytes:
    key = _key(_open_a(cba, one_bl_key), cbb, bytes(16))
    plain = bytearray(_crypt(cbb, key))
    if struct.unpack_from(">I", plain, 0x354)[0] != 0x646A0002:
        return cbb
    for at, word in _PATCH.items():
        struct.pack_into(">I", plain, at, word)
    sealed = bytearray(_crypt(bytes(plain), key))
    sealed[0x10:0x20] = bytes(16)
    return bytes(sealed)
