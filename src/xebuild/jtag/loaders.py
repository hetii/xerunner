"""`payload.bin` and `freeboot.bin`, and what the original patches in them.

Both are built into xeBuild.exe -- file offsets 0x49360 (0x200 bytes) and 0x49560
(0xD40) -- and carried here as `builtin/`. Either may come from a release's `bin/`
instead.

**Only one it recognises is patched, and it recognises its own.** A payload is patched
when its first 0x200 bytes are the built-in one's, and a core when its first 0xD40 are
-- even with more behind them. A copy with a single byte changed goes in as it stands,
and the original says of the core "CYGNOS, DEMON and NODVD command line options are
ignored due to external freeboot.bin!". Measured with three changed payloads, three
cores, and exact copies of both, on 17559 and 9199.

The comparison is a `memcmp` over those lengths (0x42DABE, 0x42DBDF) on a buffer the
file was read into with 0x10000 zeros behind it (`calloc` at 0x428827). So a file
shorter than the built-in one is recognised when it is a prefix of it and the rest of
the built-in one is zeros: a core of 0xD3C bytes is, since the built-in one ends in four
zeros, and is patched -- measured on 17559.
"""

import os


def builtin(name: str) -> bytes:
    """One of the two loaders the original carries inside itself."""
    with open(os.path.join(os.path.dirname(__file__), "builtin", name), "rb") as handle:
        return handle.read()


def _recognised(blob: bytes, name: str) -> bool:
    known = builtin(name)
    return bytes(blob[:len(known)]).ljust(len(known), b"\x00") == known


def payload_for(payload: bytes, core_length: int) -> bytes:
    """The payload with the core's length in words written in, where it is the known
    one: the operand of the `li r4` at 0x50 that sets how much it copies -- "patching
    payload.bin to load size 0xd40 (0x350 reps)", "org li r4, ffff".

    Words rounded up, `(length + 3) >> 2` at 0x42DB34: a core of 0xD2B bytes gives
    0x34B, measured.
    """
    out = bytearray(payload)
    if _recognised(payload, "payload.bin"):
        out[0x52:0x54] = (-(-core_length // 4)).to_bytes(2, "big")
    return bytes(out)


def core_for(core: bytes, version: str) -> bytes:
    """The core with the release's version written over the thirty-two X's it carries
    for one -- "patching freeboot.bin with kernel version string '17559'" -- and, for
    9199, the old hold address, where it is the known one."""
    out = bytearray(core)
    if not _recognised(core, "freeboot.bin"):
        return bytes(out)
    # Always there: the built-in core carries them at 0xD0B to 0xD2A, and a file
    # recognised with zeros behind it has to hold them itself. The original searches
    # the file's own length for them (0x42CCD7) and has an error for not finding them,
    # "ERROR PATCHING FREEBOOT.BIN for kernel version string!", which no file it
    # recognises can reach.
    blank = out.find(b"X" * 0x20)
    out[blank:blank + 0x20] = version.encode("ascii").ljust(0x20, b"\x00")[:0x20]
    if version == "9199":
        # "9199 ini string detected, patching to old hold address": one doubleword,
        # 0x8000000001003078 to 0x80000000001FFFF8 -- measured on a 9199 JTAG image,
        # where it is the one change beside the version string.
        old = bytes.fromhex("8000000001003078")
        if out.count(old) != 1:
            raise ValueError("this core does not carry the hold address 9199 patches")
        spot = out.find(old)
        out[spot:spot + 8] = bytes.fromhex("80000000001ffff8")
    return bytes(out)
