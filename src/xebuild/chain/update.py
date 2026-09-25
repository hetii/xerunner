"""An update pair -- a CF and the CG behind it -- as an image carries it.

The read side is `Chain.slots` and `Fields.in_cf`; this is the write side, beside it.
Everything here is laid on the release's own CF and CG, in the clear, and measured by
taking reference images apart and putting them back: the release's files come out
changed in these places and nowhere else.

    0x20  the nonce, which a build carries from the console
    0x30  where the rest of CG lies: a count, then that many block numbers
    0x21B which update slot this is
    0x21C the console block -- pairing, lockdown value -- that `Fields` reads
    0x220 sixteen bytes binding the CF to the console

The CF is sealed under the 1BL key every console has, and the CG under the key the CF
carries at 0x330. Update mode lays the same pair over a console that is running.
"""

from __future__ import annotations

from ..crypto.formats import encrypt_bootloader
from ..crypto.keys import hmacsha
from . import sealing
from .stage import Stage

# Where the block list starts and ends in a CF's plaintext.
BLOCKS_AT, BLOCKS_END = 0x30, 0x68


def with_tail(cf: bytearray, first_block: int, count: int) -> None:
    """Say in `cf` where the part of CG that does not fit its slot lies.

    A count at 0x30 and then that many block numbers, one up from the other. The
    number is the block's place in the flash, not in the filesystem -- 0x34 on a 16 MB
    image and 0xAE0 on a 64 MB one. x360mcp read the routine that writes it, at
    0x41C910, after first taking the numbers for versions.
    """
    field = count.to_bytes(2, "big") + b"".join(
        (first_block + step).to_bytes(2, "big") for step in range(count)
    )
    if len(field) > BLOCKS_END - BLOCKS_AT:
        raise ValueError("a CG spilling into %d blocks does not fit its CF" % count)
    cf[BLOCKS_AT:BLOCKS_END] = field.ljust(BLOCKS_END - BLOCKS_AT, b"\x00")


def with_console(cf: bytearray, slot: int, pairing: bytes, ldv: int,
                 cpu_key: bytes) -> None:
    """Make `cf` the console's: its slot number, pairing, lockdown value and binding.

    The binding is an HMAC under the CPU key over everything before it, with the nonce
    replaced by the key it derives, so the CF is hashed as it will be read. Not the
    construction CB_B's binding uses; J-Runner's `Nand.calcCFhash` spells out the same
    one.
    """
    cf[0x21B] = slot
    cf[0x21C:0x21F] = pairing
    cf[0x21F] = ldv & 0xFF
    message = bytearray(cf[:0x220])
    message[0x20:0x30] = hmacsha(sealing.ONE_BL_KEY, bytes(cf[0x20:0x30]))
    cf[0x220:0x230] = hmacsha(cpu_key, bytes(message))


def sealed(cf: bytes, cg: bytes, cg_nonce: bytes, align: int) -> bytes:
    """CF under the 1BL key, and CG under the key CF carries at 0x330, as one run.

    CG is sealed over its padding to `align` too, as every stage is: its tail file is
    ten bytes longer than CG says it is, and those ten are the stream carrying on.
    """
    stage = Stage(bytes(cf), 0)
    sealed_cf = stage.head + encrypt_bootloader(
        stage.body, hmacsha(sealing.ONE_BL_KEY, stage.nonce))
    cg = bytes(cg) + bytes(-len(cg) % align)
    head = len(Stage(cg, 0).head)
    key = hmacsha(bytes(cf[0x330:0x340]), cg_nonce)
    return sealed_cf + cg[:head] + encrypt_bootloader(cg[head:], key)
