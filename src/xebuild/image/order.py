"""Putting a dump's blocks where their own numbers say they belong.

A flash may have blocks that never worked, and the console does not hide them: it marks
them and keeps the contents somewhere else, in a pool of blocks past the last one a
build may use. Nothing above this notices, because a console reads its flash by the
numbers in the spare rather than by position -- so a dump off such a console has its
bytes in the wrong places until this has run, and every offset into it is wrong.

The whole rule was measured by giving the original dumps made for the purpose, one
change at a time, and reading what it said.

A block is one to replace when either of two things is true. Its mark byte says bad --
"bad block at 0x2a (raw offset 0xad400), block ignored". Or one of its pages no longer
carries the code its data asks for, which is a block on the way out: one flipped byte
with its code left alone gives "ECD error at block 0x2a (raw offset 0xad400), block will
be remapped". The second test is what `noecdremap` turns off and the whole of it is what
`noremap` turns off -- "Discarding remap data as NOREMAP was specified!".

What replaces it is a block carrying its number, and where that block may be is not
anywhere: a block at 0x387 holding block 0x2a's data and number was turned away as
"nanddump.bin has a bad LBA at block 0x387, block LBA ignored", while the same block at
0x3FF was taken -- "copying nanddump data from block 0x3FF to block 0x2a for file
extraction integrity", "block 0x2a was remapped to block 0x3FF at remap instance 0".
0x3FF is the last block of a 16 MB flash and 0x3DC is the last one a build may use, so
the pool is what lies past that. When nothing carries the number the original assigns
one for the image it is about to write -- "block 0x2a had no remap, assigning remap
block 0x3ff", counting down from the end -- and that is a decision about writing rather
than reading, so it is not made here.

A number that merely disagrees with its position is not a remap and is not honoured: two
blocks of a dump swapped with their own numbers were both reported as "bad LBA ... block
LBA ignored" and left where they lay. One console here carries twenty-four such blocks
across its bootloader region, each claiming four times its own position.

**The original says it ignores such a number and then loses the block, which is why
that console reads differently there.** Its blocks 0x01 to 0x18 announce four times
their position, so nothing announces 0x01 at all; the buffer it reads a keyvault and a
chain from is assembled by the announced number, and those positions stay erased.
Measured three ways and they agree: a print inserted into the binary shows it
comparing 0xFFFFFFFF where a keyvault's nonce should be; assembling a buffer that way
here leaves 0x4000 and 0x8000 erased while the filesystem, whose blocks announce
themselves correctly, survives untouched; and the original's own behaviour follows
from it exactly -- it cannot open that keyvault, it aborts its chain walk with "error
getting CB/CBA Nonce", and it still reads the CF slots, which sit in block 0x1C where
the number is right.

Reading by position is what this does, and it is what the console must do as well:
that console runs, and a machine that looked for its keyvault and its bootloaders by
those announced numbers would find neither.

**A number written in the other controller's layout is the same case, and a
deliberate divergence.** A block whose spare states its own position the way the other
controller writes it -- "nanddump.bin has a mixed controller LBA at block 0x38d ...
block ignored ... likely caused by previously using jaspersb on a jasper type console"
(the test is at 0x415C7B) -- is dropped by the original, and whatever was in it is lost
to the build: measured with the bench console's crl.bin block rewritten that way, the
original's verify failed and it laid the release's crl.bin instead, 2262 bytes apart
from this. The data is the console's own and only the number's encoding differs, and
everything taken out of a dump is verified before use -- a security file against its
hash or key, the keyvault against the CPU key, the settings block against its sum -- so
this reads the block where it lies and keeps the console's data. Kept as a decision to
revisit once every mode works.
"""

from __future__ import annotations

import logging
import functools

from ..boards.flash import PAGE

logger = logging.getLogger(__name__)


def _spares(raw: bytes, flash) -> list:
    """The field bytes of every page, in order."""
    step = PAGE + flash.spare.length
    return [raw[at + PAGE : at + step] for at in range(0, len(raw) - step + 1, step)]


def marked_bad(raw: bytes, flash) -> tuple:
    """Every block the chip itself has written off, by its mark byte."""
    spares, per = _spares(raw, flash), flash.spare.pages_a_block
    out = []
    for block in range(len(spares) // per):
        pages = spares[block * per : (block + 1) * per]
        if any(not flash.spare.is_good(one) for one in pages):
            out.append(block)
    return tuple(out)


def failing(raw: bytes, flash) -> tuple:
    """Every block holding a page whose data no longer matches its own code.

    Two seconds over a 16 MB dump, and a build asks it three times of the same one --
    to judge the dump, to put its blocks in order and to remap them -- so the answer is
    kept for the last couple of dumps asked about.
    """
    return _failing(bytes(raw), flash)


@functools.lru_cache(maxsize=2)
def _failing(raw: bytes, flash) -> tuple:
    step, per = PAGE + flash.spare.length, flash.spare.pages_a_block
    out = []
    for block in range(len(raw) // (step * per)):
        for page in range(per):
            at = (block * per + page) * step
            if not flash.spare.ecc_ok(raw[at : at + step]):
                out.append(block)
                break
    return tuple(out)


def replacements(raw: bytes, flash) -> dict:
    """Which block in the pool stands in for which, by the number it carries.

    The pool is what lies past the last block a build may use. A block claiming
    another's number from anywhere else is not a replacement -- the original turns one
    away as a bad LBA -- so nothing outside the pool is looked at.
    """
    spares, per = _spares(raw, flash), flash.spare.pages_a_block
    out = {}
    for block in range(flash.last_block + 1, len(spares) // per):
        claimed = flash.spare.block_number(spares[block * per])
        if claimed != block and claimed <= flash.last_block:
            out[claimed] = block
    return out


def stand_ins(raw: bytes, flash, ecd: bool = True, total: int = 0) -> dict:
    """Which block stands in for each one this dump's chip has written off, for an
    image about to be written -- the other direction from `logical`.

    The written-off are those marked bad and, with `ecd`, those holding a page whose
    code no longer matches. Each goes to the block the dump already has standing in
    for it, and otherwise to the highest one nothing else holds, counting down from
    `total` -- "block 0x100 had no remap, assigning remap block 0x3ff". Measured on a
    dump with one block marked bad and one failing its code: 0x3FF and 0x3FE, in that
    order.
    """
    bad = set(marked_bad(raw, flash))
    if ecd:
        bad |= set(failing(raw, flash))
    standing = replacements(raw, flash)
    taken = bad | set(standing.values())
    free, out = total - 1, {}
    for block in sorted(bad):
        stand_in = standing.get(block)
        if stand_in is None:
            while free in taken:
                free -= 1
            if free < 0:
                raise ValueError("this flash has no good block left to stand in for "
                                 "block %#x" % block)
            stand_in = free
            taken.add(stand_in)
        out[block] = stand_in
    return out


def logical(raw: bytes, flash, remap: bool = True, ecd: bool = True) -> bytes:
    """The dump with every replaced block's contents back where they belong.

    Handed a dump whose blocks are all where their numbers say -- which is every dump
    off a console that has never replaced one -- this gives the same bytes back, so it
    costs nothing to put in front of any read.
    """
    if flash.spare is None or not remap:
        return bytes(raw)
    wanted = set(marked_bad(raw, flash))
    if ecd:
        wanted |= set(failing(raw, flash))
    if not wanted:
        return bytes(raw)
    standing = replacements(raw, flash)
    step, per = PAGE + flash.spare.length, flash.spare.pages_a_block
    out = bytearray(raw)
    for block in sorted(wanted):
        stands = standing.get(block)
        if stands is None:
            logger.info("block %#x has no replacement in the dump", block)
            continue
        logger.info("copying block %#x to block %#x", stands, block)
        span = step * per
        out[block * span : (block + 1) * span] = raw[
            stands * span : (stands + 1) * span
        ]
    return bytes(out)
