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

**A number written in the other controller's layout is kept where it lies -- a
deliberate divergence, agreed on 2026-09-26.** On a small-block flash a block's number
sits in page 0's spare either at bytes 0-1 (the older controller) or at bytes 1-2 (the
newer), 12 bits each. The original works out which one this dump's controller uses from
the first block, counting from 1, whose number matches its position one way or the
other (0x416AA0: "NAND dump uses big block controller"). It then calls a block "mixed
controller" when the number read the **other** way equals the block's own position
(0x415B00, at 0x415C7B and 0x415CE8). Excluded are block 0, a block that is erased
throughout, and one marked bad at page 0 or page 16; a block whose pages fail their
code goes down the ECD path instead ("ECD error ... will be remapped"). eMMC and big-
block flash have no such case. Such a block it does not copy at all (0x416212 to
0x416579): its place stays erased, whatever was in it is lost, and every later reader
falls back as it would for a missing file -- measured with the block holding crl.bin
rewritten so, where the console's own copy then "verify failed" and crl.bin was sealed
under other parameters than the console's, 2262 bytes apart from this.

Why this keeps it:

* The original's own test is what says the block is where it belongs -- its number, read
  the other way, is its position -- so the data is the console's own, in its place, and
  its code is sound, or the ECD path would have taken it.
* The rule also hits blocks that are not mixed at all: a block at 0x101, 0x202 or 0x303
  whose sequence byte happens to equal the low byte of its number reads right both ways,
  and the original drops it -- measured with block 0x101's sequence set to 1, "mixed
  controller LBA at block 0x101 ... likely caused by previously using jaspersb".
* What the original leaves in the block's place is not safer, only emptier. Most of what
  a dump gives is verified before use -- a security file against its hash or key, the
  keyvault against the CPU key, a firmware file against its checksum -- and those fall
  back the same way either way. What is not verified -- the statistics, the
  manufacturing data, the settings blobs, the settings block, the filesystem's table --
  the original would take as erased, and this takes as the console has it. The one
  thing kept data could be is older than the console's current state, if the console
  itself never reads such a block; that is not known.

No dump this project holds, 260 of them, has such a block. The original's warning is
given for exactly the blocks it would have dropped -- see `mixed_controller` -- worded
for what happens here.
"""

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


def mixed_controller(raw: bytes, flash, ecd: bool = True) -> tuple:
    """The blocks the original calls "mixed controller LBA" -- see the module's notes
    -- in order, by the original's own tests (0x416AA0, 0x415B00).

    A small-block flash only. The dump's own layout comes from the first block after 0
    whose number matches its position. Then every block after 0 that is not erased
    throughout, not marked bad at page 0 or page 16, whose number read the other
    layout's way is its position, and -- with `ecd`, as the original's ECD test comes
    after -- whose pages all carry their code.
    """
    spare = flash.spare
    if spare is None or spare.pages_a_block != 32:
        return ()
    step = PAGE + spare.length
    span = step * spare.pages_a_block

    def read(block):
        fields = raw[block * span + PAGE:block * span + step]
        older_way = (fields[1] & 0xF) << 8 | fields[0]
        newer_way = (fields[2] & 0xF) << 8 | fields[1]
        return fields, older_way, newer_way

    newer = False
    for block in range(1, len(raw) // span):
        fields, older_way, newer_way = read(block)
        if fields[5] != 0xFF or fields[1] == 0xFF:
            continue
        if newer_way == block or older_way == block:
            newer = newer_way == block
            break
    failed = set(failing(raw, flash)) if ecd else set()
    out = []
    for block in range(1, len(raw) // span):
        at = block * span
        fields, older_way, newer_way = read(block)
        if raw[at:at + span] == b"\xff" * span:
            continue
        if fields[5] != 0xFF or raw[at + 16 * step + PAGE + 5] != 0xFF:
            continue
        if (older_way if newer else newer_way) == block and block not in failed:
            out.append(block)
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
    order. One past the last block a build may use is in the pool itself: it has no
    stand-in, None here, and is only zeroed -- "block 0x3ff had no need of remap, it's
    in the wear area", measured.
    """
    bad = set(marked_bad(raw, flash))
    if ecd:
        bad |= set(failing(raw, flash))
    standing = replacements(raw, flash)
    # A block the pool already stands in for is moved again whether or not it is
    # marked: measured, "copying 0x4200 bytes of LBA 0x100 to block 0x3ff...zero fill
    # origin" for a block the chip had not written off.
    bad |= set(standing)
    taken = bad | set(standing.values())
    free, out = total - 1, {}
    for block in sorted(bad):
        if block > flash.last_block:
            logger.debug("block %#x had no need of remap, it's in the wear area", block)
            out[block] = None
            continue
        stand_in = standing.get(block)
        if stand_in is None:
            while free in taken:
                free -= 1
            if free < 0:
                raise ValueError("this flash has no good block left to stand in for "
                                 "block %#x" % block)
            stand_in = free
            taken.add(stand_in)
            logger.debug("block %#x had no remap, assigning remap block %#x", block,
                         stand_in)
        out[block] = stand_in
    return out


def logical(raw: bytes, flash, remap: bool = True, ecd: bool = True) -> bytes:
    """The dump with every replaced block's contents back where they belong.

    Handed a dump whose blocks are all where their numbers say -- which is every dump
    off a console that has never replaced one -- this gives the same bytes back, so it
    costs nothing to put in front of any read.

    A block the chip marked bad is not read at all, whatever the options: it is left
    erased unless a block standing in for it fills it. Measured with the dump's fsroot
    block marked bad, plain and under `noremap` and `noecdremap`: "bad block at 0x398
    (raw offset 0xed3000), block ignored", and the older fsroot is the one found. A
    block failing its code is still read where nothing stands in for it.
    """
    if flash.spare is None:
        return bytes(raw)
    bad = marked_bad(raw, flash)
    standing = replacements(raw, flash) if remap else {}
    # A block the pool stands in for is read from there, marked or not -- measured:
    # "copying nanddump data from block 0x3ff to block 0x100 for file extraction
    # integrity" for a block the chip had not written off.
    wanted = set(bad) | set(standing) if remap else set()
    if remap and ecd:
        wanted |= set(failing(raw, flash))
    if not bad and not wanted:
        return bytes(raw)
    step, per = PAGE + flash.spare.length, flash.spare.pages_a_block
    span = step * per
    out = bytearray(raw)
    for block in bad:
        logger.warning("bad block at %#x (raw offset %#x), block ignored", block,
                       block * span)
        out[block * span : (block + 1) * span] = b"\xff" * span
    for block in sorted(wanted):
        stands = standing.get(block)
        if stands is None:
            if block not in bad:
                logger.warning("block %#x has no replacement in the dump", block)
            continue
        logger.debug("copying block %#x to block %#x", stands, block)
        out[block * span : (block + 1) * span] = raw[
            stands * span : (stands + 1) * span
        ]
    return bytes(out)
