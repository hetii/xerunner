"""Which block each file gets, and the table that records it.

Two things, worth keeping apart because only one of them is a decision. Recording a
table is `image.Directory.write`, which sits beside the code that reads one. Deciding
what goes in it is here.

**The packing rule is as simple as it looks, and that is measured.** Files are laid one
after another with no gap at all, in the order they are handed over, and every one is a
single run of blocks. Read off an image the original built: thirty one files, every
chain contiguous, every file beginning exactly where the one before it ended, not a byte
of slack anywhere.

**Where the first of them goes is not decided here.** It follows from what else the
image carries, and that differs by image type: a glitch image puts XeLL before its patch
slots and a JTAG one puts it after, and a JTAG image has two slot pairs where the others
have one. Measured on four images the original built, three agree on "the slots, then
twice 0x10000, because the CG's tail overflows into the filesystem and lands there" --
0xD0000 on a 16 MB glitch, 0x90000 on a retail, 0xE0000 on a big block glitch. The JTAG
one does not, so rather than guess this takes the first block as an argument and leaves
the question where it belongs.

**A file's blocks are the filesystem's own, not the flash's.** They are the same number
on a 16 MB flash, whose base is zero, and not on a 64 MB one: `jasperbigffs` counts from
block 0x2E0 and a `jasperbb` from 0xAE0, so one file is one directory number and two
different places in a flash. `Flash.offset_of` is what turns one into the other.
"""

from __future__ import annotations

import logging

from ..image.directory import Directory, Entry

logger = logging.getLogger(__name__)

BLOCK = 0x4000

# What the map says about a block holding no part of a file. Measured off three images
# the original built -- a 16 MB glitch, a retail, a JTAG -- and the same on all three.
RESERVED = 0x1FFB   # below the first file, and the blocks the top regions sit in
TABLE = 0x1FFD      # the one block the table itself is in
FREE = 0x1FFE       # past the files, up to the last block a build may use
CHAIN_END = 0x1FFF  # a file's last block
POOL = 0x0000       # the blocks past that, which a console replaces bad ones from


class Filesystem:
    """Where each file went, and what the table says about it."""

    def __init__(self, flash, first: int = 0, bigffs: bool = False,
                 table_at: int = 0, pool: int = 32):
        self.flash = flash
        self.first = first
        self.bigffs = bigffs
        self.table_at = table_at
        self.pool = pool
        self.placed = []

    @property
    def after(self) -> int:
        """The first block past every file: where the blobs and the table go."""
        return self.first + sum(one[1] for one in self.placed)

    def add(self, name: str, body: bytes, stamp: int = 0) -> Entry:
        """One more file, in the next blocks there are.

        Refused rather than trimmed when it will not fit below the last block a build
        may use: a file cut to fit reads back short with nothing said about it, and what
        lies past that block is the pool a console replaces bad ones from.
        """
        at = self.after
        blocks = -(-len(body) // BLOCK)
        last = self.flash.last_block - self.flash.base_of(self.bigffs)
        if at + blocks > last + 1:
            raise ValueError(
                "%s wants blocks %#x to %#x and this flash ends at %#x"
                % (name, at, at + blocks - 1, last)
            )
        entry = Entry.for_file(name, at, len(body), stamp)
        self.placed.append((entry, blocks, bytes(body)))
        logger.info("%s at block %#x, %#x bytes, %d blocks",
                    name, at, len(body), blocks)
        return entry

    @property
    def entries(self) -> tuple:
        return tuple(one[0] for one in self.placed)

    @property
    def following(self) -> dict:
        """The whole map, every block named: four things mean "no file here".

        Measured on three images the original built, identical on all three: blocks
        below the first file are reserved, a file's own run points along itself and
        its last block says the chain ends, the table's block says so about itself,
        what lies between the files and the last block a build may use is free, that
        block and the three above it are reserved -- the settings, statistics and
        manufacturing blocks sit there -- and the blocks past those are the pool a
        console replaces a bad one from, which say nothing at all.

        Where the table goes is the caller's to say, because it follows the settings
        blobs rather than the files: on all three, four `Mobile*.dat` sit between the
        last file and the table.
        """
        top = self.flash.last_block - self.flash.base_of(self.bigffs)
        out = {}
        for block in range(self.flash.blocks):
            if block < self.first:
                out[block] = RESERVED
            elif block <= top - 1:
                out[block] = FREE
            elif block <= top + 3:
                out[block] = RESERVED
            else:
                out[block] = POOL
        for block in range(self.flash.blocks - self.pool, self.flash.blocks):
            out[block] = POOL
        if self.table_at:
            out[self.table_at] = TABLE
        for entry, blocks, _body in self.placed:
            for step in range(blocks):
                out[entry.sector + step] = (
                    entry.sector + step + 1 if step < blocks - 1 else CHAIN_END
                )
        return out

    def table(self) -> bytes:
        """The block a flash keeps this table in."""
        return Directory.write(self.entries, self.following, self.flash.blocks)

    def over(self, image: bytes) -> bytes:
        """`image` with every file written where this says it goes.

        The blocks are the filesystem's own, so turning them into places is the flash's
        business rather than this one's.
        """
        out = bytearray(image)
        for entry, _blocks, body in self.placed:
            at = self.flash.offset_of(entry.sector, self.bigffs)
            if at + len(body) > len(out):
                raise ValueError(
                    "%s at block %#x does not fit in %#x bytes"
                    % (entry.name, entry.sector, len(out))
                )
            out[at : at + len(body)] = body
        return bytes(out)

    def __repr__(self) -> str:
        blocks = sum(one[1] for one in self.placed)
        return "Filesystem(%d files, %d blocks from %#x)" % (
            len(self.placed), blocks, self.first
        )
