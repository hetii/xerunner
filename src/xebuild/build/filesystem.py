"""Which block each file gets, and the table that records it.

Two things, worth keeping apart because only one of them is a decision. Recording a
table is `image.Directory.write`, and naming every block of the map is
`image.Directory.map_for`; both sit beside the code that reads one back, because a
marker written here and read there is one number in two places. Deciding **what** goes
in it -- which file gets which blocks, in which order -- is here.

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

from ..boards.flash import BLOCK
from ..image.directory import Directory, Entry

logger = logging.getLogger(__name__)


class Filesystem:
    """Where each file went, and what the table says about it."""

    def __init__(self, flash, first: int = 0, bigffs: bool = False,
                 table_at: int = 0, pool: int = 32, held: int = 4):
        self.flash = flash
        self.first = first
        self.bigffs = bigffs
        self.table_at = table_at
        self.pool = pool
        self.held = held
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
        """The whole map, every block named.

        What each kind of block says is the table's own business, so the naming is
        `image.Directory.map_for`; what this knows is which blocks the files took and
        which block the table goes in.
        """
        chains = tuple((entry.sector, blocks) for entry, blocks, _body in self.placed)
        return Directory.map_for(
            chains, self.flash.blocks, self.first, self.table_at,
            self.flash.last_block - self.flash.base_of(self.bigffs), self.pool,
            self.held,
        )

    def table(self) -> bytes:
        """The block a flash keeps this table in."""
        return Directory.write(self.entries, self.following, self.flash.blocks)

    def over(self, image) -> None:
        """Every file written into `image` where this says it goes, padded to its block.

        The blocks are the filesystem's own, so turning them into places is the flash's
        business rather than this one's, and refusing what does not fit is the image's.

        A file's last block is filled out with zeros: every reference image carries them
        between the end of a file and the end of its block, where erased flash would be
        0xFF, and the pages they sit in are written like any other.
        """
        for entry, blocks, body in self.placed:
            at = self.flash.offset_of(entry.sector, self.bigffs)
            image.put(at, bytes(body) + bytes(blocks * BLOCK - len(body)))

    def __repr__(self) -> str:
        blocks = sum(one[1] for one in self.placed)
        return "Filesystem(%d files, %d blocks from %#x)" % (
            len(self.placed), blocks, self.first
        )
