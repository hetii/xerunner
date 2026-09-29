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

import logging

from ..boards.flash import BLOCK, PAGE
from ..image.directory import POOL, Directory, Entry

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
        # Blocks the build stepped over between the files and the settings blobs.
        self.skipped = range(0)

    @classmethod
    def on(cls, flash, first: int, bigffs: bool = False) -> Filesystem:
        """A filesystem from block `first` on, with the reserve its flash keeps.

        No pool on a part with no bad blocks to stand in for: an eMMC's table reserves
        every block from the last one a build may use to the end of the part -- six on
        the one measured, where the anchors and the settings live -- and a devkit
        image's flat 64 MB does the same from 0xF7C. Otherwise the last four usable
        blocks are held for the settings on a 16 MB image, and none on a big block
        chip, whose settings sit outside the filesystem's numbering.
        """
        base = flash.base_of(bigffs)
        if not flash.pool:
            return cls(flash, first, bigffs, pool=0,
                       held=flash.blocks - (flash.last_block - base))
        return cls(flash, first, bigffs, held=0 if cls._big(flash) else 4)

    @staticmethod
    def _big(flash) -> bool:
        """Whether its pages carry the filesystem's own fields: a big block chip."""
        return flash.spare is not None and flash.spare.fs_at is not None

    @property
    def after(self) -> int:
        """The first block past every file: where the blobs and the table go."""
        return self.first + sum(one[1] for one in self.placed)

    def add(self, name: str, body: bytes, stamp: int = 0) -> Entry | None:
        """One more file, in the next blocks there are, or None where it will not fit.

        The block below the last one a build may use is kept for the table, so a file
        must end before it; one that would not is left out and the next one tried, as
        the original does -- "ERROR: adding xenonsclatin.xtt will exceed available
        flash space! Skipped!" -- and a smaller one behind it can still go in. Measured
        on 17489_RGL's longer `-i flash` list on jasperbb, and on trinity with a file
        padded to put secdata.bin at block 0x3DA, which goes in, and at 0x3DB, which
        does not. Never trimmed: a file cut to fit reads back short with nothing said.
        """
        at = self.after
        blocks = -(-len(body) // BLOCK)
        last = self.flash.last_block - self.flash.base_of(self.bigffs)
        if at + blocks > last - 1:
            logger.error("adding %s will exceed available flash space! Skipped!", name)
            return None
        entry = Entry.for_file(name, at, len(body), stamp)
        self.placed.append((entry, blocks, bytes(body)))
        logger.debug("%s at block %#x, %#x bytes, %d blocks",
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
        out = Directory.map_for(
            chains, self.flash.blocks, self.first, self.table_at,
            self.flash.last_block - self.flash.base_of(self.bigffs), self.pool,
            self.held,
        )
        # A block the build stepped over to start the blobs on the flash's own step is
        # never named at all, and the table keeps the zero it started with -- measured
        # on a jasperbb image, whose four blocks between the files and the blobs say
        # 0x0000 where the free ones around them say 0x1FFE.
        for block in self.skipped:
            out[block] = POOL
        return out

    def table(self) -> bytes:
        """The block a flash keeps this table in."""
        return Directory.write(self.entries, self.following, self.flash.blocks)

    def over(self, image, fields: bytes = b"") -> None:
        """Every file written into `image` where this says it goes, padded to its block,
        and its pages marked written.

        The blocks are the filesystem's own, so turning them into places is the flash's
        business rather than this one's, and refusing what does not fit is the image's.

        A file's last block is filled out with zeros: every reference image carries them
        between the end of a file and the end of its block, where erased flash would be
        0xFF, and the pages they sit in are written like any other. On a big block chip
        the pages carry `fields` -- the filesystem's three bytes -- and kind 0x2A, and a
        file that fits in one block leaves its padding's fields erased, with a real
        code over the zeros: measured on four such files in a jasperbb image. A longer
        file's padding is written like the rest of it, and nothing of this on a 16 MB
        image.
        """
        big = self._big(self.flash)
        for entry, blocks, body in self.placed:
            at = self.flash.offset_of(entry.sector, self.bigffs)
            image.put(at, bytes(body) + bytes(blocks * BLOCK - len(body)))
            span = blocks * BLOCK
            if big and blocks == 1:
                span = -(-len(body) // PAGE) * PAGE
            image.mark(at, span, 0, 0x2A if big else 0, fs=fields)

    def lay_blobs(self, image, blobs: dict, fields: bytes = b"") -> dict:
        """The console's settings blobs laid behind the files, and where the table goes.

        What follows the files starts on the flash's own step: a jasperbb's files end at
        0x38D0000 and its blobs go to 0x38E0000 -- and so does its table when there are
        no blobs. On every other part the files already end on one. The blobs go
        `mobile_stride` apart in the order B to J, each with its version 1, its kind
        from 0x31 up, and four bytes more: its length in units of 0x100 and how many
        pages of its block are still free -- counted in fours on a big block chip,
        0x3F, 0x3E, 0x3D, 0x3C down a block. A blob that would reach the block kept for
        the table is left out, as a file is: measured with B at 0x3DA going in and C at
        0x3DB not.

        The table follows the last blob placed, on the flash's step: 0x10000 past the
        start of four 0x4000 blobs, 0x20000 past four packed 0x800 apart on a big block
        part, one block past a lone MobileB. With none placed it goes where they would
        have begun, and the blocks stepped over stay free; with some, they go unnamed.
        All measured. Returns the blobs placed, by kind, as `(block, length)`.
        """
        flash, big = self.flash, self._big(self.flash)
        base = flash.base_of(self.bigffs) * BLOCK
        start = flash.offset_of(self.after, self.bigffs)
        start += -start % flash.round_to
        placed, table_at = {}, start
        for index, name in enumerate(sorted(blobs)):
            at = start + index * flash.mobile_stride
            body, kind = blobs[name], 0x31 + "BCDEFGHIJ".index(name[6])
            if at + len(body) > (flash.last_block - 1) * BLOCK:
                logger.error("adding %s will exceed available flash space! Skipped!",
                             name)
                continue
            image.put(at, body)
            placed[kind] = ((at - base) // BLOCK, len(body))
            ends = at + len(body)
            table_at = ends + -ends % flash.round_to
            if flash.spare is None:
                continue
            per = flash.spare.pages_a_block
            pages = max(1, len(body) // PAGE)
            free = per - (at // PAGE) % per - pages
            free >>= 2 if big else 0
            image.mark(at, pages * PAGE, 1, kind,
                       bytes([len(body) // 0x100, free, 0, 0]),
                       b"\x00" if big else b"")
        if placed:
            self.skipped = range(self.after, (start - base) // BLOCK)
        self.table_at = (table_at - base) // BLOCK
        return placed

    def lay_table(self, image, fields: bytes = b"") -> None:
        """The table into its block, marked with its own kind: 0x30 on a 16 MB image,
        0x2C on a big block chip, where it keeps the filesystem's three bytes."""
        at = self.flash.offset_of(self.table_at, self.bigffs)
        table = self.table()
        image.put(at, table)
        image.mark(at, len(table), 1, 0x2C if self._big(self.flash) else 0x30,
                   fs=fields)

    def __repr__(self) -> str:
        blocks = sum(one[1] for one in self.placed)
        return "Filesystem(%d files, %d blocks from %#x)" % (
            len(self.placed), blocks, self.first
        )
