"""The filesystem's table: which files there are, and which blocks each one holds.

The table lives in one block of the flash, and that block is **two tables interleaved a
page at a time**. Its even pages, run together, are the block map -- one sixteen-bit
word a block, saying which block follows. Its odd pages, run together, are the
directory: one entry of thirty-two bytes a file.

Measured rather than taken from anywhere. The entry layout came out of the bytes with
the original's own file list beside it to check against: name of twenty-two bytes, then
the first block, the length and a timestamp. The interleaving was proved by following
the map: `dash.xex` says 0x5b2000 bytes, which is 365 blocks, and its chain is 365
blocks long exactly -- and so are `xam.xex`'s 148, `aac.xexp1`'s 5 and `pdatedata.bin`'s
1.

A word of the map carries flags above its value, so the block it points at is the low
thirteen bits; the values seen above that are 0x1FFB, 0x1FFE, 0x1FFF, 0x5FFE and 0x9FFF.
What a word says when it holds no part of a file is named below, and `map_for` lays a
whole map out of what a build decided -- both here rather than beside the deciding,
because these are the words `map` reads back.
A chain ends where the next block is one the flash does not have. Over a console whose
filesystem is intact this gives the right length for all thirty-four of its files.

`Directory.write` is the other direction, and it is here rather than with whatever
decides a layout for one reason: the interleaving is the only awkward thing in this
file, and a second copy of it somewhere else could disagree with this one. Two halves
wrong the same way read each other back perfectly and leave a console that will not
start.
Written and read in one place, a test catches it.

What it does not do is choose anything. Which file gets which blocks is a decision about
free space and where a region ends; this takes a list and a map already decided and
lays them out.

A name whose first byte is 0x05 is one the filesystem has let go. Three entries on one
console carry it, and they are exactly the entries whose chains no longer add up -- the
entry survives a deletion and the blocks are handed to something else. The original
lists them anyway, without checking, so nothing here filters them either; `released`
says so and the caller decides.
"""

import time
import struct
import calendar

from ..boards.flash import BLOCK, PAGE

ENTRY = 0x20
NAME = 0x16  # how much room an entry gives a name

# What the map says about a block holding no part of a file. Measured off three images
# the original built -- a 16 MB glitch, a retail, a JTAG -- and the same on all three.
RESERVED = 0x1FFB   # below the first file, and the blocks the top regions sit in
TABLE = 0x1FFD      # the one block the table itself is in
FREE = 0x1FFE       # past the files, up to the last block a build may use
CHAIN_END = 0x1FFF  # a file's last block
POOL = 0x0000       # the blocks past that, which a console replaces bad ones from


class Entry:
    """One file, as the table has it."""

    def __init__(self, row: bytes):
        self.row = bytes(row)

    @classmethod
    def for_file(cls, name: str, sector: int, size: int, stamp: int = 0) -> Entry:
        """One entry, made rather than read.

        **No file goes in here.** The name says which file the entry is about, and the
        three numbers are what the table records of it; nothing is opened and nothing is
        read from a disk. Reading an entry is the plain constructor, which takes the
        thirty-two bytes; this is the other direction.
        """
        plain = str(name).encode("latin-1")
        if len(plain) > NAME:
            raise ValueError(
                "%s is %d bytes and an entry gives a name %d" % (name, len(plain), NAME)
            )
        row = bytearray(ENTRY)
        row[: len(plain)] = plain
        struct.pack_into(">H", row, NAME, sector)
        struct.pack_into(">II", row, NAME + 2, size, stamp)
        return cls(bytes(row))

    @property
    def name(self) -> str:
        """The name as stored, first byte and all. Nothing is repaired here."""
        raw = self.row[:22]
        end = raw.find(b"\x00")
        return (raw if end < 0 else raw[:end]).decode("latin-1")

    @property
    def released(self) -> bool:
        """Whether the filesystem has let this file go and reused its blocks.

        0x05 is what a deletion writes over the name's first byte.
        """
        return bool(self.row) and self.row[0] == 0x05

    @property
    def sector(self) -> int:
        """The first block, counted from wherever this flash's filesystem counts."""
        return int.from_bytes(self.row[0x16:0x18], "big")

    @property
    def size(self) -> int:
        return int.from_bytes(self.row[0x18:0x1C], "big")

    @property
    def stamp(self) -> int:
        """When it was written, as a FAT date and time -- see `fat_time`."""
        return int.from_bytes(self.row[0x1C:0x20], "big")

    @staticmethod
    def fat_time(seconds: int) -> int:
        """A moment in UTC as an entry keeps it: FAT's date in the top sixteen bits and
        its time, seconds counted in twos, in the bottom -- which is how every reference
        image's entries read."""
        at = time.gmtime(seconds)
        date = ((at.tm_year - 1980) << 9) | (at.tm_mon << 5) | at.tm_mday
        clock = (at.tm_hour << 11) | (at.tm_min << 5) | (at.tm_sec // 2)
        return (date << 16) | clock

    @staticmethod
    def seconds_of(stamp: int) -> int:
        """`fat_time` the other way round: the moment in UTC a FAT date and time say."""
        date, clock = stamp >> 16, stamp & 0xFFFF
        return calendar.timegm(((date >> 9) + 1980, (date >> 5) & 0xF, date & 0x1F,
                                clock >> 11, (clock >> 5) & 0x3F, (clock & 0x1F) * 2))

    def __repr__(self) -> str:
        return "Entry(%r, block %#x, %#x bytes%s)" % (
            self.name, self.sector, self.size, ", released" if self.released else ""
        )


class Directory:
    """One flash's file table, out of the block that holds it."""

    def __init__(self, block: bytes, blocks: int, block_length: int = BLOCK):
        self.block = bytes(block)
        self.blocks = blocks  # how many the flash has; a chain ends past them
        self.block_length = block_length

    def _halves(self, first: int) -> bytes:
        """Every other page of the table's block, run together."""
        pages = len(self.block) // PAGE
        return b"".join(
            self.block[page * PAGE : (page + 1) * PAGE]
            for page in range(first, pages, 2)
        )

    @property
    def entries(self) -> tuple:
        """Every file the table names, in the order it names them."""
        rows = self._halves(1)
        out = []
        for at in range(0, len(rows) - ENTRY + 1, ENTRY):
            entry = Entry(rows[at : at + ENTRY])
            # Block 0 is a block like any other: a 64 MB image lists the CG's tail
            # there, at the filesystem's base. Reading it as "no file" hid that entry,
            # and a rule written off what this read -- that such an image lists thirty
            # files -- was wrong by the same one.
            if not entry.name or not 0 <= entry.sector < self.blocks:
                continue
            if not 0 < entry.size <= self.blocks * self.block_length:
                continue
            out.append(entry)
        return tuple(out)

    @property
    def map(self) -> tuple:
        """Which block follows which, one word a block, with any flags taken off.

        What is left is either a block this flash has or one of the four markers, and
        `chain` stops at a marker without needing to know which it is.
        """
        words = self._halves(0)
        # Thirteen bits are the block; above them are a console's flags, and masking
        # them off is what makes an older copy of a table read the right file lengths.
        return tuple(
            int.from_bytes(words[at : at + 2], "big") & 0x1FFF
            for at in range(0, len(words), 2)
        )

    def chain(self, sector: int) -> tuple:
        """Every block a file occupies, from its first one.

        Stops at any word that is not a block this flash has, which covers all four
        markers. Stops rather than looping if a map points back at a block already seen.
        """
        # The map is read once. It was inside the loop, which rebuilt the whole of it
        # for every block of every chain: `dash.xex` is 365 blocks and took 0.72 seconds
        # to follow, and reading a whole filesystem took two seconds rather than none.
        words = self.map
        following, at, seen = [], sector, set()
        while at < self.blocks and at not in seen:
            following.append(at)
            seen.add(at)
            at = words[at] if at < len(words) else self.blocks
        return tuple(following)

    def blocks_of(self, entry: Entry) -> tuple:
        """The blocks that hold one file, cut to the length its entry states."""
        wanted = -(-entry.size // self.block_length)
        return self.chain(entry.sector)[:wanted]

    @classmethod
    def write(cls, entries, following: dict, blocks: int,
              block_length: int = BLOCK) -> bytes:
        """The block a flash holds this table in, from a list and a map.

        `entries` are the files, in the order they are to be listed. `following` says
        which block comes after which -- `map_for` is what builds one -- and a block it
        does not name ends a chain, which is what `CHAIN_END` says. Blocks past what the
        flash has are left alone.

        The two halves are laid into alternating pages, which is how the flash keeps
        them: even pages the map, odd pages the entries.
        """
        half = block_length // 2
        words, rows = bytearray(half), bytearray(half)
        for block in range(min(blocks, half // 2)):
            struct.pack_into(">H", words, block * 2, following.get(block, CHAIN_END))
        listed = list(entries)
        if len(listed) * ENTRY > half:
            raise ValueError(
                "a table of %#x bytes lists %d files and this has %d"
                % (block_length, half // ENTRY, len(listed))
            )
        for index, one in enumerate(listed):
            rows[index * ENTRY : (index + 1) * ENTRY] = one.row
        out = bytearray()
        for page in range(block_length // PAGE // 2):
            out += words[page * PAGE : (page + 1) * PAGE]
            out += rows[page * PAGE : (page + 1) * PAGE]
        return bytes(out)

    @staticmethod
    def map_for(chains, blocks: int, first: int, table_at: int, top: int,
                pool: int, held: int = 4) -> dict:
        """Every block of a flash named, from what a build decided to put where.

        `chains` are the files as `(first block, how many)`, `first` is the block the
        first of them starts at, `table_at` is the block this table goes in, `top` is
        the last block a build may use, and `pool` is how many blocks at the very end
        the console keeps to replace a bad one from. `held` is how many blocks from the
        last usable one are reserved for the console's settings: four on a 16 MB image,
        and none on a big block chip, whose settings sit outside the filesystem's
        numbering -- its table says the pool's zero there, measured on four images.

        Measured on three images the original built, identical on all three: blocks
        below the first file are reserved, a file's own run points along itself and its
        last block says the chain ends, the table's block says so about itself, what
        lies between the files and the last usable block is free, that block and the
        three above it are reserved -- the settings, statistics and manufacturing
        blocks sit there -- and the blocks past those say nothing at all.

        Which block the table goes in is the caller's to say, because it follows the
        settings blobs rather than the files: on all three, four `Mobile*.dat` sit
        between the last file and the table.
        """
        out = {}
        for block in range(blocks):
            if block < first:
                out[block] = RESERVED
            elif block <= top - 1:
                out[block] = FREE
            elif block < top + held:
                out[block] = RESERVED
            else:
                out[block] = POOL
        for block in range(blocks - pool, blocks):
            out[block] = POOL
        if table_at:
            out[table_at] = TABLE
        for at, held in chains:
            for step in range(held):
                out[at + step] = at + step + 1 if step < held - 1 else CHAIN_END
        return out

    def __repr__(self) -> str:
        return "Directory(%d entries, %d blocks)" % (len(self.entries), self.blocks)
