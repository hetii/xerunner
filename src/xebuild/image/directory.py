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
A chain ends where the next block is one the flash does not have. Over a console whose
filesystem is intact this gives the right length for all thirty-four of its files.

A name whose first byte is 0x05 is one the filesystem has let go. Three entries on one
console carry it, and they are exactly the entries whose chains no longer add up -- the
entry survives a deletion and the blocks are handed to something else. The original
lists them anyway, without checking, so nothing here filters them either; `released`
says so and the caller decides.
"""

from __future__ import annotations

PAGE = 512
ENTRY = 0x20


class Entry:
    """One file, as the table has it."""

    def __init__(self, row: bytes):
        self.row = bytes(row)

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
        """When it was written, in whatever the console counts in."""
        return int.from_bytes(self.row[0x1C:0x20], "big")

    def __repr__(self) -> str:
        return "Entry(%r, block %#x, %#x bytes%s)" % (
            self.name, self.sector, self.size, ", released" if self.released else ""
        )


class Directory:
    """One flash's file table, out of the block that holds it."""

    def __init__(self, block: bytes, blocks: int, block_length: int = 0x4000):
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
            if not entry.name or not 0 < entry.sector < self.blocks:
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
        following, at, seen = [], sector, set()
        while at < self.blocks and at not in seen:
            following.append(at)
            seen.add(at)
            at = self.map[at] if at < len(self.map) else self.blocks
        return tuple(following)

    def blocks_of(self, entry: Entry) -> tuple:
        """The blocks that hold one file, cut to the length its entry states."""
        wanted = -(-entry.size // self.block_length)
        return self.chain(entry.sector)[:wanted]

    def __repr__(self) -> str:
        return "Directory(%d entries, %d blocks)" % (len(self.entries), self.blocks)
