"""A flash image: its header, its settings blobs, its filesystem, its files.

One class for an image whichever direction it is going. What is read here is what the
original's extract mode reports, and every rule below was checked against what it
printed for two consoles' own dumps.

An image is read exactly as it is handed over, block for block: the block a file's table
names is taken to be the block at that position. That holds for every dump here, and it
is where this stops. A console may keep a block somewhere other than where its number
says, and the original puts such a block back before it reads any file -- "copying
nanddump data from block 0x%x to block 0x%x for file extraction integrity". Where a
number is not believable instead it says "block LBA ignored" and falls back to the
position, which is what happens on one of the two dumps measured here: twenty-four
blocks of its bootloader region carry four times their own position, and the original
ignores all of them.

Putting blocks back where their numbers say is its own job and not this one. Whoever has
a dump that needs it orders the bytes first and hands the ordered bytes here.

Finding the settings blobs took the most measuring, because a console never overwrites
one: it appends a new copy and leaves every older copy where it was. One dump here holds
two hundred and fifty-six pages of filesystem table and another holds a thousand and
fifty-six. The rule is the highest version, and among equal versions the last page in
flash -- and the page found that way is the blob's **last** page, so it begins as many
pages earlier as it is long. Taking the first page of a run instead reads version 168
where the original says 169, because copies of an older version were written after the
current one.
"""

from __future__ import annotations

from .directory import Directory
from .header import Header

PAGE = 512


class Image:
    """One flash image, read through the flash that holds it."""

    def __init__(self, raw: bytes, flash, bigffs: bool = False):
        self.raw = bytes(raw)
        self.flash = flash
        self.bigffs = bigffs
        self.flat = flash.flatten(self.raw)

    @property
    def header(self) -> Header:
        return Header(self.flat)

    @property
    def blobs(self) -> dict:
        """Every settings blob, by name: which page, where, how long, which version.

        The kinds and their lengths are a table because nothing in flash states them: a
        blob is not a file and has no directory entry. The filesystem table wears 0x30
        on a 16 MB image and 0x2C on a big block chip, which is why both are here -- a
        scan that knew only 0x30 found the mobiles in a 64 MB image and no table.
        """
        if self.flash.spare is None:
            raise ValueError("an eMMC image has no spare to scan; its anchors do")
        lengths = {0x30: 0x4000, 0x2C: 0x4000,
                   0x31: 0x800, 0x32: 0x200, 0x33: 0x800, 0x34: 0x800}
        step = PAGE + self.flash.spare.length
        best: dict[int, tuple] = {}
        for page in range(len(self.raw) // step):
            at = page * step + PAGE
            fields = self.raw[at : at + self.flash.spare.length]
            kind = self.flash.spare.kind(fields)
            if kind not in lengths:
                continue
            version = self.flash.spare.sequence(fields)
            if kind not in best or (version, page) >= best[kind]:
                best[kind] = (version, page)
        out = {}
        for kind, (version, last) in sorted(best.items()):
            length = lengths[kind]
            start = last - (length // PAGE - 1)
            if start < 0:
                continue
            out[_named(kind)] = {"version": version, "page": start,
                                 "offset": start * PAGE, "length": length}
        return out

    def blob(self, name: str) -> bytes:
        """One settings blob's bytes, the live copy."""
        found = self.blobs[name]
        return self.flat[found["offset"] : found["offset"] + found["length"]]

    @property
    def directory(self) -> Directory:
        """The filesystem's table, out of the live copy of it."""
        found = self.blobs["fsroot"]
        block = self.flat[found["offset"] : found["offset"] + found["length"]]
        return Directory(block, self.flash.blocks)

    def read(self, name: str) -> bytes:
        """One file's bytes, following its chain of blocks and cut to its length."""
        table = self.directory
        for entry in table.entries:
            if entry.name != name:
                continue
            out = bytearray()
            for block in table.blocks_of(entry):
                at = self.flash.offset_of(block, self.bigffs)
                out += self.flat[at : at + table.block_length]
            return bytes(out[: entry.size])
        raise ValueError("%s is not a file in this image" % name)

    def __repr__(self) -> str:
        return "Image(%#x raw, %#x flat, %r)" % (
            len(self.raw), len(self.flat), self.flash
        )


def _named(kind: int) -> str:
    """What a blob of this kind is called.

    The console's own names, which is how the original spells them when it writes one
    out; its survey line spells a mobile with a small first letter instead.
    """
    if kind in (0x30, 0x2C):
        return "fsroot"
    return "Mobile%s.dat" % chr(ord("A") + kind - 0x30)
