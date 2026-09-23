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

**An image is in one of two states and they never mix.** One read in from a file is what
every mode but a build wants: it keeps the file it was handed, hands exactly those bytes
back, and **refuses to be written to at all** -- `put` says so, and its flat run is
immutable, so a structure's setter refuses as well. A console's dump is the material a
build reads from and is needed whole until the build has finished, so the class is what
keeps it safe rather than the care of whoever is calling.

One started with `blank` is the other state: no file, an erased flat run, and writing
allowed. Every structure here is a **view** on that run, so setting `header.version`
writes into the image itself. `raw` then assembles the file the part holds -- page,
spare, page, spare -- computing each page's code over what it ends up holding, which is
the only thing a build can do, since the content is its own.

The round trip between the two forms is proved rather than assumed: on this console's
own dump, taking it apart and putting it back gives the same 17,301,504 bytes.

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

from .anchor import Anchor
from .directory import Directory
from .header import Header

PAGE = 512
BLOCK = 0x4000  # what an anchor counts in, and what a directory entry counts in


class Image:
    """One flash image, read through the flash that holds it."""

    def __init__(self, raw: bytes, flash, bigffs: bool = False):
        self.flash = flash
        self.bigffs = bigffs
        # The file as it was handed over, and None on an image being built, which is
        # what tells the two states apart. A read keeps it for two reasons: it is what
        # `raw` gives back, so nothing is recomputed over bytes somebody else measured,
        # and while it is here this image is not one anything may write to.
        self.file = bytes(raw)
        self.flat = flash.flatten(self.file)
        self.spares = _spares(self.file, flash)

    @classmethod
    def blank(cls, flash, bigffs: bool = False) -> Image:
        """An erased image of this flash's length, ready to be filled.

        Erased flash is 0xFF and so is a spare nothing has written to, which is what a
        part reads before anything is put on it.
        """
        one = cls(b"", flash, bigffs)
        one.file = None
        one.flat = bytearray(b"\xff" * flash.length)
        if flash.spare is not None:
            pages = flash.length // PAGE
            one.spares = [b"\xff" * flash.spare.length for _ in range(pages)]
        return one

    @property
    def writable(self) -> bool:
        """Whether this is an image being built rather than a file read in."""
        return self.file is None

    @property
    def raw(self) -> bytes:
        """The file the part holds: the one that was read in, or the one being built.

        A read hands back what it was given, so a dump comes out of here exactly as
        it went in -- a page whose stored code does not match its content keeps that
        code, and saying so is `Spare.ecc_ok`'s job rather than this one's. A build has
        no such file and assembles one, computing each page's code over what it holds.
        """
        if not self.writable:
            return self.file
        return self.flash.unflatten(bytes(self.flat), self.spares)

    def put(self, at: int, data: bytes) -> None:
        """`data` into the flat run at `at`, on an image that is being built.

        Two refusals, and both of them are silent damage if they are left out. An image
        read in from a file is material -- a console's dump is what everything else is
        made from -- so writing into it would take away what has not been used yet. And
        an image is a fixed length, so bytes past its end are not bytes the part would
        hold: they would simply be dropped, and a region written one span too high is
        exactly the mistake that has to be loud.
        """
        if not self.writable:
            raise ValueError(
                "this image was read in from a file and is material, not a canvas; "
                "start from Image.blank() to build one"
            )
        if at < 0 or at + len(data) > len(self.flat):
            raise ValueError(
                "%#x bytes at %#x do not fit in an image of %#x"
                % (len(data), at, len(self.flat))
            )
        self.flat[at : at + len(data)] = data

    @property
    def header(self) -> Header:
        return Header(self.flat)

    @property
    def blobs(self) -> dict:
        """Every settings blob, by name: which page, where, how long, which version.

        Two flashes answer this two ways, because a blob is found two ways. A NAND is
        scanned page by page through its spare bytes; an eMMC part has no spare and
        names its blobs in an anchor block instead.
        """
        if self.flash.spare is None:
            return self._from_anchor()
        return self._from_spare()

    def _from_anchor(self) -> dict:
        """What the anchor an eMMC console would believe says is where.

        A version is not in it. The original reports 1 for every blob it reads this way,
        the filesystem table included, and 1 is what is reported here -- measured on an
        image it built and then read back.
        """
        one = Anchor.chosen(bytes(self.flat))
        out = {}
        for kind, (block, length) in one.blobs.items():
            out[_named(kind)] = _found(block * BLOCK, length, 1)
        out["fsroot"] = _found(one.table * BLOCK, 0x4000, 1)
        return out

    def _from_spare(self) -> dict:
        """Every blob a NAND's spare bytes point at.

        The kinds and their lengths are a table because nothing in flash states them: a
        blob is not a file and has no directory entry. The filesystem table wears 0x30
        on a 16 MB image and 0x2C on a big block chip, which is why both are here -- a
        scan that knew only 0x30 found the mobiles in a 64 MB image and no table.
        """
        lengths = {0x30: 0x4000, 0x2C: 0x4000,
                   0x31: 0x800, 0x32: 0x200, 0x33: 0x800, 0x34: 0x800}
        best: dict[int, tuple] = {}
        for page, fields in enumerate(self.spares):
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
            out[_named(kind)] = _found(start * PAGE, length, version)
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
        return "Image(%#x flat, %d pages of spare, %s, %r)" % (
            len(self.flat), len(self.spares),
            "being built" if self.writable else "read in", self.flash,
        )


def _spares(raw: bytes, flash) -> list:
    """The field bytes of every page of a file; none at all where a part has no spare.

    `order._spares` does this for a dump on its way in. This one answers for a file that
    is short or not there at all as well, which is what `blank` starts from.
    """
    if flash.spare is None:
        return []
    step = PAGE + flash.spare.length
    return [
        bytes(raw[at + PAGE : at + step])
        for at in range(0, len(raw) - step + 1, step)
    ]


def _found(offset: int, length: int, version: int) -> dict:
    """One blob, the same shape whichever way it was found."""
    return {"version": version, "page": offset // PAGE,
            "offset": offset, "length": length}


def _named(kind: int) -> str:
    """What a blob of this kind is called.

    The console's own names, which is how the original spells them when it writes one
    out; its survey line spells a mobile with a small first letter instead.
    """
    if kind in (0x30, 0x2C):
        return "fsroot"
    return "Mobile%s.dat" % chr(ord("A") + kind - 0x30)
