"""The package a release ships its dashboard in, and the two bootloaders inside it.

A release does not carry its firmware files loose. They live in one signed package --
`su20076000_00000000`, twelve megabytes of it -- in the format the console uses for
everything it downloads. The original says so as it opens one: "loading system update
container", "Read 0xb50000 bytes to memory", "extracted SUPD/xboxupd.bin".

**Blocks are not where their numbers say.** Data blocks are 0x1000 bytes and the first
sits at 0xC000, but hash tables are laid among them -- one every 0xAA blocks and one
every 0x70E4 -- so a block's place is its number plus the tables that come before it.

**A table is one block here, and the package is asked rather than told.** A byte in the
volume descriptor is usually read as saying whether tables are one block or two; on this
package it says two and the truth is one, which reproduces every checksum the release
states while two reproduces three of twenty-two. So this finds the first data block's
own SHA-1 in the table below it: 0xB000 for one-block tables and 0xA000 for two.

**Firmware files wear a `$flash_` prefix inside the package** that they do not wear in a
recipe or in a finished image: the recipe asks for `dash.xex` and the package holds
`$flash_dash.xex`.

**`xboxupd.bin` is a CF followed by a CG**, and nothing else: 0x4560 and 0x77A76 here,
which come to exactly its 0x7BFE0. They arrive sealed, and the chain simply continues
into the release -- the CF opens under the key every console carries, and the CF then
holds the key that opens the CG, sixteen bytes at 0x330 of it.

Checked the only way that means anything: opened and put in the canonical form the
release's own readme describes, the two reproduce the checksums the recipe states,
0x0883E155 and 0x10FBC84D. Every firmware file in the package reproduces its own as
well, twenty-two of twenty-two.
"""

from __future__ import annotations

import hashlib
import struct

from ..chain import sealing
from ..chain.stage import Stage

BLOCK = 0x1000
DATA_AT = 0xC000
# How many blocks one hash table covers, and how many of those the table above it does.
SPAN, SPAN2 = 0xAA, 0x70E4


def intact(raw: bytes, header_hash: bytes = b"", content_type: int = 0, title: int = 0,
           magic: bytes = b"") -> bool:
    """Whether a package holds together the way the original checks one before it
    sends it anywhere (0x405FA0, 0x405610).

    Its header is hashed from 0x344 to the header's size (0x340, rounded up to a
    block) against 0x32C, and a hash a manifest lists for it has to be that same
    0x32C -- unless the manifest's twenty bytes are all zero. Then each data block
    against its row in the table above it, a table at a time; a table whose first
    row has a zero word at +0x14 is taken for the table above tables, hashed against
    0x381 and checked to hold the first table's hash, and every table after it is
    checked against its next row. A zero row ends a table early, and a package ends
    where two blocks no longer fit.

    Only two levels are walked, as there: a package past 0x70E4 blocks would need a
    third, and none sent was that large. The layout is taken as the original takes
    it, one block to a table, which is not `Package`'s reading of its own tables --
    a check and a reader, not one thing.

    Three fields are asked for first where the caller names them, as the update
    container is loaded (0x40CB2C): the content type at 0x344 (`0x000B0000`), the
    title at 0x360 (`0xFFFE07D1`) and four bytes at 0x971A (`SUPD`). The avatar
    containers are sent with none of them asked.
    """
    raw = bytes(raw)
    if len(raw) < 0x344:
        return False
    if content_type and struct.unpack_from(">I", raw, 0x344)[0] != content_type:
        return False
    if title and (len(raw) < 0x364
                  or struct.unpack_from(">I", raw, 0x360)[0] != title):
        return False
    if magic and raw[0x971A:0x971A + len(magic)] != magic:
        return False
    if any(header_hash) and raw[0x32C:0x340] != bytes(header_hash):
        return False
    head = (struct.unpack_from(">I", raw, 0x340)[0] + BLOCK - 1) & ~(BLOCK - 1)
    if hashlib.sha1(raw[0x344:head]).digest() != raw[0x32C:0x340]:
        return False

    def matches(at: int, wanted: bytes) -> bool:
        return hashlib.sha1(raw[at:at + BLOCK]).digest() == wanted[:0x14]

    table, data, counted = head, head + BLOCK, 0
    above, row = None, 0x18
    while True:
        end, full = counted + SPAN, False
        while True:
            entry = raw[table:table + 0x18]
            if not any(entry):
                break
            if not matches(data, entry):
                return False
            counted, table, data = counted + 1, table + 0x18, data + BLOCK
            if counted == end:
                full = True
                break
        if data + 2 * BLOCK >= len(raw):
            return True
        if not any(raw[data + 0x14:data + 0x18]):
            if not matches(data, raw[0x381:0x395]) or not matches(head, raw[data:]):
                return False
            above, data = data, data + BLOCK
        if above is not None and not matches(data, raw[above + row:]):
            return False
        table, data, row = data, data + BLOCK, row + 0x18
        if not full:
            return True


class Held:
    """One file the package holds: where its blocks are and how long it is."""

    def __init__(self, row: bytes):
        self.row = bytes(row)

    @property
    def name(self) -> str:
        return self.row[: self.row[0x28] & 0x3F].decode("latin-1")

    @property
    def blocks(self) -> int:
        return int.from_bytes(self.row[0x29:0x2C], "little")

    @property
    def first(self) -> int:
        return int.from_bytes(self.row[0x2F:0x32], "little")

    @property
    def length(self) -> int:
        return struct.unpack_from(">I", self.row, 0x34)[0]

    @property
    def consecutive(self) -> bool:
        """Whether its blocks run one after another rather than as a chain."""
        return bool(self.row[0x28] & 0x40)

    def __repr__(self) -> str:
        return "Held(%s, %#x bytes)" % (self.name, self.length)


class Package:
    """A signed package, read. Takes the bytes; opening the file is the caller's."""

    def __init__(self, raw: bytes):
        self.raw = bytes(raw)
        if self.raw[:4] not in (b"CON ", b"LIVE", b"PIRS"):
            raise ValueError(
                "this is not a signed package; it begins %r" % self.raw[:4]
            )
        self.wide = self._wide()

    def _wide(self) -> bool:
        """Whether a hash table takes two blocks, asked of the package itself."""
        want = hashlib.sha1(self.raw[DATA_AT : DATA_AT + BLOCK]).digest()
        for at, wide in ((0xB000, False), (0xA000, True)):
            if self.raw[at : at + len(want)] == want:
                return wide
        raise ValueError("no hash table in this package holds its first block")

    def _at(self, block: int) -> int:
        """Where a data block's bytes actually are."""
        step = 2 if self.wide else 1
        before = 0
        if block >= SPAN:
            before += (block // SPAN + 1) * step
        if block >= SPAN2:
            before += (block // SPAN2 + 1) * step
        return DATA_AT + (block + before) * BLOCK

    @property
    def name(self) -> str:
        """What the package calls itself, which it writes in wide characters."""
        return self.raw[0x411:0x439].decode("utf-16-be", "replace").rstrip("\x00")

    @property
    def held(self) -> dict:
        """Everything in the package, by name."""
        out = {}
        first = int.from_bytes(self.raw[0x37E:0x381], "little")
        count = struct.unpack_from("<H", self.raw, 0x37C)[0]
        for block in range(count):
            at = self._at(first + block)
            for index in range(BLOCK // 0x40):
                row = self.raw[at + index * 0x40 : at + (index + 1) * 0x40]
                if not row or not row[0]:
                    return out
                one = Held(row)
                out[one.name] = one
        return out

    def read(self, name: str) -> bytes:
        """One file's bytes.

        A file whose blocks are a chain rather than a run is refused. Every file in
        every package here is a run, so nothing would check an implementation of the
        other, and a wrong one would hand back plausible bytes.
        """
        one = self.held.get(name)
        if one is None:
            raise ValueError("%s is not in this package" % name)
        if not one.consecutive:
            raise ValueError(
                "%s is kept as a chain of blocks, which nothing here can check" % name
            )
        body = b"".join(
            self.raw[self._at(one.first + n) : self._at(one.first + n) + BLOCK]
            for n in range(one.blocks)
        )
        return body[: one.length]

    def __repr__(self) -> str:
        return "%s(%s, %d files)" % (type(self).__name__, self.name,
                                     len(self.held))


class Container(Package):
    """A release's update container: its firmware files, and its CF and CG."""

    def firmware_name(self, name: str) -> str | None:
        """What the package calls a firmware file a recipe names, or None.

        Matched without regard to case, as the original matches: 9199's package holds
        `$flash_XenonCLatin.xttp` for the `xenonclatin.xttp` its list names, and the
        original's log says "extracted SUPD/xenonclatin.xttp".
        """
        wanted = ("$flash_" + name).lower()
        for held in self.held:
            if held.lower() == wanted:
                return held
        return None

    def firmware(self, name: str) -> bytes:
        """One firmware file, under the name a recipe uses for it."""
        held = self.firmware_name(name)
        if held is None:
            raise ValueError("%s is not in this package" % name)
        return self.read(held)

    @property
    def stages(self) -> tuple:
        """The CF and the CG, opened, in that order.

        They are sealed and they are not independent: the CF opens under the key every
        console carries, and holds the key the CG opens under.
        """
        raw = self.read("xboxupd.bin")
        cf = Stage(raw, 0)
        opened = sealing.under(cf, sealing.ONE_BL_KEY)
        cg = Stage(raw, cf.length)
        # Sixteen bytes at 0x330 of the opened CF are what the CG is keyed from.
        return opened, sealing.under(cg, opened[0x330:0x340])
