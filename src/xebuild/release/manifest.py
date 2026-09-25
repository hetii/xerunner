"""`system.manifest`: the list a system update keeps of the files it puts on a console's
hard disk, which avatar data is sent from -- `client -e`, and update mode when a
system update sits in the release's directory.

The original checks the header before it reads a row (0x4327A0), in this order, and
refuses on the first that fails:

    size     between 0x164 and 0x10000 bytes -- "manifest size error! len 0x%x"
    0x148    schema, 3                        -- "manifest schema != 3!"
    0x138    revision, `xsym` or `xonm`       -- "manifest revision 0x%08x != ..."
    0x000    magic, `XMNP`                    -- "manifest magic 0x%08x != ..."
    0x024    SHA-1 of the body: from 0x138, as many bytes as 0x13C says
                                              -- "manifest checksum failed!"

Everything after 0x138 is the body, and every offset a row carries counts from there.
The body keeps the row count at +0x2C and the rows from +0x30, 0x60 bytes apiece;
0x14C of the file is the flash version the update belongs to.

A row, as the walk at 0x432190 reads it:

    +0x00  where the file's name is           +0x20  where its name on the console is
    +0x08  its size                           +0x24  a container's header hash
    +0x0C  where its version is (a pointer)   +0x38  a plain file's SHA-1
    +0x18  what it is: 2 container, 3 file    +0x4C  a container's content type
                                              +0x50  a container's title
"""

from __future__ import annotations

import struct
import hashlib

BODY = 0x138


def _be32(raw: bytes, at: int) -> int:
    return struct.unpack_from(">I", raw, at)[0] if at + 4 <= len(raw) else 0


class Entry:
    """One row of a manifest, its offsets already followed."""

    def __init__(self, body: bytes, row: bytes):
        self.body, self.row = body, row

    def _name(self, at: int) -> str:
        """A name the body keeps: two bytes of big-endian length and then that many
        bytes, the terminator counted in, cut at the first zero as the copy is."""
        where = _be32(self.row, at)
        if where + 2 > len(self.body):
            return ""
        (length,) = struct.unpack_from(">H", self.body, where)
        text = self.body[where + 2:where + 2 + length]
        return text.split(b"\x00")[0].decode("latin-1")

    @property
    def source(self) -> str:
        """The file's name beside the manifest; empty where the row has none."""
        return self._name(0x00) if _be32(self.row, 0x00) else ""

    @property
    def target(self) -> str:
        """Its name on the console, and the source name where the row names none --
        the original reads it into the buffer the source name is in and leaves that
        alone when the length is zero."""
        return (self._name(0x20) if _be32(self.row, 0x20) else "") or self.source

    @property
    def size(self) -> int:
        return _be32(self.row, 0x08)

    @property
    def version(self) -> int:
        """The version it belongs to, which a plain file's directory is named for:
        four bytes the row points at, not four it carries; zero where it points
        nowhere."""
        where = _be32(self.row, 0x0C)
        return _be32(self.body, where) if where else 0

    @property
    def kind(self) -> int:
        """2 for a container, 3 for a plain file; the original sends nothing else."""
        return _be32(self.row, 0x18)

    @property
    def header_hash(self) -> bytes:
        return self.row[0x24:0x38]

    @property
    def hash(self) -> bytes:
        return self.row[0x38:0x4C]

    @property
    def content_type(self) -> int:
        return _be32(self.row, 0x4C)

    @property
    def title(self) -> int:
        return _be32(self.row, 0x50)

    def __repr__(self) -> str:
        return "Entry(%s, %#x bytes, kind %d)" % (self.source, self.size, self.kind)


class Manifest:
    """A `system.manifest`, read. Takes the bytes; finding the file is the caller's."""

    def __init__(self, raw: bytes):
        self.raw = bytes(raw)

    def refusal(self) -> str | None:
        """Why the original would not read this one, in its words, or None."""
        raw = self.raw
        if not 0x164 <= len(raw) <= 0x10000:
            return "manifest size error! len 0x%x" % len(raw)
        if _be32(raw, 0x148) != 3:
            return "manifest schema != 3!"
        revision = _be32(raw, BODY)
        if revision not in (0x7873796D, 0x786F6E6D):
            return "manifest revision 0x%08x != 0x786F6E6D|0x7873796D!" % revision
        if _be32(raw, 0) != 0x584D4E50:
            return "manifest magic 0x%08x != 0x584D4E50!" % _be32(raw, 0)
        hashed = raw[BODY:BODY + _be32(raw, 0x13C)]
        if hashlib.sha1(hashed).digest() != raw[0x24:0x38]:
            return "manifest checksum failed!"
        return None

    @property
    def version(self) -> int:
        """The flash version the update belongs to, packed as a kernel's is."""
        return _be32(self.raw, 0x14C)

    @property
    def entries(self) -> list:
        """Every row with a name, in order."""
        body = self.raw[BODY:]
        out = []
        for index in range(_be32(body, 0x2C)):
            at = 0x30 + index * 0x60
            if at + 0x60 > len(body):
                break
            one = Entry(body, body[at:at + 0x60])
            if one.source:
                out.append(one)
        return out

    def __repr__(self) -> str:
        return "Manifest(%d entries)" % len(self.entries)
