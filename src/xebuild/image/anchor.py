"""The two blocks an eMMC console keeps in place of scanning its flash.

A NAND console finds its settings blobs by reading the spare bytes of every page: each
says what kind of blob the page belongs to and which version of it. An eMMC part has
no spare area at all, so there is nothing to scan, and the image carries two copies of
a small structure saying where everything went. The original calls them anchors::

    copying anchor block 1 to offset 0x2fe8000
    copying anchor block 2 to offset 0x2fec000

Read off images the original built for `corona4g`, every number cross-checked against
what the same run said it was doing:

    0x00  20  SHA-1 of the rest of the structure, no key
    0x14   4  zero
    0x18   4  which anchor this is
    0x1C   2  the block the filesystem table went to
    0x1E   2  zero
    0x20  16  four settings blobs, each a block and a length
    0x30     zero to the end of the structure

Both the reading rule and the writing rule were measured rather than inferred.

**Which anchor a reader believes is decided by the number, not by where it sits.**
With the numbers swapped over -- 2 in the first block and 1 in the second -- the
original selects the first, and says so: "anchor block v 2 at 0x2fe8000 is selected".
The number is not policed either: an anchor numbered 9 is accepted and wins. A copy
whose hash disagrees is skipped, and when neither survives the original refuses the
image outright with "Could not find fsroot!".

**A blob's slot is its type, not its turn.** Built with only MobileC and MobileE
present, the structure fills slots 1 and 3 and leaves 0 and 2 at zero, while the bodies
are packed one after another in the image. So slot index is type minus 0x31, and an
absent blob leaves a hole.

Only one flash shape has anchors, so the two offsets are stated here rather than asked
of the shape; there is nothing yet to tell a rule from a constant.
"""

import struct
import hashlib

AT = (0x2FE8000, 0x2FEC000)
LENGTH = 0x200
HASH = 0x14

# From 0x14 to 0x30 in one go: a zero, the number, the table's block and a zero, then
# the four (block, length) pairs.
BODY = ">2I2H8H"

# The kind the first slot stands for; a NAND's spare bytes use the same numbers.
FIRST_KIND = 0x31
SLOTS = 4


class Anchor:
    """What one anchor says: which copy it is, and where the bookkeeping went.

    Everything here is in blocks, because that is what the structure holds. Turning a
    block into an offset is the flash's job and not this one.
    """

    def __init__(self, number: int, table: int, blobs: dict):
        self.number = number
        self.table = table
        self.blobs = dict(blobs)

    @classmethod
    def parse(cls, block: bytes) -> Anchor:
        """One anchor out of its bytes, refusing a copy whose hash disagrees."""
        block = bytes(block[:LENGTH])
        if len(block) < LENGTH:
            raise ValueError(
                "an anchor is %#x bytes and this is %#x" % (LENGTH, len(block))
            )
        if hashlib.sha1(block[HASH:]).digest() != block[:HASH]:
            raise ValueError("this anchor's hash does not match what follows it")
        _zero, number, table, _also, *slots = struct.unpack_from(BODY, block, HASH)
        blobs = {}
        for index in range(SLOTS):
            at, length = slots[index * 2], slots[index * 2 + 1]
            if at or length:
                blobs[FIRST_KIND + index] = (at, length)
        return cls(number, table, blobs)

    @classmethod
    def chosen(cls, raw: bytes) -> Anchor:
        """The anchor an eMMC console would believe: the highest number that parses."""
        found = []
        for at in AT:
            try:
                found.append(cls.parse(raw[at : at + LENGTH]))
            except ValueError:
                continue
        if not found:
            raise ValueError(
                "neither anchor block parses, so this image names no filesystem"
            )
        return max(found, key=lambda one: one.number)

    @property
    def encoded(self) -> bytes:
        """This anchor as the structure, hash and all."""
        slots = []
        for index in range(SLOTS):
            slots.extend(self.blobs.get(FIRST_KIND + index, (0, 0)))
        out = bytearray(LENGTH)
        struct.pack_into(BODY, out, HASH, 0, self.number, self.table, 0, *slots)
        out[:HASH] = hashlib.sha1(bytes(out[HASH:])).digest()
        return bytes(out)

    def __repr__(self) -> str:
        return "Anchor(%d, table at block %#x, %d blobs)" % (
            self.number, self.table, len(self.blobs)
        )


def lay(image, table: int, blobs: dict) -> None:
    """Both anchors written into `image` where an eMMC console looks for them.

    Each is given 0x1000 bytes and the rest of its 0x4000 block is left as it was: in an
    image the original built, the structure is followed by zeros to 0x1000 and by erased
    flash from there to the end of the block.
    """
    span = 0x1000
    for number, at in enumerate(AT, start=1):
        image.put(at, Anchor(number, table, blobs).encoded.ljust(span, b"\x00"))
