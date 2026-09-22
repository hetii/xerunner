"""The three ways a page's sixteen spare bytes are laid out.

This is the whole of what a console decides that is behaviour rather than a number.
Everything else about it -- how big its flash is, where its filesystem counts from,
which SMC it takes -- is a value, and values belong on the console. These three do not:
they read and write the same four fields from different offsets, so each is a small
object a flash points at rather than a branch someone has to keep writing.

They are the console's own `sfc.meta_type` 0, 1 and 2, named in `flash_config.c` as
released with xeBuild's source, and free60's "NAND File System" page declares the same
three as C structs, field for field:

    meta 0  Small Block                BlockID at 0-1, BadBlock at 5, FsSequence0 at 2
    meta 1  Big Block on a Small NAND  FsSequence0 at 0, BlockID at 1-2, BadBlock at 5
    meta 2  Big Block                  BadBlock at 0, BlockID at 1-2, FsSequence0 at 5

free60 says a block is 16 pages, or 32 on a big block chip, with 64 spare bytes there.
Read off images, a block is 32 pages and 256 respectively and the spare is 16 bytes in
both: free60 describes the raw chip, where a big block part really does have 2048 byte
pages, and the console's flash interface presents the same block as pages of 512.

An eMMC console has none of these: there is no spare area at all, so its flash answers
`None` and its image is written flat.
"""

from __future__ import annotations

# The shift register the flash controller runs over a page, and the table that makes it
# quick. It exclusive-ors the polynomial *before* shifting rather than after, so read as
# an ordinary reflected code the polynomial sits one place down, which is why it is
# written here shifted. The table is built once because the alternative is 0x1066 bit
# steps per page and a dump has tens of thousands of pages.
ECC_POLY = 0x6954559 >> 1
ECC_BITS = 0x1066  # 0x1000 of a page's data and the first 0x66 of its spare
ECC_TABLE = []
for _byte in range(256):
    _value = _byte
    for _ in range(8):
        _value = (_value >> 1) ^ (ECC_POLY if _value & 1 else 0)
    ECC_TABLE.append(_value)
ECC_TABLE = tuple(ECC_TABLE)


class Spare:
    """One layout. Only the offsets differ, so one body serves all three."""

    meta = -1
    number_at = 0  # the block number, least significant byte first
    mark_at = 0  # 0xFF unless the chip has marked the block bad
    sequence_at = 0  # free60's FsSequence0; the original's log calls it a version
    pages_a_block = 32

    extra_at = 8  # four bytes only a settings blob uses
    kind_at = 12  # the blob's kind in the low six bits, the ECC's top two above it
    length = 16

    def block_number(self, spare: bytes) -> int:
        return int.from_bytes(spare[self.number_at : self.number_at + 2], "little")

    def is_good(self, spare: bytes) -> bool:
        return spare[self.mark_at] == 0xFF

    def sequence(self, spare: bytes) -> int:
        return spare[self.sequence_at]

    def kind(self, spare: bytes) -> int:
        return spare[self.kind_at] & 0x3F

    def written(self, block: int, sequence: int = 0, kind: int = 0) -> bytes:
        """The field bytes for one page. The ECC is written over them separately."""
        out = bytearray(self.length)
        out[self.mark_at] = 0xFF
        out[self.number_at : self.number_at + 2] = block.to_bytes(2, "little")
        out[self.sequence_at] = sequence
        out[self.kind_at] = kind & 0x3F
        return bytes(out)

    # --- the code the controller keeps over a page -------------------------------
    # Where it sits is the same in all three layouts, which is why it is here and not
    # in one of them: the top two bits of byte 12, whose low six the kind uses, and the
    # three bytes after it. Twenty-six bits in all.
    def ecc(self, data: bytes, fields: bytes) -> int:
        """The code this page's data and fields ask for.

        A shift over 0x1066 bits -- the whole 512 of data and the first 0x66 of the
        spare -- with every byte inverted going in and the result inverted coming
        out. An image written back without recomputing this is the right length and
        the console refuses it, so this decides whether a rebuilt dump is usable.
        """
        whole, tail = ECC_BITS // 8, ECC_BITS % 8
        body = bytes(
            one ^ 0xFF for one in bytes(data) + bytes(fields)[: whole + 1]
        )
        value = 0
        for one in body[:whole]:
            value = (value >> 8) ^ ECC_TABLE[(value ^ one) & 0xFF]
        last = body[whole]
        for bit in range(tail):
            value ^= (last >> bit) & 1
            value = (value >> 1) ^ ECC_POLY if value & 1 else value >> 1
        return ~value & 0xFFFFFFFF

    def with_ecc(self, data: bytes, fields: bytes) -> bytes:
        """This page's spare with its code put right and nothing else touched.

        The rest of the spare carries the block number, the bad-block mark and the
        filesystem's bookkeeping, and rewriting any of it would throw away what the
        flash knows about itself.
        """
        out = bytearray(fields)
        value = self.ecc(data, out)
        out[self.kind_at] = (out[self.kind_at] & 0x3F) | ((value << 6) & 0xC0)
        out[self.kind_at + 1] = (value >> 2) & 0xFF
        out[self.kind_at + 2] = (value >> 10) & 0xFF
        out[self.kind_at + 3] = (value >> 18) & 0xFF
        return bytes(out)

    def ecc_ok(self, page: bytes) -> bool:
        """Whether a raw page -- data and the spare behind it -- carries its code."""
        if len(page) < 512 + self.length:
            return False
        data, fields = page[:512], bytes(page[512 : 512 + self.length])
        return self.with_ecc(data, fields)[self.kind_at :] == fields[self.kind_at :]

    def __repr__(self) -> str:
        return "%s(meta %d)" % (type(self).__name__, self.meta)


class SmallBlock(Spare):
    """meta 0 -- xenon, zephyr, falcon, and a Jasper with the older controller."""

    meta = 0
    number_at = 0
    mark_at = 5
    sequence_at = 2


class BigBlockController(Spare):
    """meta 1 -- a 16 MB part read by the newer controller."""

    meta = 1
    number_at = 1
    mark_at = 5
    sequence_at = 0


class BigBlockChip(Spare):
    """meta 2 -- a 256 or 512 MB part, whose blocks hold 256 pages rather than 32."""

    meta = 2
    number_at = 1
    mark_at = 0
    sequence_at = 5
    pages_a_block = 256
