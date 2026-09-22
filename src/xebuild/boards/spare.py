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
