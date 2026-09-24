"""The flash shapes an image can have.

A console is a motherboard and the part fitted to it; five of the shapes here are those
parts, and they serve all fourteen consoles. The sixth belongs to no console: it is the
shape two image types carry whatever board they are built for. Nothing here knows who
selects it -- a `Board` points at a `Flash`, never the other way round.

They hold no logic, only what follows from the silicon -- how long the image is, where
its filesystem counts from, how much room a bootloader region gets. The one thing that
is not a number, the spare layout, is an object from `spare.py`.

The original's layout routine sets exactly four of these: the block count, the SMC
configuration offset, the last usable block and the filesystem base. The rest was
measured to follow either the part or the image's length, which is why they sit here
too; where a shape has no console, the ones that follow the part have no answer.

Two pairs of numbers look like one number each until a flash that is not 16 MB is built.

`part` is the silicon; `blocks` is the image. They are different questions. No console
was ever fitted with a 64 MB part in the sense the word is used for an image: a 64 MB
image is the system area at the front of a 256 or 512 MB chip, and a 48 MB image the
front of a 4 GB eMMC. A part that really is 64 MB exists in a developer Xenon, Zephyr or
Falcon, and the image built for it is the same 16 MB as for its 16 MB sibling.

`block_size` is the part's erase block, which is how much room CF and CG are given.
`round_to` is what the bootloader region's start rounds up to, and it follows the
image's size rather than the part's: every 64 MB image rounds to 0x20000 and every
smaller one to 0x4000. So a Trinity with a big block part states 0x10000 and rounds
to 0x20000.

Measured off images, with the filesystem base read from a real directory entry -- taking
it from the bytes the CG tail ends in finds the CG's own body instead, because the two
share bytes.
"""

from __future__ import annotations

from .spare import PAGE, BigBlockChip, BigBlockController, SmallBlock

# One erase block of the filesystem's own reckoning: what a directory entry counts in,
# what an anchor counts in, and what a settings blob gets one of. A part's own erase
# block is `block_size`, and it is not always this.
BLOCK = 0x4000


class Flash:
    """What is fitted to a motherboard."""

    part = ""  # the silicon, which is not the same question as the image's length
    blocks = 0  # how long the image is, in 0x4000 byte blocks
    smc_config = 0  # where the console's settings block goes
    last_block = 0  # the last block a build may use
    filesystem_base = 0  # the block a directory entry counts from
    bigffs_base = None  # and where it counts from when a larger filesystem is asked for

    block_size = 0x10000  # the part's erase block; the room CF and CG get
    states_block_size = True  # whether the image's header says so at 0x70
    round_to = BLOCK  # what the bootloader region's start rounds up to

    mobile_stride = BLOCK  # a settings blob gets its own block ...
    mobile_region = 0x10000  # ... unless they are packed into one region of this size

    spare = None  # one of `spare.py`'s three, or None on a part with no spare area
    anchors = False  # two blocks an eMMC console needs to find its own filesystem
    # Whether the blocks past the last usable one are a pool for bad ones, which the
    # table leaves unnamed; where not, it reserves every one of them.
    pool = True

    @property
    def length(self) -> int:
        """The image as the console addresses it, without any spare bytes."""
        return self.blocks * BLOCK

    @property
    def raw_length(self) -> int:
        """The file on disk: a spare follows every page."""
        if self.spare is None:
            return self.length
        return self.length // PAGE * (PAGE + self.spare.length)

    def flatten(self, raw: bytes) -> bytes:
        """The image as the console addresses it, with the spare bytes taken out.

        Everything that reads an image -- the header, the chain, the filesystem --
        counts from the flat run, and every offset in it is wrong while the spare is
        still there. Nothing raises when it is: the chain is simply not where it should
        be. An eMMC part has no spare, so this hands the bytes straight back.
        """
        if self.spare is None:
            return bytes(raw)
        step = PAGE + self.spare.length
        return b"".join(
            bytes(raw[at : at + PAGE]) for at in range(0, len(raw) - step + 1, step)
        )

    def unflatten(self, flat: bytes, spares) -> bytes:
        """The image the way the part holds it: every page followed by its own spare.

        The inverse of `flatten`, and the half of building that can be checked without a
        console -- take a dump apart, put it back, and the bytes either match or they do
        not. `spares` is one run of field bytes a page, and each page's code is computed
        over what it actually ends up holding.

        A spare of nothing but zeros is left alone. That is a retired block, and the
        whole point of zeroing it is that nothing is left to read, the code included.
        Nothing else can be all zeros: a written page carries a 0xFF mark somewhere and
        an erased one is 0xFF throughout.
        """
        if self.spare is None:
            return bytes(flat)
        out = bytearray()
        for index, at in enumerate(range(0, len(flat), PAGE)):
            page = bytes(flat[at : at + PAGE]).ljust(PAGE, b"\x00")
            fields = (
                bytes(spares[index])
                if index < len(spares)
                else bytes(self.spare.length)
            )
            out += page + (self.spare.with_ecc(page, fields) if any(fields) else fields)
        return bytes(out)

    def base_of(self, bigffs: bool = False) -> int:
        """The block the filesystem counts from, with or without the larger one."""
        if bigffs and self.bigffs_base is not None:
            return self.bigffs_base
        return self.filesystem_base

    def offset_of(self, block: int, bigffs: bool = False) -> int:
        """Where a directory's block number actually points."""
        return (self.base_of(bigffs) + block) * BLOCK

    def __repr__(self) -> str:
        return "%s(%#x blocks)" % (type(self).__name__, self.blocks)


class SmallBlockNand(Flash):
    """16 MB on the older controller: xenon, zephyr, falcon, and a Jasper XSB.

    Its header leaves 0x70 at zero -- the block size is stated only where the controller
    is a big block one. This is the one profile a genuine 64 MB part answers to, in a
    developer machine, and the extra room goes unused.
    """

    part = "16 MB NAND, or a 64 MB one in a developer machine"
    blocks = 0x400
    smc_config = 0xF7C000
    last_block = 0x3DC
    states_block_size = False
    spare = SmallBlock()


class SmallNand(Flash):
    """16 MB read by the newer controller: jasper, trinity, corona, winchester."""

    part = "16 MB NAND"
    blocks = 0x400
    smc_config = 0xF7C000
    last_block = 0x3DC
    spare = BigBlockController()


class BigBlockNand(Flash):
    """The system area of a 256 or 512 MB part -- only Jasper's.

    The one flash whose header states 0x20000, which is what its blocks of 256 pages
    really erase in. What lies past the system area is the console's memory unit.
    """

    part = "256 or 512 MB NAND; the image is its first 64 MB"
    blocks = 0x1000
    smc_config = 0x3BE0000
    last_block = 0xEE0
    filesystem_base = 0xAE0
    bigffs_base = 0x2E0
    block_size = 0x20000
    round_to = 0x20000
    mobile_stride = 0x800
    mobile_region = 0x20000
    spare = BigBlockChip()


class BigNandStatingSmallBlocks(BigBlockNand):
    """The same part on Trinity, Corona and Winchester.

    Identical to `BigBlockNand` but for the block size its header states: 0x10000, while
    the spare beside it is laid out as meta 2, which goes with 0x20000. Both cannot be
    true of one console and the spare is the one that is right, so the header field is
    wrong and is written that way regardless: the console takes `meta_type` from its
    controller's configuration register and never reads this, and a reader that derives
    the layout from the image's length is unaffected.

    Measured: `-c trinitybb` and `-c winchesterbb` put `aac.xexp1` at 0x3900220, and
    their `bigffs` spellings at 0x1900220.
    """

    part = "512 MB NAND; the image is its first 64 MB"
    block_size = 0x10000


class Emmc(Flash):
    """48 MB of usable flash inside a 4 GB eMMC: Corona 4GB and Winchester 4GB.

    No spare area at all, so there are no bookkeeping bytes a page and no ECC over them,
    and the image is exactly as long as the flash. Anchor blocks are what such a console
    keeps in place of scanning for its filesystem.
    """

    part = "4 GB eMMC; the image is its first 48 MB"
    blocks = 0xC00
    smc_config = 0x2FFC000
    last_block = 0xBFA
    anchors = True
    pool = False


class FlatBigNand(Flash):
    """64 MB with the filesystem counting from zero: a devkit image on a small block
    console.

    The shape a `devkit` or a `testkit` image takes on a console whose controller is a
    small block one -- xenon, zephyr, falcon, a 16 MB jasper -- whatever part it
    has; on a big block console the same type takes that console's own shape with the
    larger filesystem instead. The layout routine's arm at 0x40F3D7 gives the four
    numbers below, and the rest was measured on four devkit images the original built
    for xenon, falcon and jasper: the console's own spare layout, a region rounded to
    0x4000, one 0x4000 block a settings blob, the statistics one block under the
    settings, and 0x10000 stated at 0x70 on every one -- where a 16 MB falcon image of
    any other type states nothing there.

    `spare` is the console's, which is why this is made per console.
    """

    part = "no part of its own; the shape a devkit image takes on a small block console"
    blocks = 0x1000
    smc_config = 0x3DFC000
    last_block = 0xF7C
    pool = False  # the table reserves 0xF7C to the end, measured

    def __init__(self, spare):
        self.spare = spare
