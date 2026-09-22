"""What every console answers, whichever one it is.

A console is a motherboard and the flash fitted to it, and this class is that pair. The
original models it the same way: it keeps a board word whose low three bits are the
motherboard -- 1 xenon, 2 zephyr, 3 falcon, 4 jasper, 5 trinity, 6 corona, 7 winchester
-- and whose top bits are set as `-c` is parsed to say what is fitted (a big block part,
the larger filesystem, an eMMC). The classes here follow those two axes: a family base
says what the motherboard is, a `Flash` from `flash.py` says what is fitted, and each
console is the class that inherits the family and names the flash.

Nothing here is configured, so nothing here has a setter. A console is not a set of
options someone chooses; it is a machine that already exists, and every field is a fact
about it that was measured. What a build chooses -- the hack, the release, the larger
filesystem -- is passed to the method that needs it and is never stored.
"""

from __future__ import annotations


class Board:
    """One console: a motherboard, and the flash fitted to it."""

    # --- the motherboard -------------------------------------------------------
    section = ""  # the ini section its chain is read from, without the `bl` suffix
    fat = False  # a fat chain keys its CD twice: HMAC(cpu, HMAC(prev, nonce))
    states_keyvault_size = True  # whether the image's header states it at 0x60
    copyright_year = 2009  # the year the image's copyright notice carries
    jtag_copyright_year = 2007  # and the year a JTAG image carries instead

    smc_clean = ""  # the stock SMC for this board
    smc_cr4 = ""  # its CR4 glitch image, where one exists
    smc_plus = ""  # its SMC+ glitch image, where one exists

    # --- the flash, and how the pair is spelled ---------------------------------
    flash = None  # an instance from `flash.py`
    name = ""  # what `-c` takes for this console
    text = ""  # what the original prints on its `Console :` line
    also = ()  # other spellings the original takes for the same machine

    # ----------------------------------------------------------------------------
    @property
    def bigffs(self) -> str:
        """The spelling that asks for the larger filesystem, or nothing.

        The family's own name with `bigffs` after it, and it exists exactly where the
        flash has room to move the filesystem. J-Runner builds the same spelling the
        same way.
        """
        return self.section + "bigffs" if self.flash.bigffs_base else ""

    @property
    def spellings(self) -> tuple:
        """Every `-c` spelling this console answers to."""
        return (self.name, *self.also, *((self.bigffs,) if self.bigffs else ()))

    @property
    def named(self) -> str:
        """What the original prints on its `Console :` line.

        Two consoles have no name there. Measured by building with each spelling:
        `coronabb`, `coronabigffs`, `winchesterbb` and `winchesterbigffs` are known to
        the original's layout dispatch and not to its naming dispatch, so a 66 MB image
        is built and the summary above it says the type was not caught.
        """
        return self.text or "whoops, console type was not caught!"

    def notice_year(self, hack: str = "") -> int:
        """The year the copyright notice in this image carries."""
        return self.jtag_copyright_year if hack == "jtag" else self.copyright_year

    def smc(self, kind: str = "clean") -> str:
        """The SMC image this board takes, by what is wanted of it."""
        return {
            "clean": self.smc_clean,
            "cr4": self.smc_cr4,
            "smc+": self.smc_plus,
        }[kind]

    # --- what the flash answers, asked of the console ----------------------------
    @property
    def spare(self):
        """The page layout, or None where the part has no spare area at all."""
        return self.flash.spare

    @property
    def length(self) -> int:
        return self.flash.length

    @property
    def raw_length(self) -> int:
        return self.flash.raw_length

    def offset_of(self, block: int, bigffs: bool = False) -> int:
        return self.flash.offset_of(block, bigffs)

    def stated_block_size(self) -> int:
        """What the header carries at 0x70, which is zero where it says nothing."""
        return self.flash.block_size if self.flash.states_block_size else 0

    def __repr__(self) -> str:
        return "%s(%r, %r)" % (type(self).__name__, self.name, self.flash)
