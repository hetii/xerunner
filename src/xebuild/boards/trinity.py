"""Trinity, the first slim board."""

from .board import Board
from .flash import BigNandStatingSmallBlocks, SmallNand


class Trinity(Board):
    """What every Trinity shares."""

    section = "trinity"
    fat = False  # from here on a CD is keyed once, not twice
    copyright_year = 2010
    # No chain for this family in `_jtag.ini`, so the year below names a cell that the
    # original refuses before it reaches the notice.
    jtag_copyright_year = 2007

    smc_clean = "TRINITY_CLEAN.bin"
    smc_cr4 = "TRINITY_CR4.bin"
    smc_plus = "TRINITY_SMC+.bin"


class Trinity16(Trinity):
    flash = SmallNand()
    name = "trinity"
    text = "Trinity"


class TrinityBigBlock(Trinity):
    """A Trinity developer board carrying a 512 MB part."""

    flash = BigNandStatingSmallBlocks()
    name = "trinitybb"
    text = "Trinity (big block)"
