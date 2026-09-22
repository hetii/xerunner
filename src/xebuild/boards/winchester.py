"""Winchester, the last board, and the only one with no glitch SMC at all."""

from .board import Board
from .flash import BigNandStatingSmallBlocks, Emmc, SmallNand


class Winchester(Board):
    """What every Winchester shares."""

    section = "winchester"
    fat = False
    copyright_year = 2010
    jtag_copyright_year = 2007  # no chain in `_jtag.ini`; the cell is refused

    smc_clean = "WINCHESTER_CLEAN.bin"  # and there is no CR4 or SMC+ for this board


class Winchester16(Winchester):
    flash = SmallNand()
    name = "winchester"
    text = "Winchester"


class WinchesterBigBlock(Winchester):
    """A Winchester with big block NAND.

    The same hole as `CoronaBigBlock`: measured, `-c winchesterbb` builds a 66 MB image
    -- `aac.xexp1` at 0x3900220, and at 0x1900220 for `winchesterbigffs` -- and its
    summary says the console type was not caught.
    """

    flash = BigNandStatingSmallBlocks()
    name = "winchesterbb"
    text = ""


class Winchester4G(Winchester):
    flash = Emmc()
    name = "winchester4g"
    text = "Winchester"
