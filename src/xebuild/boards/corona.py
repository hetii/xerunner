"""Corona, the first family fitted with an eMMC."""

from .board import Board
from .flash import BigNandStatingSmallBlocks, Emmc, SmallNand


class Corona(Board):
    """What every Corona shares."""

    section = "corona"
    fat = False
    copyright_year = 2010
    jtag_copyright_year = 2007  # no chain in `_jtag.ini`; the cell is refused

    smc_clean = "CORONA_CLEAN.bin"
    smc_cr4 = "CORONA_CR4.bin"
    smc_plus = "CORONA_SMC+.bin"


class Corona16(Corona):
    flash = SmallNand()
    name = "corona"
    text = "Corona"


class CoronaBigBlock(Corona):
    """A Corona with big block NAND rather than eMMC.

    Both its spellings are absent from the original's usage text and from its naming
    dispatch, though its layout dispatch knows them: measured, `-c coronabb` builds a
    66 MB image whose summary says the console type was not caught. `text` is empty
    because there is no string to carry -- "Corona (big block)" would be an analogy with
    Trinity's rather than a measurement.
    """

    flash = BigNandStatingSmallBlocks()
    name = "coronabb"
    text = ""


class Corona4G(Corona):
    """48 MB of usable flash inside a 4 GB eMMC, written flat."""

    flash = Emmc()
    name = "corona4g"
    text = "Corona"
