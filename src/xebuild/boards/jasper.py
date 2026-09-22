"""Jasper, the one family fitted with all three kinds of NAND."""

from .board import Board
from .flash import BigBlockNand, SmallBlockNand, SmallNand


class Jasper(Board):
    """What every Jasper shares, whichever part is in it."""

    section = "jasper"
    fat = True
    copyright_year = 2009
    jtag_copyright_year = 2008  # the one family whose JTAG year differs from its own

    smc_clean = "JASPER_CLEAN.bin"
    smc_cr4 = "JASPER_CR4.bin"
    smc_plus = "JASPER_SMC+.bin"


class JasperXsb(Jasper):
    """16 MB on the older controller -- the same part a Falcon has."""

    flash = SmallBlockNand()
    name = "jaspersb"
    text = "Jasper"


class Jasper16(Jasper):
    """16 MB on the newer controller, which is what makes it meta 1."""

    flash = SmallNand()
    name = "jasper"
    text = "Jasper"
    # `jasperbc` is a spelling the original takes and does not document. Measured: it
    # builds a 16 MB image and its summary says `Jasper`, so it is this console.
    also = ("jasperbc",)


class JasperBigBlock(Jasper):
    """The system area of a 256 or 512 MB part, and the only flash stating 0x20000."""

    flash = BigBlockNand()
    name = "jasperbb"
    text = "Jasper (big block)"
    also = ("jasper256", "jasper512")
