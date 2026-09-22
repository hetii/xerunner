"""The first motherboard, and the only one whose SMC works nowhere else."""

from .board import Board
from .flash import SmallBlockNand


class Xenon(Board):
    """A Xenon, whichever of its two parts is fitted.

    J-Runner lists a Xenon 16MB and a Xenon 64MB and they are one console here: the
    64 MB part is the old small block Samsung in a developer machine, and the image
    built for it is the same 16 MB.
    """

    section = "xenon"
    fat = True
    states_keyvault_size = False  # the two oldest boards leave 0x60 at zero
    copyright_year = 2005
    jtag_copyright_year = 2005

    smc_clean = "XENON_CLEAN.bin"
    smc_plus = "XENON_SMC+.bin"  # and no CR4 image exists for a Xenon

    flash = SmallBlockNand()
    name = "xenon"
    text = "Xenon"
