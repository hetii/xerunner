"""The first motherboard whose header states the keyvault's length."""

from .board import Board
from .flash import SmallBlockNand


class Falcon(Board):
    """A Falcon. Its 64 MB variant is a developer part, as Xenon's is."""

    section = "falcon"
    fat = True
    copyright_year = 2007
    jtag_copyright_year = 2007

    smc_clean = "FALCON_CLEAN.bin"
    smc_cr4 = "FALCON_CR4.bin"
    smc_plus = "FALCON_SMC+.bin"

    flash = SmallBlockNand()
    name = "falcon"
    text = "Falcon"
