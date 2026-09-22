"""The second motherboard, which borrows Falcon's glitch SMCs."""

from .board import Board
from .flash import SmallBlockNand


class Zephyr(Board):
    """A Zephyr. Its 64 MB variant is a developer part, as Xenon's is."""

    section = "zephyr"
    fat = True
    states_keyvault_size = False
    copyright_year = 2005
    jtag_copyright_year = 2005

    # It has a stock image of its own and no glitched one, so it takes Falcon's for both.
    smc_clean = "ZEPHYR_CLEAN.bin"
    smc_cr4 = "FALCON_CR4.bin"
    smc_plus = "FALCON_SMC+.bin"

    flash = SmallBlockNand()
    name = "zephyr"
    text = "Zephyr"
