"""A console's own flash, and what a build is entitled to take out of it.

An `Image` is a flash image whatever it is for. A `Dump` is one that came off a
particular console, which makes two things true of it that are not true of an image in
general. Its blocks may not be where their numbers say, so they are put back first. And
it is the only place some of a console's material exists: the keyvault that holds its
serial and its DVD key, the settings block that holds its fan curves and its MAC, the
statistics the dashboard keeps, the sealed SMC it boots.

Everything read here was checked against what the original's extract mode says about the
same dump, which narrates each one::

    decrypting KeyVault at address 0x4000 of size 0x4000
    decrypting SMC at address 0x1000 of size 0x3000
    seeking smc config in dump...found at offset 0xf7c000!
    Statistics.settings found at offset 0xf78000, size 4096 (0x1000) bytes

**Three blocks sit one above the other at the top of a flash, a `round_to` apart**: the
settings block where the shape says, the statistics block one step below it, and
`Manufacturing.data` two steps below. Measured by building from one dump on four shapes:
0xF7C000/0xF78000/0xF74000 on 16 MB, 0x3BE0000/0x3BC0000/0x3BA0000 on both 64 MB
shapes, and 0x2FFC000/0x2FF8000/0x2FF4000 on the eMMC. Taking the step as 0x4000 is
what 16 MB makes it look like, and it is wrong on the two 64 MB shapes.

**A console need not have a manufacturing block.** One of the two here does not: its
block is erased, all 0xFF, and the original says nothing about it. The other carries its
own serial number there in the clear. What decides it is whether the block was ever
written -- planting the data alone into the erased one changes nothing, and planting the
block with its spare bytes makes the original report it on all four shapes.

**Where the settings block is, and where the statistics block is, are two different
rules.** The settings block sits where the flash shape says, and the statistics block
one `round_to` below it -- not one 0x4000 block below it, which is what a 16 MB flash
makes it look like. Measured by building from one dump for four shapes and reading
where each run put them: 0xF78000 under 0xF7C000 on 16 MB, 0x3BC0000 under 0x3BE0000 on
both 64 MB shapes, and 0x2FF8000 under 0x2FFC000 on the eMMC.

**The original does not seek the settings block, whatever it says.** It looks at the one
offset the shape names and checks what is there. A dump with its block blanked and a
sound copy planted one block lower is reported as "not found!".

The pairing and the lockdown value come from the bootloader chain rather than from the
flash directly, so they arrive through `chain` -- the original says as much in the same
breath, "CB decrypt failed! Unable to get pairing data!" and "could not find a non-zero
CF LDV to use". They are read off the CF slot this console boots, which needs no console
secret, and they agree with what the original prints for the same dump.

Decrypting the SMC is not here either, though `crypto.smc` can: what a build carries
over is the sealed SMC exactly as the console holds it, and reading it is a separate job
from taking it.
"""

from __future__ import annotations

import logging

from .image import Image
from .keyvault import Keyvault
from .order import logical

logger = logging.getLogger(__name__)

# The settings block, and the region of it the head's word is computed over.
CONFIG_LENGTH = 0x400
SUMMED = (0x10, 0x10C)


def checksum(block: bytes) -> int:
    """The word a settings block's head has to carry for the original to accept it.

    One's complement of the sum of its bytes from 0x10 to 0x10C, and the head holds it
    little-endian -- the SMC is a little-endian device in a big-endian console.

    Measured rather than assumed, and the span is exact. Three real blocks agree. A
    byte changed at 0x10B makes the original say "not found!"; the same change at 0x10C,
    at the MAC address in 0x220, or at the block's very last byte leaves it accepted.
    Nothing else is checked: change a byte inside the span, recompute this, and the
    block is accepted again. The bytes from 0x02 to 0x10 are outside it, which is why
    the zero pair and the `05 21` beside it can be overwritten with no complaint.
    """
    return (~sum(bytes(block)[SUMMED[0] : SUMMED[1]])) & 0xFFFF


class Dump:
    """One console's flash, with its blocks in the order the console reads them."""

    def __init__(self, raw: bytes, board, bigffs: bool = False,
                 remap: bool = True, ecd: bool = True):
        self.board = board
        self.flash = board.flash
        self.image = Image(logical(raw, board.flash, remap, ecd), board.flash, bigffs)

    @property
    def header(self) -> object:
        return self.image.header

    @property
    def sealed_keyvault(self) -> bytes:
        """The keyvault as it lies in flash, where the header says it is."""
        head = self.header
        at, length = head.keyvault_at, head.keyvault_size
        return self.image.flat[at : at + length]

    def keyvault(self, cpu_key: bytes) -> Keyvault:
        """The console's keyvault, opened with its CPU key."""
        return Keyvault.opened(self.sealed_keyvault, cpu_key)

    @property
    def smc(self) -> bytes:
        """The SMC as the console holds it, sealed, where the header says it is."""
        head = self.header
        at, length = head.smc_at, head.smc_size
        return self.image.flat[at : at + length]

    @property
    def smc_config(self) -> bytes:
        """The console's settings block: fan curves, temperatures, MAC, regions."""
        at = self.flash.smc_config
        return self.image.flat[at : at + CONFIG_LENGTH]

    @property
    def smc_config_ok(self) -> bool:
        """Whether the settings block is one the original would use."""
        block = self.smc_config
        return len(block) == CONFIG_LENGTH and (
            int.from_bytes(block[:2], "little") == checksum(block)
        )

    @property
    def statistics(self) -> bytes:
        """`Statistics.settings`, the block the dashboard keeps its counters in."""
        at, length = self.flash.smc_config - self.flash.round_to, 0x1000
        return self.image.flat[at : at + length]

    @property
    def manufacturing(self) -> bytes:
        """`Manufacturing.data`, two steps below the settings block.

        All 0xFF when this console has none, which is an erased block rather than a
        missing one; `manufacturing_written` is that question.
        """
        at, length = self.flash.smc_config - 2 * self.flash.round_to, 0x1000
        return self.image.flat[at : at + length]

    @property
    def manufacturing_written(self) -> bool:
        """Whether this console keeps one at all.

        The original decides it from the spare -- an erased block is skipped -- and a
        flat run has no spare to look at, so this asks whether anything was written
        there. The two agree on both consoles measured: one is 0xFF throughout and the
        original reports nothing, the other carries its serial and is reported.
        """
        return set(self.manufacturing) != {0xFF}

    @property
    def chain(self):
        """This console's bootloader chain."""
        from ..chain import Chain
        return Chain(self.image, self.board)

    @property
    def pairing(self) -> bytes:
        """The three bytes binding this console's bootloaders to it."""
        return self.chain.console.pairing

    @property
    def ldv(self) -> int:
        """The lockdown value, as the console's own CF states it."""
        return self.chain.console.ldv

    @property
    def security(self) -> dict:
        """The console's security files, by name, for those this dump carries.

        They are ordinary files in the filesystem and the original treats them as such:
        it reports each with the sector and size its directory entry gives. Which of
        them decrypt is a question for whatever opens them, not for reading them out.
        """
        wanted = ("crl.bin", "dae.bin", "extended.bin", "fcrt.bin", "secdata.bin")
        held = {entry.name for entry in self.image.directory.entries}
        return {name: self.image.read(name) for name in wanted if name in held}

    def survey(self, cpu_key: bytes | None = None) -> None:
        """Say what this dump holds, once. Reading a property is not worth a line.

        The original narrates the same things as it loads a dump, and it goes on when
        one of them does not work out: without a CPU key it reports "keyvault decrypt
        failed, discarding" and carries on to everything else. So does this.
        """
        head = self.header
        logger.info("keyvault at %#x of size %#x", head.keyvault_at, head.keyvault_size)
        if cpu_key is None:
            logger.info("no cpu key given, so the keyvault stays sealed")
        else:
            keyvault = self.keyvault(cpu_key)
            if keyvault.looks_opened:
                logger.info("keyvault opened: console %s, made %s",
                            keyvault.serial, keyvault.made_on)
            else:
                logger.info("keyvault did not open with this cpu key")
        logger.info("smc at %#x of size %#x, sealed", head.smc_at, head.smc_size)
        logger.info("smc config at %#x of size %#x, %s", self.flash.smc_config,
                    CONFIG_LENGTH, "sound" if self.smc_config_ok else "not sound")
        logger.info("statistics at %#x of size %#x",
                    self.flash.smc_config - self.flash.round_to, len(self.statistics))
        logger.info("manufacturing data at %#x: %s",
                    self.flash.smc_config - 2 * self.flash.round_to,
                    "kept" if self.manufacturing_written
                    else "none, the block is erased")
        found = self.chain
        logger.info("chain of %d stages%s, pairing %s, lockdown %d",
                    len(found.stages),
                    " with an inserted bootloader" if found.converted else "",
                    found.console.pairing.hex(), found.console.ldv)
        for name, body in self.security.items():
            logger.info("%s in the filesystem, %#x bytes", name, len(body))

    def __repr__(self) -> str:
        return "Dump(%s, %r)" % (self.board.name, self.flash)
