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

import logging

from ..smc import Smc
from ..boards import ALL
from .image import Image
from .keyvault import Keyvault
from ..boards.spare import PAGE
from ..crypto.formats import decrypt_smc
from .settings import CONFIG_LENGTH, sums
from .order import failing, logical, marked_bad, mixed_controller

logger = logging.getLogger(__name__)


def cut(raw: bytes | None) -> bytes | None:
    """A dump as the original reads it: anything past a flash's length cut off.

    The original's rule, read out of its loader at 0x417171 and measured on each
    branch. A dump longer than 48 MB is an eMMC one cut to 48 MB when it holds `FATX`
    right there -- "FATX magic found, truncating load size to 0x3000000 bytes for mmc
    consoles" -- or when its first page carries no valid code, which a NAND dump's
    always does: "First page does not contain a valid ECC, assuming this is an mmc
    dump". Otherwise it is a big block part read whole, 256 or 512 MB, cut to its
    first 64 MB -- "assuming this is a big block flash overdump and truncating load
    size to 0x4200000 bytes". Measured: an eMMC image padded to 64 MB with and without
    `FATX`, and a 256 MB dump, each building the image its first part does.
    """
    if raw is None or len(raw) <= 0x3000000:
        return raw
    # The code sits in the same place in every spare layout.
    spare = next(one.flash.spare for one in ALL
                 if one.flash.spare is not None)
    if raw[0x3000000:0x3000004] == b"FATX":
        logger.debug("FATX magic found, truncating load size to 0x3000000 bytes for "
                     "mmc consoles")
        return raw[:0x3000000]
    if not spare.ecc_ok(raw[:PAGE + spare.length]):
        logger.debug("First page does not contain a valid ECC, assuming this is an "
                     "mmc dump and truncating load size to 0x3000000 bytes")
        return raw[:0x3000000]
    if len(raw) > 0x4200000:
        logger.debug("First page contains a valid ECC, assuming this is a big block "
                     "flash overdump and truncating load size to 0x4200000 bytes")
        return raw[:0x4200000]
    return raw


def faulty(raw: bytes, flash, whole: int | None = None, ecd: bool = True) -> str:
    """Why the original would throw this dump away, or nothing.

    `whole` is the length of the file as it was handed over, which every address in the
    header is held against; `ecd` is false under `noecdremap`.

    Thrown away, not refused: the build goes on as it does with no dump at all,
    which without a `smc.bin`, a `kv.bin` and a `smc_config.bin` beside it ends in
    "critical bootloader files are missing". Each cause below was measured on the
    bench console's dump with that one fault put in: the original discarded it, and
    with the console's own files beside the build made the image this makes.

    **The header, as its loader checks it at 0x416D1D**, every address against the
    length of the file as it was handed over: the magic; the entry point and the
    slot offset at 0x08 and 0x0C; a keyvault length over 0x8000 at 0x60; the update
    slot at 0x64 below the offset at 0x0C or past the file -- "SysUpdateAddr is
    malformed"; the keyvault, the filesystem and the SMC past the file at 0x6C,
    0x70 and 0x7C; an SMC length at 0x78 other than 0x3000 or 0x3800. Three more
    fields it only complains about and goes on, measured too: a slot count at 0x68
    other than 2, a settings block address at 0x74 other than 0, a keyvault version
    at 0x6A other than 0x0712.

    **An eMMC dump the original built as a XeLL image** -- "nanddump.bin is a
    ZEROPAIR/XELL image, discarding".

    **Block 0 marked bad** -- "NAND dump does not appear to have a good block at
    block 0, discarding dump!".

    **More than 32 blocks to move** -- "MAX REMAPS of 32 exceeded, remapping
    disabled and image rejected as faulty!". Its table holds 32 (0x479F78); a block
    failing its code takes a place in it as a block marked bad does, unless
    `noecdremap` leaves such blocks alone, and `noremap` changes nothing here --
    all three measured.
    """
    head = bytes(raw[:0x80])
    whole = len(raw) if whole is None else whole

    def word(at: int) -> int:
        return int.from_bytes(head[at:at + 4], "big")

    # The original's own words for each, which name the fields its way.
    if head[:2] != b"\xff\x4f":
        return "flash header magic is incorrect"
    for name, at in (("Entry", 0x08), ("Size", 0x0C)):
        if word(at) > whole:
            return "flash header %s is too large" % name
    if word(0x60) > 0x8000:
        return "flash header KeyVaultSize is too large"
    if word(0x64) > whole or word(0x0C) > word(0x64):
        return "flash header SysUpdateAddr is malformed"
    if int.from_bytes(head[0x68:0x6A], "big") != 2:
        logger.warning("flash header SysUpdateCount is not 2, continuing anyway")
    if int.from_bytes(head[0x6A:0x6C], "big") != 0x0712:
        logger.warning("flash header KeyVaultVersion is not 0x0712, continuing "
                       "anyway")
    for name, at in (("KeyVaultAddr", 0x6C), ("FileSystemAddr", 0x70)):
        if word(at) > whole:
            return "flash header %s is too large" % name
    if word(0x74):
        logger.warning("flash header SmcConfigAddr is not 0, continuing anyway")
    if word(0x78) & ~0x800 != 0x3000:
        return "flash header SmcBootSize is not 0x3000 or 0x3800"
    if word(0x7C) > whole:
        return "flash header SmcBootAddr is too large"
    if flash.spare is None:
        # "zeropair image" where the copyright line goes, which the original
        # calls a ZEROPAIR/XELL image -- measured on an eMMC dump. It checks an
        # eMMC dump only in effect: the same test on a NAND dump (0x4167AA) reads
        # a buffer block 0 has not been copied into yet, and a NAND dump marked
        # the same way was used.
        if head[0x10:0x1E] == b"zeropair image":
            return "the dump is a ZEROPAIR/XELL image"
        return ""
    per = flash.spare.pages_a_block * (PAGE + flash.spare.length)
    if marked_bad(raw[:per], flash):
        return "NAND dump does not appear to have a good block at block 0"
    moved = set(marked_bad(raw, flash))
    if ecd:
        moved |= set(failing(raw, flash))
    if len(moved) > 32:
        return ("MAX REMAPS of 32 exceeded (%d), remapping disabled and image "
                "rejected as faulty" % len(moved))
    return ""


class Dump:
    """One console's flash, with its blocks in the order the console reads them."""

    def __init__(self, raw: bytes, board, bigffs: bool = False, ecd: bool = True):
        self.board = board
        self.flash = board.flash
        # The original drops these blocks and this keeps them -- see `image.order`.
        step = PAGE + board.flash.spare.length if board.flash.spare is not None else 0
        for block in mixed_controller(raw, board.flash, ecd):
            logger.warning("nanddump.bin has a mixed controller LBA at block %#x (raw "
                           "offset %#x), block kept where it lies", block,
                           block * step * board.flash.spare.pages_a_block)
            logger.warning("this is likely caused by previously using jaspersb on a "
                           "jasper type console!")
        self.image = Image(logical(raw, board.flash), board.flash, bigffs)
        if not self.fsroot_found:
            logger.error("Could not find fsroot!")
        if not self.header.keyvault_at:
            logger.warning("KeyVault cannot be at 0x0, trying 0x4000")
        if self.header.smc_at not in (0x800, 0x1000):
            logger.warning("smc.bin should not be at %#x, trying 0x1000",
                           self.header.smc_at)

    @property
    def header(self) -> object:
        return self.image.header

    @property
    def keyvault_at(self) -> int:
        """Where the keyvault is read: where the header says, or 0x4000 where it states
        0 -- "KeyVault cannot be at 0x0, trying 0x4000" (0x413F62), measured; any other
        address is taken as stated."""
        return self.header.keyvault_at or 0x4000

    @property
    def sealed_keyvault(self) -> bytes:
        """The keyvault as it lies in flash, at `keyvault_at`."""
        # 0x4000 long whatever the header states. A xenon or zephyr image leaves the
        # length at zero, and one stating 0x8000 has a second keyvault behind the
        # first -- "decrypting KeyVault at address 0x4000 of size 0x4000", then
        # "decrypting alt KeyVault at address 0x8000" -- measured on a dump whose
        # header said 0x8000.
        return self.image.flat[self.keyvault_at : self.keyvault_at + 0x4000]

    def keyvault(self, cpu_key: bytes) -> Keyvault:
        """The console's keyvault, opened with its CPU key."""
        return Keyvault.opened(self.sealed_keyvault, cpu_key)

    @property
    def smc_at(self) -> int:
        """Where the SMC is read: at 0x800 or 0x1000, the only two places an SMC is ever
        laid, as the header says; a header stating anything else is read at 0x1000 all
        the same -- "smc.bin should not be at 0x%x, trying 0x1000" (0x413B4B), measured
        with 0x2000 and with 0."""
        at = self.header.smc_at
        return at if at in (0x800, 0x1000) else 0x1000

    @property
    def smc(self) -> bytes:
        """The SMC as the console holds it, sealed, at `smc_at`. The length is always
        one of the two the header check lets through, 0x3000 or 0x3800."""
        return self.image.flat[self.smc_at : self.smc_at + self.header.smc_size]

    @property
    def smc_opens(self) -> bool:
        """Whether the SMC opens to the four zeros every SMC ends with, the one test
        the original makes of it as the dump is read (0x413C7E). One that does not is
        discarded there -- "SMC did not decrypt, discarding it" -- which a build
        answers for: see `Build.smc`."""
        return decrypt_smc(self.smc)[-4:] == bytes(4)

    @property
    def smc_config(self) -> bytes | None:
        """The console's settings block -- fan curves, temperatures, MAC, regions --
        or None where the dump holds no sound one.

        The first sound block from where the shape keeps it to the end of the flash,
        0x200 at a time (0x4159AE): the original searches upward whatever it prints,
        measured with the block spoilt and a sound copy 0x200 and 0x400 above it. Below
        that place it does not look: its search only climbs.
        """
        flat = self.image.flat
        for at in range(self.flash.smc_config, len(flat) - 0x200 + 1, 0x200):
            if sums(flat[at:at + 0x10C]):
                return bytes(flat[at:at + CONFIG_LENGTH])
        return None

    @property
    def smc_config_ok(self) -> bool:
        """Whether the dump holds a settings block the original would use."""
        return self.smc_config is not None

    @property
    def fsroot_found(self) -> bool:
        """Whether the scan found the filesystem's table. The original finds the
        mobiles in the same scan (0x415230), and where it finds no table it skips the
        steps after it as well (0x417C5B): the netKd block (0x414300),
        Statistics.settings and Manufacturing.data (0x414050) and the security files
        (0x417DD7). Measured
        with every table page erased, and on an eMMC dump with both anchors zeroed:
        "ERROR! Could not find fsroot!", and nothing "adding from previous parse"."""
        return "fsroot" in self.image.blobs

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
    def net_kd(self) -> bytes | None:
        """The network debugging block a development console keeps in its header, or
        None where there is none.

        It starts at 0x80 with the magic 0xCA4A and states its own length at 0x8C and
        its version at 0x90; version 1 carries the console's IP and MAC, a port and the
        host's IP, which the original prints -- "netKd info found, size 0x28". Read out
        of it at 0x414300, and measured by putting one into the bench console's header:
        the image the original built carried those 0x28 bytes at 0x80.
        """
        page = self.image.flat
        if bytes(page[0x80:0x82]) != b"\xca\x4a":
            return None
        length = int.from_bytes(bytes(page[0x8C:0x90]), "big")
        return bytes(page[0x80:0x80 + length])

    @property
    def memory_unit(self) -> tuple | None:
        """Where the memory unit a big block console keeps in its first 64 MB lies, as
        `(start, end)` of the flat image, or None where this dump carries none.

        The range is the author's own, in the ini xeBuild's source ships: "blocks 0x10
        through 0x15B (inclusive) ... when NAND MU data is detected only". The blocks
        are the chip's 0x20000, so 0x200000 up to 0x2B80000 -- the gap between the
        bootloaders and the filesystem. Detected, as at the original's 0x415B8A, by a
        page whose kind is 1 to 0x29, which only a big block chip has.
        """
        spare = self.flash.spare
        if spare is None or spare.pages_a_block != 256:
            return None
        if not any(0 < spare.kind(one) <= 0x29 for one in self.image.spares):
            return None
        step = spare.pages_a_block * PAGE
        return 0x10 * step, 0x15C * step

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
        failed, discarding" and carries on to everything else. So does this. Every
        number said here is held against what the original's extract mode reports for
        the same dump -- see `tests/xebuild/e2e/e2e_extract.py`.
        """
        head = self.header
        logger.info("keyvault at %#x of size 0x4000", self.keyvault_at)
        if cpu_key is None:
            logger.info("no cpu key given, so the keyvault stays sealed")
        else:
            keyvault = self.keyvault(cpu_key)
            if keyvault.looks_opened:
                logger.info("keyvault opened: console %s, made %s",
                            keyvault.serial, keyvault.made_on)
            else:
                logger.warning("keyvault did not open with this cpu key")
        smc = Smc(decrypt_smc(self.smc))
        logger.info("smc at %#x of size %#x: %s%s", self.smc_at, head.smc_size,
                    smc.named, ", a stock image" if smc.clean else "")
        logger.info("smc config at %#x of size %#x, %s", self.flash.smc_config,
                    CONFIG_LENGTH, "sound" if self.smc_config_ok else "not sound")
        logger.info("statistics at %#x of size %#x",
                    self.flash.smc_config - self.flash.round_to, len(self.statistics))
        logger.info("manufacturing data at %#x: %s",
                    self.flash.smc_config - 2 * self.flash.round_to,
                    "kept" if self.manufacturing_written
                    else "none, the block is erased")
        for name, found in sorted(self.image.blobs.items()):
            logger.info("%s version %d at %#x, %#x bytes, page %#x", name,
                        found["version"], found["offset"], found["length"],
                        found["offset"] // PAGE)
        self._survey_files()
        self._survey_chain()

    def _survey_files(self) -> None:
        """The filesystem's files, in the order its table lists them, and the security
        files among them."""
        for entry in self.image.directory.entries:
            logger.info("%-22s block %#06x at %#010x, %#x bytes, stamp %#010x",
                        entry.name, entry.sector,
                        self.flash.offset_of(entry.sector, self.image.bigffs),
                        entry.size, entry.stamp)
        for name, body in self.security.items():
            logger.info("%s in the filesystem, %#x bytes", name, len(body))

    def _survey_chain(self) -> None:
        """The bootloader chain, stage by stage, and what the CF says of the console.

        The original's extract mode checks the chain as its update mode would and names
        each stage by its place -- "CB v9188 at 0x9ac0 size 0x7800 (dual CB)" -- which
        is how it calls an RGH3 console's third CB its CD. This names each stage by its
        own magic and says which is an inserted one.
        """
        found = self.chain
        for stage in found.walked:
            logger.info("%s v%d at %#x, %#x bytes%s", stage.tag, stage.build, stage.at,
                        stage.length, " (inserted by an exploit)" if stage.payload
                        else "")
        last = found.walked[-1] if found.walked else None
        if last is not None and last.tag in ("CE", "SE"):
            # "final truncated bootloader size 0x6c5c0": where the last stage ends,
            # counted from the start of the flash and rounded up to 0x10.
            end = last.at + last.length
            logger.info("the bootloaders end at %#x", end + -end % 0x10)
        try:
            console = found.console
        except ValueError as why:
            logger.warning("no console block read off the CF: %s", why)
            return
        logger.info("pairing %s, lockdown %d, from the CF", console.pairing.hex(),
                    console.ldv)

    def __repr__(self) -> str:
        return "Dump(%s, %r)" % (self.board.name, self.flash)
