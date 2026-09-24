"""What goes into an image, region by region, decided from the material and the release.

`layout` says where each region goes and `image.Image` knows how to hold it; this
decides **what** the bytes are. Every rule here came off the original: either out of an
image it built, or out of what it printed while building one, and the docstring says
which.

Nothing here writes into an image. A region is produced and handed back, so each one can
be held against the same region of a reference image on its own -- which is how they
were measured, and what a mistake in one of them looks like.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time

from .. import boards, jtag
from ..boards.flash import PAGE
from ..chain import Fields, fuses, sealing, update
from ..chain.stage import LENGTH as STAGE_HEADER
from ..chain.stage import Stage
from ..config.options import BUTTONS
from ..crypto import smc as cipher
from ..crypto.rc4 import rc4
from ..image import Dump, Entry, Header, Image, Keyvault, order
from ..image import anchor as anchors
from ..image.settings import TEMPERATURES, SmcConfig
from ..release import Release
from ..smc import Smc
from . import layout, security
from .filesystem import Filesystem
from .material import Material

# The copyright line every image carries, with the year a build replaces. Read off the
# sixteen reference images, which carry two different years and nothing else different.
NOTICE = b"\xa9 2004-2010 Microsoft Corporation. All rights reserved."

# The kinds of stage that make up the chain proper. CF and CG are named by the same list
# and are not in it: they go in the slot behind the chain.
CHAIN_KINDS = ("CB", "CBA", "CBB", "SB", "SC", "CD", "SD", "CE", "SE")

# What each kind of stage is to the chain, by the letter the original goes by: B for a
# CB of either half, D, E. The development chains' SB, SD and SE are the same three.
ROLES = {"CB": "B", "CBA": "B", "CBB": "B", "SB": "B", "SC": "C", "CD": "D", "SD": "D",
         "CE": "E", "SE": "E"}

# What a stage is sealed in multiples of. Measured: under the manufacturing patch set a
# patched CD ends at 0x52A8, the image says 0x52B0, and the next stage begins there.
# CE is not patched, keeps the length its own file states, and the region runs the few
# bytes further that its padding takes.
SEAL_ALIGN = 0x10

logger = logging.getLogger(__name__)


class Build:
    """One build: the console's own material on one side, a release on the other.

    `config` is a `config.BuildConfig`, which already resolves the console and the image
    type from what `-c` and `-t` were given, so neither is passed again here. `material`
    is the directory `-d` names and `release` the one `-f` names.
    """

    def __init__(self, config, material, release):
        self.config = config
        self.material = material
        self.release = release
        self._dump = None
        self._raw = None
        self._recipe = None
        self._walked = None
        self._drawn = {}

    @property
    def recipe(self):
        """The release's file list for this image type, read once.

        `firmware_ext` goes into its name -- `-i WB` reads `_glitch2_WB.ini`, which the
        original says when it is not there: "could not open '17559/_glitch2_WB.ini'".
        """
        if self._recipe is None:
            self._recipe = self.release.recipe(self.image_type,
                                               self.config.firmware_ext or "")
        return self._recipe

    @property
    def stage_list(self) -> tuple:
        """What the file list names for this console's chain and update slot.

        `section_ext` goes into the section's name -- `-r WB` on a corona reads
        `[coronabl_WB]` -- and, measured, into the patch file's as well: the same build
        reads `patches_g2corona_WB.bin`. See `patches`.
        """
        return self.recipe.stages(self.console, self.config.section_ext or "")

    @property
    def console(self):
        return self.config.console

    @property
    def image_type(self):
        return self.config.image_type

    @property
    def flash(self):
        """The part the image is laid on: the console's, but for a devkit image --
        see `ImageType.shape`."""
        return self.image_type.shape(self.console, self.config.bigffs)[0]

    @property
    def bigffs(self) -> bool:
        """Whether with the larger filesystem: asked for, or forced by the type."""
        return self.image_type.shape(self.console, self.config.bigffs)[1]

    @property
    def dump(self) -> Dump | None:
        """The console's own flash, or None when the material holds no dump.

        Read once: it is seventeen megabytes and nearly every region asks it something.
        **Read with its own geometry**, which `boards.for_dump` works out from the dump,
        and not with the geometry of the console being built for: a trinity dump builds
        a falcon image, and read as a falcon's its settings blobs are scanned at the
        wrong offsets.
        """
        if self._dump is None and self.dump_raw is not None:
            raw = self.dump_raw
            try:
                own = boards.for_dump(raw, self.console)
            except ValueError:
                # A dump of no length a flash has is not refused: it is ignored, and
                # the build goes on as if there were none -- "is not a correct raw
                # (with ecc) dump size (0x10c2000 bytes), ignoring", measured.
                logger.warning("nanddump.bin is not a correct raw (with ecc) dump size "
                               "(%#x bytes), ignoring", len(raw))
                self._dump = False
                return None
            why = self._faulty(raw, own.flash)
            if why:
                logger.warning("%s, discarding nanddump.bin", why)
                self._dump = False
                return None
            bigffs = self.config.bigffs if own is self.console else False
            self._dump = Dump(raw, own, bigffs, remap=not self.config.noremap,
                              ecd=not self.config.noecdremap)
        return self._dump or None

    def _faulty(self, raw: bytes, flash) -> str:
        """Why the original would throw this dump away, or nothing.

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

        **Block 0 marked bad** -- "NAND dump does not appear to have a good block at
        block 0, discarding dump!".

        **More than 32 blocks to move** -- "MAX REMAPS of 32 exceeded, remapping
        disabled and image rejected as faulty!". Its table holds 32 (0x479F78); a block
        failing its code takes a place in it as a block marked bad does, unless
        `noecdremap` leaves such blocks alone, and `noremap` changes nothing here --
        all three measured.
        """
        head = bytes(raw[:0x80])
        whole = len(self.material.dump) if self.material.dump is not None else len(raw)

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
            return ""
        per = flash.spare.pages_a_block * (PAGE + flash.spare.length)
        if order.marked_bad(raw[:per], flash):
            return "NAND dump does not appear to have a good block at block 0"
        moved = set(order.marked_bad(raw, flash))
        if not self.config.noecdremap:
            moved |= set(order.failing(raw, flash))
        if len(moved) > 32:
            return ("MAX REMAPS of 32 exceeded (%d), remapping disabled and image "
                    "rejected as faulty" % len(moved))
        return ""

    @property
    def dump_raw(self) -> bytes | None:
        """The dump's bytes as the build reads them: anything past a flash's length cut.

        The original's rule, read out of its loader at 0x417171 and measured on each
        branch. A dump longer than 48 MB is an eMMC one cut to 48 MB when it holds
        `FATX` right there -- "FATX magic found, truncating load size to 0x3000000
        bytes for mmc consoles" -- or when its first page carries no valid code, which
        a NAND dump's always does: "First page does not contain a valid ECC, assuming
        this is an mmc dump". Otherwise it is a big block part read whole, 256 or 512
        MB, cut to its first 64 MB -- "assuming this is a big block flash overdump and
        truncating load size to 0x4200000 bytes". Measured: an eMMC image padded to
        64 MB with and without `FATX`, and a 256 MB dump, each building the image its
        first part does.
        """
        if self._raw is not None:
            return self._raw or None
        self._raw = self._cut(self.material.dump) or b""
        return self._raw or None

    @staticmethod
    def _cut(raw: bytes | None) -> bytes | None:
        """`dump_raw`'s rule, applied once."""
        if raw is None or len(raw) <= 0x3000000:
            return raw
        # The code sits in the same place in every spare layout.
        spare = next(one.flash.spare for one in boards.ALL
                     if one.flash.spare is not None)
        if raw[0x3000000:0x3000004] == b"FATX":
            logger.info("FATX magic found, truncating load size to 0x3000000 bytes for "
                        "mmc consoles")
            return raw[:0x3000000]
        if not spare.ecc_ok(raw[:PAGE + spare.length]):
            logger.info("First page does not contain a valid ECC, assuming this is an "
                        "mmc dump and truncating load size to 0x3000000 bytes")
            return raw[:0x3000000]
        if len(raw) > 0x4200000:
            logger.info("First page contains a valid ECC, assuming this is a big block "
                        "flash overdump and truncating load size to 0x4200000 bytes")
            return raw[:0x4200000]
        return raw

    @property
    def cpu_key(self) -> bytes | None:
        """This console's CPU key, from wherever the original looks first.

        The command line wins and the file is then not even opened -- "CPU key
        overridden from command line, not looking for cpukey.txt" -- and `config` is
        where the command line and the ini have already been settled against each
        other.
        """
        if self.config.cpu_key is not None:
            return self.config.cpu_key
        return self.material.key_in_file("cpukey.txt")

    @property
    def one_bl_key(self) -> bytes | None:
        """The 1BL key, the same way, and refused where its sum is not the 1BL key's.

        The original adds its bytes up and stops a build whose sum is not 0x983 -- "1BL
        key 0x0011... does not appear to be correct!" -- measured. That is the whole of
        its test, and sealing here takes the one key there is, `sealing.ONE_BL_KEY`:
        a different key with the same sum would seal differently in the original, and
        such a key is not one any console has.
        """
        key = self.config.one_bl_key
        if key is None:
            key = self.material.key_in_file("1blkey.txt")
        if key is not None and sealing.key_sum(key) != sealing.key_sum(
                sealing.ONE_BL_KEY):
            raise ValueError("1BL key 0x%s does not appear to be correct!"
                             % key.hex().upper())
        return key

    @property
    def _walk(self) -> tuple:
        """The dump's `Chain.nonce_walk`, read once; nothing read with no dump."""
        if self._walked is None:
            self._walked = (self.dump.chain.nonce_walk() if self.dump is not None
                            else ({}, False))
        return self._walked

    @property
    def drawing(self) -> bool:
        """Whether this build draws its nonces and sealing material afresh.

        The original draws all twelve of its staging buffers -- see
        `security.COMPILED_IN` -- unless `-norandom` says not to or its survey walked
        the dump's chain to the end: "initializing random nonces" is the line that says
        it did. So a build from a console's own dump draws nothing, one with no dump
        draws everything, and so does one from a dump whose chain it cannot walk.
        """
        return not self.config.no_random and not self._walk[1]

    def _buffer(self, name: str, carried=None):
        """One staging buffer's value: drawn, the console's own, or compiled in.

        Drawn once a build and then kept, because the original draws each buffer once
        and every stage that reads it reads the same bytes.
        """
        static = security.COMPILED_IN[name]
        if self.drawing:
            if name not in self._drawn:
                parts = static if isinstance(static, tuple) else (static,)
                drawn = tuple(os.urandom(len(one)) for one in parts)
                self._drawn[name] = drawn if isinstance(static, tuple) else drawn[0]
            return self._drawn[name]
        return carried if carried is not None else static

    @property
    def pairing(self) -> bytes:
        """The three bytes of pairing: the console's, or with no dump drawn or static.

        Off the dump's CF whenever there is a dump -- "setting pairing data from image
        to 0x780227". With none, `-norandom` leaves the three bytes the original stores
        one at a time at 0x41BA43, "initializing static pairing value", and otherwise
        they are drawn with everything else.
        """
        if self.dump is not None:
            return self.dump.pairing
        if self.config.no_random:
            return bytes.fromhex("2345f1")
        if "pairing" not in self._drawn:
            self._drawn["pairing"] = os.urandom(3)
        return self._drawn["pairing"]

    def smc(self, seed: bytes = b"") -> bytes:
        """The SMC as the image carries it: sealed, and patched if the options ask.

        **The original chooses no image of its own.** It takes `smc.bin` from the
        per-build directory, and where there is none it keeps the console's --
        "reading data/smc.bin failed, using smc.bin from nand dump". Measured over
        forty-six builds on every board spelling and three hack types. Which shipped
        image belongs to a console is J-Runner's decision, handed over as this file.

        **Three patches, the hack types' alone** -- JTAG, the glitches and devgl, 2 to
        5: `smcnoeject` and `smcnoblink` replace a routine each, and `patchsmc` lifts
        the reset limit -- "will patch clean smc to remove 5 reset limit, ignored for
        retail". A retail or devkit image keeps its SMC untouched, measured.

        **The seal takes the console's own seed**, the first four bytes of the SMC the
        dump carries, so an unchanged SMC comes out as the dump's bytes; with no dump it
        is a staging buffer's -- see `_buffer` -- and under `-norandom` with no dump,
        four the original holds elsewhere.
        """
        given = self.material.smc
        carried = None
        if given is not None:
            smc = Smc.handed_in(given)
            if smc is None:
                if not self.config.smcnocheck:
                    raise ValueError("smc.bin is neither in the clear nor a valid, "
                                     "decryptable SMC; smcnocheck builds with it all "
                                     "the same")
                smc = Smc(cipher.opened(given))
            plain = smc.plain
        else:
            if self.dump is None:
                raise ValueError("this build has neither an smc.bin nor a dump to take "
                                 "an SMC from")
            carried = self.dump.smc
            plain = cipher.opened(carried)
        if self.image_type.number in (2, 3, 4, 5):
            for name in ("smcnoeject", "smcnoblink"):
                if getattr(self.config, name):
                    patched = Smc(plain).with_patch(name)
                    if patched == plain:
                        logger.warning("could not patch the SMC for %s: its routine is "
                                       "not in this image", name)
                    plain, carried = patched, None
            if self.config.patchsmc:
                patched = Smc(plain).patched()
                if patched != plain:
                    logger.info("patching smc to remove the reset limit")
                    plain, carried = patched, None
        self._check_smc(Smc(plain))
        if carried is not None and not self.drawing:
            return carried
        if not seed:
            if self.dump is None and not self.drawing:
                # Not the staging buffer's 8E0375CC: with no dump under `-norandom`
                # the original seals every SMC under these four, measured on a
                # trinity, a falcon JTAG and a corona build with three different
                # SMCs, twice over. Where they come from is not read out.
                seed = bytes.fromhex("cc7ac1e7")
            else:
                own = self.dump.smc[:4] if self.dump is not None else None
                seed = self._buffer("smc.bin", own)
        return cipher.sealed(plain, seed)

    def _check_smc(self, smc: Smc) -> None:
        """What the original refuses an SMC for, and what `smcnocheck` waives.

        Three cases are fatal and `smcnocheck` waives exactly those: a retail image
        over an SMC that is not clean, a JTAG image over one that is -- `Smc.clean_for`
        -- and an SMC that would not decrypt, which `smc` asks. A glitch image over a
        clean SMC only draws a complaint.

        One more refusal is ours: a blank SMC passes every test the original makes and
        is written, which gives a console none. A deliberate divergence agreed in
        x360mcp, and waived by `smcnocheck` like the rest.
        """
        if self.config.smcnocheck:
            return
        if smc.blank:
            raise ValueError("this SMC is blank -- nothing but 0x00 or 0xFF -- and an "
                             "image built over it would have none; smcnocheck builds "
                             "with it all the same")
        number = self.image_type.number
        clean = smc.clean_for(number)
        if self.image_type.name == "retail" and not clean:
            raise ValueError("hacked or unknown SMC binary found: a retail image wants "
                             "a clean SMC, and smcnocheck builds with this one anyway")
        if self.image_type.name == "jtag" and clean:
            raise ValueError("clean SMC found: a JTAG image wants a hacked one, and "
                             "smcnocheck builds with this one anyway")
        if number == 3 and clean:
            logger.warning("clean SMC found for a glitch image; building anyway")

    def keyvault(self) -> bytes:
        """The console's keyvault, as the image carries it: sealed under its CPU key.

        The dump's own, carried as it stands, when nothing asks for a change: sealing is
        deterministic -- the nonce is derived from the content -- so opening and closing
        it again would give the same bytes, and carrying it means a console whose
        keyvault this build cannot open still gets its own back.

        Otherwise it is `plain_keyvault` sealed again. See there.
        """
        if (self.material.keyvault is None and self.dump is not None
                and not self.drawing and not self._dvdkey_goes_in
                and (not self.cpu_key or self._own_keyvault() is not None)):
            return self.dump.sealed_keyvault
        return self.plain_keyvault().sealed(self.cpu_key)

    def _own_keyvault(self) -> Keyvault | None:
        """The dump's keyvault, or None where this CPU key does not open it -- which
        the original discards, and then stops for want of a kv.bin."""
        if self.dump is None:
            return None
        own = Keyvault.opened_if_own(self.dump.sealed_keyvault, self.cpu_key)
        if own is None:
            logger.warning("keyvault decrypt failed, discarding")
        return own

    @property
    def _dvdkey_goes_in(self) -> bool:
        """The DVD key goes into the keyvault on every type but retail, as the shipped
        ini says."""
        return bool(self.config.dvdkey) and self.image_type.name != "retail"

    def plain_keyvault(self) -> Keyvault:
        """The keyvault in the clear, as this build will seal it.

        **A `kv.bin` beside the build is written, over the dump's too** -- measured by
        x360mcp on a build with both, whose image carried the file's keyvault; see
        `Keyvault.handed_in` for the two states it may come in.

        **Its eight bytes of head are not the file's.** They are a staging buffer: the
        console's own keyvault's where the survey read them, drawn with no dump,
        compiled in under `-norandom`. Measured on donor builds in both regimes.

        No `kv.bin` and no dump is what the original refuses as "critical bootloader
        files are missing".
        """
        if not self.cpu_key:
            raise ValueError("a keyvault is sealed under the CPU key, and none was "
                             "given")
        own = self._own_keyvault()
        given = self.material.keyvault
        if given is not None:
            vault = Keyvault.handed_in(given, self.cpu_key)
        elif own is not None:
            vault = own
        else:
            raise ValueError("could not read kv.bin, and no keyvault the CPU key opens "
                             "in a dump: critical bootloader files are missing")
        vault = vault.with_head(self._buffer("kv.bin", own.head if own else None))
        if self._dvdkey_goes_in:
            vault = vault.with_dvd_key(self.config.dvdkey)
        return vault

    def xell(self) -> bytes | None:
        """The loader, or None for an image type that carries none.

        `xell-gggggg.bin` for a glitch image and `xell-2f.bin` for a JTAG one, verbatim
        and exactly 0x40000 bytes: the original's default-name resolver chooses by the
        type alone (x360mcp read it out of the jump table at 0x4501E8), and every
        image measured carries the one it names. Only the hack types carry one in the
        system area -- numbers 2 to 5; a devkit image lists XeLL as a file instead.
        """
        if self.image_type.number not in (2, 3, 4, 5):
            return None
        jtag = self.image_type.name == "jtag"
        return self.material.xell("xell-2f.bin" if jtag else "xell-gggggg.bin")

    def patch_slot(self) -> bytes:
        """What goes in the patch slot: one block, and a retail image leaves it erased.

        A lead -- sixteen bytes of 0xFF, or a manufacturing chain's fuses, see
        `_slot_lead` -- then the **last** set of the release's patch file as it stands,
        sentinel included, then zeros to the end of the block. Byte-exact on every
        reference image that has one.

        Two things about which file that set comes from. A `glitch` image on a fat
        console takes it from `patches_fat.bin` while its bootloaders are patched from
        `patches_<board>.bin`: the original's own log says `patches_fat.bin` for every
        fat spelling that builds one -- zephyr, falcon and all six jaspers -- and
        `patches_<board>.bin` for the slim ones, and the bytes agree. A `glitch2`
        image reads the file named after the **family**, so all six jasper spellings
        read `patches_g2jasper.bin`, which is what `Board.section` is.

        **A JTAG image takes the whole file** and nothing in front of it, unpadded: its
        reboot core applies the first set to the 1BL itself and moves the rest into
        place, so all four sets of `patches_falcon.bin` are at 0x91000 of the image the
        original built, 0xA74 bytes verbatim. Where it goes and what fills the room
        behind it is `image`'s.
        """
        block = layout.BLOCK
        if self.image_type.patches is False:
            return b"\xff" * block
        patches = self.patches
        if patches is None:
            raise ValueError("this release ships no patch file for a %s %s image"
                             % (self.console.name, self.image_type.name))
        if self.image_type.name == "jtag":
            return self._with_addons(patches.raw)
        last = patches.set_raw(len(patches.sets) - 1)
        return (self._slot_lead() + self._with_addons(last)).ljust(block, b"\x00")

    def _with_addons(self, listed: bytes) -> bytes:
        """The slot's patch set with every `-a` file's entries spliced in.

        Measured by x360mcp, building with `-a` and without: the entries go in behind
        the set's own, before its terminator, one terminator closes the lot, and the
        word after it says how many bytes the files brought -- their own lengths added
        up, 00 00 0C F8 for `xl_usb`'s 3320 and 00 00 0D 14 with `hvFixKeys` as well.
        Nothing else in the image moves. A file is `bin/<name>.bin` of the release.
        """
        if not self.config.append:
            return listed
        end = b"\xff\xff\xff\xff"
        body = listed[:-4] if listed.endswith(end) else listed
        brought = 0
        for name in self.config.append:
            extra = self.release.option(name).raw
            brought += len(extra)
            body += extra[:-4] if extra.endswith(end) else extra
        return body + end + brought.to_bytes(4, "big")

    def _slot_lead(self) -> bytes:
        """What sits in front of the patch set: sixteen bytes of 0xFF, or the fuses.

        A chain under the manufacturing regime -- a bit in its CB_A says so, not the
        image type -- belongs to a console whose fuses are not burnt, and its loader is
        handed them here instead, the set moving to 0x60. See `fuses`.
        """
        files = self._chain_files()
        if not files or not Stage(self.release.bootloader(files[0]), 0).manufacturing:
            return b"\xff" * 0x10
        cbb = [one for at, one in enumerate(files)
               if ROLES.get(one.kind) == "B" and at == 1]
        if not cbb:
            raise ValueError("fuses are built from the CB_B, and this chain has none")
        return self.fuses(cbb[0])

    def fuses(self, listed, devkit: bool = False) -> bytes:
        """The fuses for this console -- see `chain.fuses` -- from the CB it is bound
        on: a manufacturing chain's CB_B, a JTAG image's second CB.

        `devkit` gives a development kernel's instead, type 0 and no allow bits: a JTAG
        chain that ends in 1838's `SE_1838.bin` is "re-encoded" after its CB and the
        fuses the original then prints and writes are those -- measured.
        """
        if not self.cpu_key:
            raise ValueError("fuses carry the CPU key, and none was given")
        word = 0 if devkit else fuses.cb_word(self.release.bootloader(listed))
        return fuses.virtual(word, self.cpu_key, self.ldv)

    def chain(self, which: int = 0) -> bytes:
        """The bootloader region: the release's stages, patched, bound and sealed.

        `which` counts the chains the file list names; only a JTAG image names two. See
        `_chain_files`.

        The stages ship **in the clear** -- `cbb_9188.bin` and its neighbours are
        plaintext bodies behind a 0x20 header -- and the original seals them itself.
        Held against the chain of every reference image, opened again with its own keys:
        what this lays is what the original laid, byte for byte.

        Five things happen to them, and each was measured by taking a reference image's
        chain apart and putting it back:

        * **The list says which.** `CB` alone, or `CBA` and `CBB` where the chain is
          split, then `CD` and `CE`. CF and CG are on the same list and are not here.
        * **Two patch sets go on**: the first on `CB_B`, the second on `CD`, at offsets
          counted from the start of the stage, header included. A set may make a stage
          longer -- the release's CD is 0x4F20 and comes out 0x5290 -- and then the
          header says the new length, rounded up to `SEAL_ALIGN`, which is where the
          stage behind it begins. A chain with no CB_B takes the second set only, and a
          JTAG chain takes neither: measured, its CB, CD and CE are the release's files
          untouched, and so are the CB and CD of its second chain.
        * **Each nonce is the console's own**, stage for stage, read off the dump's
          chain. Every reference image carries the nonces of the dump it was built from.
          Where there is no dump to read there is nothing to carry, and the original
          draws them -- "initializing random nonces" -- so this draws them too.
        * **CB_B carries the console's block**: the pairing, and the sixteen bytes
          binding it to this SMC, at the start of its body. `chain.Fields` writes them.
          A JTAG image's second chain has no CB_B, and its single CB carries the block
          instead, bound under that CB's own key -- which is the ordinary one, from the
          1BL key and the nonce: taken apart on the reference image, it opens that way
          and the sixteen bytes are what `Fields` computes over it.
        * **Each stage is sealed under its own key**, `chain.sealing` deciding the order
          and, for a retail image on a chain with no CB_B, the second pass under the
          console's key.
        """
        listed = self._chain_files(which)
        if not listed:
            raise ValueError("this release names no bootloaders for a %s %s image"
                             % (self.console.name, self.image_type.name))
        out, offsets = bytearray(), []
        for index, one in enumerate(listed):
            offsets.append(len(out))
            out += self._stage_body(one, index)
        stages = [Stage(out, at) for at in offsets]
        for stage, nonce in zip(stages, self._nonces(stages), strict=True):
            stage.nonce = nonce
        keys = sealing.keys(stages, self.cpu_key or b"", self._second_pass_at(stages))
        binds = self._wears_console(stages, which)
        if binds >= 0:
            # Under the manufacturing regime the original computes no binding, and the
            # CB_B of an image it built that way carries sixteen zeros where the digest
            # would be. The switch is a bit in CB_A rather than the image type or the
            # file's name, which `Stage.manufacturing` reads.
            bound_to = None if stages[0].manufacturing else self.cpu_key
            at = offsets[binds] + STAGE_HEADER
            out[at:at + Fields.LENGTH * 2] = Fields.write(
                self.pairing, bound_to, keys[binds],
                cipher.fingerprint(self.smc()),
            )
        for stage, key in zip(stages, keys, strict=True):
            if key is None:
                raise ValueError(
                    "%s at %#x has no key: the CPU key this chain binds to was not "
                    "given" % (stage.tag, stage.at)
                )
            # Sealed over the padding as well as the body: the stream simply carries
            # on. Measured on the last stage, whose header states less than it fills --
            # the six bytes after CE are that continuation, and x360mcp saw it on a
            # manufacturing image, where CE had moved by 0x20 and the dump's bytes at
            # the same place were something else entirely.
            padded = stage.length + -stage.length % SEAL_ALIGN
            body = bytes(out[stage.at + len(stage.head):stage.at + padded])
            out[stage.at:stage.at + padded] = stage.head + rc4(key, body)
        return bytes(out)

    def _wears_console(self, stages, which: int = 0) -> int:
        """Which stage of a chain carries the console's block, or -1 for none.

        `stages` may be the stages or their kinds. A split chain carries it on CB_B.
        A single CB carries it itself -- sealed under its own key, with nothing of the
        console mixed in -- on a retail or devkit image and on a JTAG image's second
        chain, and a glitch image's single CB carries none at all. Measured on fat
        retail images of 13604, whose CB 5771 wears the pairing and the computed field,
        on devkit images, on the JTAG image, and on fat glitch images, whose log has no
        "CBENC pairing set to" line.
        """
        roles = [ROLES.get(getattr(one, "tag", one)) for one in stages]
        if roles[:2] == ["B", "B"]:
            return 1
        alone = self.image_type.number in (1, 6, 7, 8, 9)
        if roles[:1] == ["B"] and (which > 0 or alone):
            return 0
        return -1

    def _chain_files(self, which: int = 0) -> list:
        """The stages of one chain, out of the file list, in the order it names them.

        The list is positional and its slots may be empty: a fat `glitch` image reads
        `[CB, none, CD, CE, CF, CG]`, where `none` is the CB_B such a chain does not
        have. **It runs past the chain, too.** A JTAG list names nine files -- its own
        CB, CD and CE, then a CF/CG pair, then another CB and CD, then the release's own
        CF and CG -- and the image the original built carries two chains: CB 5770,
        CD 5770 and CE 1888 at 0x8000, and CB 5771 and CD 8453 at 0xD5060, while both
        CF pairs end up in slots. So a chain is a run of the chain kinds that CE or
        anything but a chain kind closes, and `which` counts the runs; that gives
        every reference image's chains exactly.
        """
        runs, run = [], []
        for one in self.stage_list:
            if one.absent:
                continue
            if one.kind in CHAIN_KINDS:
                run.append(one)
            if run and ROLES.get(one.kind, "E") == "E":
                runs.append(run)
                run = []
        if run:
            runs.append(run)
        return runs[which] if which < len(runs) else []

    def _stage_body(self, listed, index: int) -> bytes:
        """One stage in the clear, patched, and as long as its header will say.

        Padding to `SEAL_ALIGN` is part of what is sealed, so it is part of the stage
        rather than a gap between stages.
        """
        body = bytearray(self.release.bootloader(listed))
        which = self._patch_set_for(listed.kind, index)
        if which is not None:
            patches = self.patches
            if patches is not None and which < len(patches.sets):
                ends = max(one.at + one.length for one in patches.sets[which])
                if ends > len(body):
                    body += bytes(ends - len(body))
                body = bytearray(patches.over(bytes(body), which=which))
                Stage(body, 0).length = len(body) + -len(body) % SEAL_ALIGN
        return bytes(body) + bytes(-len(body) % SEAL_ALIGN)

    def _patch_set_for(self, kind: str, index: int):
        """Which set of the release's patch file this stage takes, if any.

        The first set is CB_B's -- the B stage in second place, which is where the
        development chains keep their SB -- and the second is CD's, SD's likewise. A
        JTAG image patches no stage of its chain, which is measured rather than assumed:
        its CB, CD and CE come out of the reference image as the release's files with
        nothing laid over them.
        """
        if self.image_type.name == "jtag":
            return None
        role = ROLES.get(kind)
        if role == "B" and index == 1:
            return 0
        return 1 if role == "D" else None

    def _second_pass_at(self, stages) -> int:
        """Which stage runs its key through the console's key a second time.

        The original's own test, at 0x41C760: the chain has no CB_B and the image is
        retail. That is the stage behind the single CB, which is its CD.
        """
        if sealing.binding_at(stages) >= 0 or self.image_type.name != "retail":
            return -1
        return 1 if len(stages) > 1 else -1

    def _nonces(self, stages) -> list:
        """One nonce a stage, out of the original's six stage buffers.

        **By role and not by position**: the second letter of the tag -- B, D or E --
        names the buffers a stage reads, CB_A and then CB_B for a CB. A chain with a
        single CB takes the dump's CB_A, CD and CE and leaves its CB_B out; taking them
        in order instead hands its CD the nonce of a CB_B, which reads as a chain and
        is not one. Measured on a fat glitch image and a JTAG one -- whose second chain
        takes the same CB_A and CD again -- and a role the buffers have no name for, a
        devgl chain's SC, takes the buffer of its position.

        What each buffer holds is `_buffer`'s: the dump's where the survey read it,
        drawn where the original draws, compiled in under `-norandom`.
        """
        read, _finished = self._walk
        order = ("CB_A", "CB_B", "CD", "CE", "CF", "CG")
        held = {name: self._buffer(name, read.get(name)) for name in order}
        roles = {"B": [held["CB_A"], held["CB_B"]], "D": [held["CD"]],
                 "E": [held["CE"]]}
        seen, out = {}, []
        for at, stage in enumerate(stages):
            role = stage.tag[1:2]
            have = roles.get(role)
            if not have:
                out.append(held[order[min(at, len(order) - 1)]])
                continue
            index = seen.get(role, 0)
            seen[role] = index + 1
            out.append(have[min(index, len(have) - 1)])
        return out

    def slot(self, tail_at: int, which: int = -1) -> bytes:
        """The update the console runs after the chain: CF, then CG, both sealed.

        One run of bytes, because CG does not fit and simply carries on: the first
        `layout.slot_span` of it are the slot, and the rest is the tail, which lands at
        `tail_at`. The CF has to say where that is, so the caller passes it.

        `which` counts the pairs the file list names, and only a JTAG image names two.
        **Only the last is the console's**: the reference image's first pair, CF/CG
        4532, carries the console's nonces and says where its tail is, and nothing
        else of the release's file is changed -- no slot number, no pairing, no
        binding. The last carries all of it, and its slot number is its place, which
        x360mcp read at 0x41CDB0 and the JTAG image confirms with a 1.

        What changes in the release's CF is `chain.update`'s -- where the tail lies,
        the console's block and the binding -- and **both nonces are the console's
        own**, taken from the dump's CF and the CG behind it: the slot with the largest
        lockdown value. Carried across releases: the dump's CF is 17502, the image's is
        17559, and they share a nonce. With no dump they are two of the original's
        staging buffers, like the chain's -- see `_nonces`.

        Nothing else. CG's plaintext is the release's, byte for byte.
        """
        if not self.cpu_key:
            raise ValueError("a CF binds itself to the console's CPU key, and none was "
                             "given")
        pairs = self._update_pairs()
        if not pairs:
            raise ValueError("this release names no CF and CG for a %s %s image"
                             % (self.console.name, self.image_type.name))
        which %= len(pairs)
        cf_listed, cg_listed = pairs[which]
        cf = bytearray(self.release.bootloader(cf_listed))
        cg = bytearray(self.release.bootloader(cg_listed))
        read, _finished = self._walk
        cf_nonce = self._buffer("CF", read.get("CF"))
        cg_nonce = self._buffer("CG", read.get("CG"))
        Stage(cf, 0).nonce = cf_nonce
        Stage(cg, 0).nonce = cg_nonce

        span = layout.slot_span(self.image_type, self.flash)
        spill = len(cf) + len(cg) - span
        update.with_tail(cf, tail_at // layout.BLOCK,
                         max(0, -(-spill // layout.BLOCK)))
        # A JTAG image's first pair is the one its exploit boots through, and it never
        # carries the console -- 1838 names no second pair, and its one CF still goes
        # out with nothing of the console in it, measured.
        jtag_first = self.image_type.name == "jtag" and which == 0
        if which < len(pairs) - 1 or jtag_first:
            return update.sealed(cf, cg, cg_nonce, SEAL_ALIGN)
        # The pairing goes in only where a chain binds to the console. A chain with
        # no CB_B binds nowhere, and its CF carries three zeros there and the lockdown
        # value all the same -- measured on a fat glitch image, the one such chain this
        # release builds beside a slot. A JTAG image binds on its second chain's CB.
        binds = any(
            self._wears_console([one.kind for one in self._chain_files(chain)],
                                chain) >= 0
            for chain in (0, 1) if self._chain_files(chain)
        )
        update.with_console(cf, which, self.pairing if binds else bytes(3), self.ldv,
                            self.cpu_key)
        return update.sealed(cf, cg, cg_nonce, SEAL_ALIGN)

    def _update_pairs(self) -> list:
        """The CF/CG pairs the file list names, in order: one, or a JTAG image's two.

        A CF opens a pair and the CG after it closes it.
        """
        pairs, cf = [], None
        for one in self.stage_list:
            if one.absent:
                continue
            if one.kind == "CF":
                cf = one
            elif one.kind == "CG" and cf is not None:
                pairs.append((cf, one))
                cf = None
        # None at all is a real answer: 1888, 1838 and 17489 name `none` in both
        # places and ship no update, and the original leaves the slot erased.
        return pairs

    def files(self, when: int) -> list:
        """The files the filesystem holds after the CG's tail, as `(name, bytes)`.

        The release's `[flashfs]` list and then its `[security]` list, each in the
        order it names them -- which is the order of every reference image's table.

        A patch file is written under its name with the number of update slots its
        type has after it: `aac.xexp` goes in as `aac.xexp1` and `xenonclatin.xttp` as
        `xenonclatin.xttp1`, all seven of them on every image measured -- and as
        `aac.xexp2` on the JTAG one, which has two.

        A file the list names outside the release that is not there -- `..\\launch.xex`
        and its two neighbours -- is left out, as the original leaves it; its list
        states a checksum of zero, which is how it says the file is optional.
        """
        recipe = self.recipe
        out = []
        # The number of update slots the type has, not of pairs the list names: a JTAG
        # list with its second pair taken out still writes `aac.xexp2`, measured.
        suffix = "2" if self.image_type.name == "jtag" else "1"
        for listed in recipe.firmware:
            if listed.name.lower().startswith("sysupdate.xexp"):
                # The name the tail of CG goes under, so the original will not take a
                # file of that name from the list: "firmware file sysupdate.xexp
                # ignored, 'sysupdate.xexp' is a reserved name!" -- measured with one
                # added to 17559's list, which built as if it were not there. Its test
                # is `_strnicmp` over those fourteen characters (0x42EB36), so any case
                # and anything after them, `sysupdate.xexp1` included.
                logger.warning("firmware file %s ignored, 'sysupdate.xexp' is a "
                               "reserved name!", listed.name)
                continue
            body = self.release.firmware(listed)
            if body is None:
                # A file the list vouches for with no checksum, or with zero, is one
                # the original goes without: "could not read file '..\\launch.xex',
                # skipping" -- and 7258's `Byrom.xex`, listed with none, likewise.
                if listed.outside or not listed.crc:
                    logger.warning("could not read file '%s', skipping", listed.name)
                    continue
                raise ValueError("%s is named by the file list and the release does "
                                 "not have it" % listed.plain)
            name = listed.plain
            # Any name ending in `p` that the list vouches for with a checksum: 17489's
            # and 1838's `rrbkgnd.bmp` go in as `rrbkgnd.bmp1` beside every `.xexp1`,
            # and 17489_RGL's `rglXam.rglp`, listed with none, goes in as it is --
            # all three measured.
            if name.lower().endswith("p") and listed.crc:
                name += suffix
            out.append((name, body))
        for listed in recipe.security:
            body = self.security_file(listed.plain, when)
            if body is not None:
                out.append((listed.plain, body))
        return out

    def security_file(self, name: str, when: int) -> bytes | None:
        """One of the five security files sealed for this console, or None to leave out.

        The **content** comes from the first place that has it, in the order the
        original's log walks: a file beside the build, the update container -- only
        crl.bin and dae.bin are ever in one, "using data from SUPD" -- and then the
        console's own dump. `nosusecurity` takes the container out of that and
        `nosecurity` the dump. What has no source at all is left out of the image, which
        is what happens to crl.bin, dae.bin and fcrt.bin with both options -- except
        extended.bin and secdata.bin, which the build makes up clean: "Making up an
        clean/empty extended.bin!".

        The **sealing parameters** are the console's own copies' unless `nosecurity`
        says the dump is not to be read, and then the ones compiled into the original.
        extended.bin's head is the keyvault's either way.

        All of it measured against the original with each option and with both.
        """
        if not self.cpu_key:
            raise ValueError("the security files are sealed for a console's CPU key, "
                             "and none was given")
        config = self.config
        own = None
        if self.dump is not None and not config.nosecurity:
            try:
                own = self.dump.image.read(name)
            except ValueError:
                own = None
            if own is not None and not security.verifies(name, own, self.cpu_key):
                logger.warning("%s verify failed! Discarding data.", name)
                own = None
        content, clear, made_clean = self.material.bytes_in(name), False, False
        if content is not None:
            verdict, clear = security.taken_beside(name, content, self.cpu_key)
            if verdict == "as is":
                logger.error("%s appears to be crypted with the wrong key or damaged",
                             name)
                return content
            if verdict == "clean":
                logger.warning("%s is not the correct size or would not open; making "
                               "up a clean one", name)
                content, made_clean = None, True
        if content is None and name in ("crl.bin", "dae.bin") and \
                not config.nosusecurity and self.release.container is not None and \
                name in self.release.container.held:
            content = self.release.container.read(name)
        if content is None and not made_clean:
            content = own
        cpu, ldv = self.cpu_key, self.ldv
        if name == "crl.bin":
            if content is None:
                return None
            own_params = None if own is None else security.crl_parameters(own, cpu)
            iv, key = self._buffer(name, own_params)
            return security.crl(content, cpu, when, ldv, iv, key, clear)
        if name == "dae.bin":
            if content is None:
                return None
            own_params = None if own is None else security.dae_parameters(own, cpu)
            head, field = self._buffer(name, own_params)
            return security.dae(content, cpu, when, ldv, head, field)
        if name == "extended.bin":
            return security.extended(content, self.plain_keyvault().head, cpu,
                                     clear)
        if name == "secdata.bin":
            carried = None
            if own is not None:
                carried = security.secdata_head(own, cpu)
            return security.secdata(content, cpu, when, ldv,
                                    self._buffer(name, carried), clear)
        if name == "fcrt.bin":
            return None if content is None else security.fcrt(content, cpu)
        # Any other name the list gives -- 9199's names `odd.bin` -- is looked for
        # like the rest and, found nowhere, left out: "WARNING: odd.bin not found,
        # skipping". Found beside the build, it goes in as it is -- measured with a
        # made-up odd.bin, listed between crl.bin and extended.bin as its list says.
        if content is None:
            logger.warning("%s not found, skipping", name)
        return content

    @property
    def ldv(self) -> int:
        """The lockdown value written into the chain's CF and three security files.

        `cfldv` when it is given, the console's own -- read off its CF -- otherwise, and
        1 with no dump to read it off, which the original says: "cfldv was not set
        anywhere, setting it to 1".
        """
        if self.image_type.name == "jtag" and any(
                one.kind == "SE" for one in self.stage_list):
            # A JTAG list naming an SE -- 1838's second chain ends in `SE_1838.bin` --
            # gives a lockdown value of zero, "Fuse CF LDV set to : 0x0000...", and the
            # fuses and the security files carry it, `cfldv` or not. The original sets
            # it as it reads the stage's magic (0x42AD51). Measured on 1838 with and
            # without `-o cfldv=10`, and on 17559's list with its own pair taken out,
            # which keeps the console's 14: it is the SE and not the missing pair.
            return 0
        if self.config.cfldv is not None:
            return self.config.cfldv
        if self.dump is None:
            logger.warning("cfldv was not set anywhere, setting it to 1")
            return 1
        return self.dump.ldv

    def image(self, when: int | None = None) -> Image:
        """The whole image, every region in its place and every page's spare written.

        `when` is the build's time, which the directory's stamps and three security
        files carry: the clock when nothing says, and a reference build's own when one
        is being reproduced.

        Which pages carry spare follows the rule x360mcp measured over every page of a
        reference build: a page gets it exactly when the build wrote something there.
        Content decides for the regions below the filesystem, since what nothing wrote
        is erased; the files, the settings blobs, the table and the console's settings
        are marked by their spans, because their pages may hold 0xFF all the same.
        """
        when = int(time.time()) if when is None else when
        # Refused here, before anything is laid, as the original does.
        if self.console is None:
            raise ValueError("you need to specify console type!")
        _ = self.one_bl_key
        out = Image.blank(self.flash, self.bigffs)
        where, spills = self._system_area(out)
        placed, table_at = self._filesystem(out, where, spills, when)
        self._top_of_flash(out, placed, table_at)
        return out

    def _system_area(self, out: Image) -> tuple:
        """Everything below the filesystem: header, SMC, keyvault, chains, XeLL, slots,
        patch slot and JTAG loaders. Returns `layout.for_type`'s regions and the CG
        tails that spill into the filesystem."""
        flash, bigffs = self.flash, self.bigffs
        chain = self.chain()
        chain_end = layout.CHAIN_AT + len(chain)
        second = self.chain(1) if self._chain_files(1) else b""
        plain_end = layout.CHAIN_AT + sum(
            -(-len(self.release.bootloader(one)) // SEAL_ALIGN) * SEAL_ALIGN
            for one in self._chain_files()
        )
        where = layout.for_type(self.image_type, flash, chain_end, bigffs, len(second),
                                plain_end)
        slots, tail_at = where["slot"][0], where["tail"][0]
        smc = self.smc()
        smc_at = layout.smc_at(len(smc))
        page = self.header(slots, self.stated_version, len(smc))
        # Zeros from the page to the SMC, on every reference image.
        out.put(0, page + bytes(smc_at - len(page)))
        net_kd = self.dump.net_kd if self.dump is not None else None
        if net_kd:
            # "Inserting netKd data from dump into header": as many bytes as the block
            # states, at 0x80 -- see `Dump.net_kd`. Only a block inside the first page
            # was measured, so a longer one is left out rather than laid over whatever
            # follows it.
            if 0x80 + len(net_kd) <= PAGE:
                logger.info("Inserting netKd data from dump into header")
                out.put(0x80, net_kd)
            else:
                logger.warning("the dump's netKd block states %#x bytes, more than the "
                               "header's page holds; left out", len(net_kd))
        out.put(smc_at, smc)
        out.put(layout.KEYVAULT_AT, self.keyvault())
        # The chain's last block is filled out with zeros, as a file's is.
        out.put(layout.CHAIN_AT, chain + bytes(-chain_end % layout.BLOCK))
        xell = self.xell() if "xell" in where else None
        if xell is not None:
            out.put(where["xell"][0], xell)
        # One slot pair after another, and each tail straight behind the one before.
        spills, at, span = [], tail_at, where["slot"][1]
        for which in range(len(self._update_pairs())):
            run = self.slot(at, which)
            out.put(slots + which * span, run[:span])
            spill = run[span:]
            out.put(at, spill + bytes(-len(spill) % layout.BLOCK))
            spills.append(spill)
            at += len(spill) + -len(spill) % layout.BLOCK
        if "freeboot" in where:
            self._jtag_regions(out, where, second)
        else:
            out.put(where["patches"][0], self.patch_slot())
        out.mark_written(0, tail_at)
        if "payload" in where:
            # The payload's page says how long the core is, in words, at bytes 10 and
            # 11 of its spare -- the one page of any image with anything there. The
            # built-in core's length, whatever core goes in: 0x350 beside a 0xD80 one
            # from the release, whose own length the payload is patched with instead.
            words = len(jtag.builtin("freeboot.bin")) // 4
            out.mark(where["payload"][0], PAGE, extra=words.to_bytes(4, "big"))
        return where, spills

    def _filesystem(self, out: Image, where: dict, spills: list, when: int) -> tuple:
        """The files, the settings blobs and the table -- see `Filesystem`. Returns the
        blobs placed and the table's block, which the anchors of an eMMC point at."""
        flash, bigffs = self.flash, self.bigffs
        base = flash.base_of(bigffs) * layout.BLOCK
        fs = Filesystem.on(flash, (where["tail"][0] - base) // layout.BLOCK, bigffs)
        # Two seconds on from the build's time, the same two the security files' stamp
        # carries: the reference images' entries say 15:17:50 where the build began at
        # 15:17:48 UTC.
        stamp = Entry.fat_time(when + 2)
        # The tail is the first file on every shape of flash, and a JTAG image's two
        # are the first two.
        for index, spill in enumerate(spills):
            fs.add("sysupdate.xexp%d" % (index + 1), spill, stamp=stamp)
        for name, body in self.files(when):
            fs.add(name, body, stamp=stamp)
        fields = b""
        if flash.spare is not None and flash.spare.fs_at is not None:
            fields = self._fs_fields(where["slot"][0])
        fs.over(out, fields)
        placed = fs.lay_blobs(out, {} if self.config.nomobile else self._mobiles(),
                              fields)
        fs.lay_table(out, fields)
        return placed, fs.table_at

    def _top_of_flash(self, out: Image, placed: dict, table_at: int) -> None:
        """What is laid last: the console's settings, an eMMC's anchors, the raw
        patches, a kept memory unit, and the blocks moved off bad ones."""
        for at, body, span in self._settings():
            out.put(at, body)
            out.mark(at, span)
        if self.flash.anchors:
            anchors.lay(out, table_at, placed)
        # The file list's own `[rawpatch]` first -- a devkit list names two, "(1)" and
        # "(2)" in the original's log -- and then `-8`'s. Each line is a name and an
        # offset, which the list keeps where a checksum would be.
        listed = [(one.name, one.crc) for one in self.recipe.raw_patches]
        for name, at in listed + list(self.config.raw_patches):
            # "[rawpatch]": raw bytes into the flat image, "just before combining spare
            # and finalizing ecc". The spare's fields are already settled by then, so a
            # patch over erased flash leaves its pages' fields erased and only the code
            # follows the new bytes -- measured at 0xC4200. Relative to the release, as
            # the original looks for the file.
            out.put(at, self.release.raw_file(name))
        if self.config.nandmu:
            self._memory_unit(out)
        self._remap(out)

    def _memory_unit(self, out: Image) -> None:
        """`nandmu`: the dump's memory unit carried across verbatim, spare included --
        see `Dump.memory_unit`. Measured on a jasper256 build from a dump carrying one:
        the range comes across, and without the option nothing does. Only into an image
        for the same big block part.

        The sample ini promises more: "if the dump is provided as a full 256M or 512M
        dump, the remaining 192M/448M will be copied onto the end of the new image as
        well". v1.21.810 does not, measured with a 256 MB dump and `nandmu`: its image
        is 64 MB, like this one. The copy is there (0x416840) but asks for a load size
        past 64 MB, which the loader has already cut to 64 MB -- see `dump_raw`.
        """
        dump = self.dump
        if dump is None or self.flash.spare is None:
            return
        where = dump.memory_unit
        if where is None:
            return
        if dump.flash.blocks != self.flash.blocks:
            logger.info("nandmu: the dump is not from a part like this one; nothing "
                        "to keep")
            return
        logger.warning("nanddump.bin has NAND memory unit data; keeping blocks 0x10 "
                       "to 0x15B of it")
        out.carry(dump.image, *where)

    def _remap(self, out: Image) -> None:
        """Move what lands in the console's written-off blocks to blocks standing in.

        Which blocks: those the dump's chip marks bad, and those holding a page whose
        code no longer matches -- `noecdremap` leaves those alone and `noremap` all of
        them, "Discarding remap data as NOREMAP was specified!". Where to: the block the
        dump already has standing in, and otherwise the highest one nothing else
        holds, counting down -- "block 0x100 had no remap, assigning remap block 0x3ff".
        Measured on a dump with one block marked bad and one failing its code: they
        went to 0x3FF and 0x3FE, in that order, with and without the two options.

        Only where the dump's flash is the part being built for: a 16 MB dump's blocks
        say nothing about a 64 MB part's, and what the original does then has not been
        measured.
        """
        flash = self.flash
        if self.config.noremap or self.dump is None or flash.spare is None:
            return
        own = self.dump.flash
        if own.spare is None:
            return
        per = own.spare.pages_a_block
        moves = order.stand_ins(self.dump_raw, own, not self.config.noecdremap,
                                len(self.dump_raw) // ((PAGE + own.spare.length) * per))
        if moves and (own.blocks, per) != (flash.blocks, flash.spare.pages_a_block):
            logger.warning("the dump's bad blocks are not carried into an image for "
                           "another flash; nothing is remapped")
            return
        for block, stand_in in moves.items():
            logger.info("remapping block %#x to block %#x", block, stand_in)
            out.retire(block, stand_in)

    def _jtag_regions(self, out: Image, where: dict, second: bytes) -> None:
        """What a JTAG image carries past its slots: the loaders its hack runs on.

        Each at the address the reboot core has compiled into it -- see `layout`.

        * **payload.bin**, the page after the header, and **freeboot.bin**, the core,
          zeros to the patch list -- each patched as `jtag.loaders` says.
        * **the patch list**, the whole patch file -- see `patch_slot` -- and zeros to
          the end of the block. The block after it is erased and still marked written,
          which is the rest of the list's 0x4000: x360mcp measured the eight pages.
        * **the fuses**, from the second chain's CB -- see `fuses`.
        * **the second chain**, and zeros to the end of its block.

        All of it byte for byte against the reference image.
        """
        core = jtag.core_for(self._jtag_loader("freeboot.bin"), self.recipe.version)
        payload = jtag.payload_for(self._jtag_loader("payload.bin"), len(core))
        out.put(where["payload"][0], payload)
        at, room = where["freeboot"]
        out.put(at, core.ljust(room, b"\x00"))
        listed = self.patch_slot()
        at, room = where["patches"]
        if len(listed) > room:
            raise ValueError("a patch list of %#x bytes does not fit the %#x the core "
                             "reads" % (len(listed), room))
        out.put(at, listed + bytes(-(at + len(listed)) % layout.BLOCK))
        out.mark(at, room)
        files = self._chain_files(1)
        out.put(where["fuses"][0],
                self.fuses(files[0], any(one.kind == "SE" for one in files)))
        at = where["second chain"][0]
        out.put(at, second + bytes(-(at + len(second)) % layout.BLOCK))

    def _jtag_loader(self, name: str) -> bytes:
        """`payload.bin` or `freeboot.bin`: the release's own, else the built-in one.

        The original looks in the release's `bin/` and falls back to copies built into
        itself -- "could not read 17559/bin/payload.bin, using built in payload (0x200
        bytes)". Those copies are carried here as they are in xeBuild.exe, at file
        offsets 0x49360 (0x200 bytes) and 0x49560 (0xD40).
        """
        own = self.release.in_bin(name)
        if own is not None:
            return own
        logger.info("could not read %s, using built in %s", name, name)
        return jtag.builtin(name)

    def _fs_fields(self, slots: int) -> bytes:
        """The three bytes a big block chip's filesystem pages carry at 7.

        free60's FsSize1, FsSize0 and FsPageCount. The first says how much of the flash
        the system area takes, in blocks of 0x20000: all of the first 2 MB -- 0x10, on
        all three glitch types measured and on a jasperbb devkit image, which carries
        no XeLL there -- and on a retail one where its bootloader region ends, the slot
        and the patch slot included, which is 5 on the trinitybb measured. The second
        is the filesystem's size in blocks over 32, and the third is 4 on every image
        measured.
        """
        flash = self.flash
        if self.image_type.name != "retail":
            system = 0x10
        else:
            span = layout.slot_span(self.image_type, flash)
            system = (slots + 2 * span) // 0x20000
        size = flash.last_block - flash.base_of(self.bigffs)
        return bytes([system, size >> 5, 4])

    def _mobiles(self) -> dict:
        """The settings blobs this console carries, by name: the material's first."""
        out = dict(self.material.mobiles)
        if self.dump is not None:
            for name in self.dump.image.blobs:
                if name.startswith("Mobile") and name not in out:
                    out[name] = self.dump.image.blob(name)
        return out

    def _settings(self) -> list:
        """The console's statistics, manufacturing data and settings block, placed.

        As `(where, bytes, how much is marked written)`. Each is given eight pages of
        spare whatever its bytes hold -- measured by x360mcp: the statistics' block at
        0xF78000 carries spare on all eight pages although most of it is 0xFF. With
        `nomobile` the statistics are not written at all, spare included, and
        manufacturing data only when the console has any.
        """
        flash = self.flash
        span = 0x1000
        stats_at = flash.smc_config - flash.round_to
        out = []
        if self.dump is not None:
            if self.dump.manufacturing_written:
                out.append((stats_at - flash.round_to, self.dump.manufacturing, span))
            if not self.config.nomobile:
                out.append((stats_at, self.dump.statistics, span))
        config = self._given_config()
        if config is None and self.dump is not None:
            # Where the dump keeps it is the dump's own flash's business, not the one
            # being built for: a 16 MB dump builds a 64 MB image.
            own = self.dump.flash.smc_config
            config = bytes(self.dump.image.flat[own:own + span])
        if config is not None:
            out.append((flash.smc_config, self._configured(config), span))
        return out

    def _given_config(self) -> bytes | None:
        """The settings block handed over as `smc_config.bin` -- `SmcConfig.found_in`.

        The original writes that block and leaves the rest of the 0x1000 erased, its
        pages marked written all the same: measured on donor builds from `Trinity.bin`,
        whose next 0xC00 are erased anyway, and `Falcon.bin`, whose are zeros and still
        come out 0xFF.
        """
        given = self.material.smc_config
        if given is None:
            return None
        found = SmcConfig.found_in(given)
        if found is None:
            logger.warning("smc_config.bin holds no valid settings block; not used")
            return None
        return found.sealed().ljust(0x1000, b"\xff")

    def _configured(self, block: bytes) -> bytes:
        """The settings block with the options that land in it written in -- the
        fields are `SmcConfig`'s."""
        config = self.config
        settings = SmcConfig(block)
        settings.set_fan("cpu", config.cpufan)
        settings.set_fan("gpu", config.gpufan)
        for name in TEMPERATURES:
            settings.set_temperature(name, getattr(config, name))
        if config.macid:
            settings.set_mac(config.macid)
        settings.set_regions(config.avregion, config.gameregion, config.dvdregion)
        return settings.sealed()

    @property
    def stated_version(self) -> int:
        """The version word the image's page states: 1888, 0x0760, whatever the chain.

        Every release here but three ships `ce_1888.bin`, so reading it off the CE gave
        the same number; the three that do not settle it. 1838's and 17489's chains end
        in `SE_1838.bin` and `SE_17489.bin`, and the images the original built from them
        state 0x0760 all the same -- measured on both.

        **A devkit image states its E stage's own** -- "flash header build version set
        to v.17489": 0x4451 from `SE_17489.bin` and 0x072E from `SE_1838.bin`, measured.
        """
        if self.image_type.number in (6, 7, 8, 9):
            for one in self._chain_files():
                if ROLES.get(one.kind) == "E":
                    return Stage(self.release.bootloader(one), 0).build
        return 1888

    @property
    def patches(self):
        """The patch file this build reads, or None for a type that reads none.

        One choice for the whole build, because the chain and the patch slot take their
        sets from the same file. A `glitch` image on a fat console reads
        `patches_fat.bin` rather than the file named after the console -- the original's
        log says so for every fat spelling, and the bytes of both the chain and the slot
        agree.
        """
        fat = self.console.fat and self.image_type.name == "glitch"
        # `-r` and `-i` both put their word into the patch file's name: `-r WB` reads
        # `patches_g2corona_WB.bin`, `-i flash` `patches_g2mjasper_flash.bin`, and both
        # at once `-i`'s first -- `-i X -r Y` reads `patches_g2trinity_X_Y.bin`. All
        # three measured.
        ext = "_".join(one for one in (self.config.firmware_ext,
                                       self.config.section_ext) if one)
        return self.release.patches(self.image_type, "fat" if fat else self.console,
                                    ext)

    def header(self, slots: int, stated_version: int, smc_length: int) -> bytes:
        """The image's first page, built from named fields rather than copied.

        Every byte of it is held against the pages of **sixteen images the original
        built**, and all sixteen agree, so a build with no dump to copy a page from
        produces the same page as one with a dump.

        What the caller says is what the page states about things it cannot see from
        here: where the slots begin, the version word -- 0x0760, see `stated_version` --
        and how long the SMC is. Where the SMC goes follows from
        that length, because it ends where the keyvault begins; `layout.smc_at` is the
        rule, and a page stating a place that disagrees with the length is what it
        prevents.

        The rest follows from the console and the type:

        * the magic, and the entry point, which is 0x8000 on every image measured
        * the slot offset, **twice**: at 0x0C and again at 0x64
        * the copyright line, whose year is the board's, and a JTAG image carries the
          other year the board has
        * the word at 0x48: one for every hack measured and zero for retail
        * the boot flags at 0x4C -- see `boot_options`
        * the keyvault, at 0x4000 and 0x4000 long on all sixteen -- a xenon and a
          zephyr leave the length zero -- the two patch slots the page counts, and the
          keyvault's version word
        * the erase block at 0x70, which is the console's own: a falcon image says zero
          where a trinity one says 0x10000
        * nothing at 0x74, which is where a settings block's address would go; every
          image built leaves it zero and the original then goes looking -- "seeking smc
          config in dump...found at offset 0xf7c000"
        """
        head = Header.blank()
        head.version = stated_version
        head.entrypoint = layout.CHAIN_AT
        head.size = slots
        head.cf_at = slots
        # A devkit image carries 2010 whatever the board -- measured on xenon, falcon,
        # jasper and jasperbb, whose other images say 2005, 2007 and 2009.
        kit = self.image_type.number in (6, 7, 8, 9)
        year = 2010 if kit else self.console.notice_year(self.image_type.name)
        head.notice = NOTICE.replace(b"2010", b"%d" % year)
        head.before_flags = 1 if self.image_type.number in (2, 3, 4, 5) else 0
        if kit:
            head.word_at_04 = 0x8000
        self.boot_options(head)
        head.keyvault_at = layout.KEYVAULT_AT
        if self.console.states_keyvault_size:
            head.keyvault_size = layout.KEYVAULT_AT
        head.patch_slots = 2
        head.keyvault_version = 0x0712
        flash = self.flash
        head.block_size = flash.block_size if flash.states_block_size else 0
        if head.block_size and self.image_type.name == "jtag":
            # A JTAG image states the 16 MB step whatever the part's own is: x360mcp
            # measured `-t jtag -c jasper256`, whose flash steps 0x20000 and whose image
            # says 0x10000 here.
            head.block_size = 0x10000
        head.smc_size = smc_length
        head.smc_at = layout.smc_at(smc_length)
        return bytes(head.image)

    def boot_options(self, head: Header) -> None:
        """The four bytes at 0x4C that decide how the console starts, set on `head`.

        Measured by x360mcp a build at a time, each option against a reference, and
        named in `Header`:

        * `xell_reason` is `xellbutton`; `nodvd` and `olddvd` clear it
        * `xell_reason2` is `xellbutton2`, zero when it is the same button
        * `boot_options` is 1 for `cygnos` or `demon`, which write the same bit; on a
          JTAG image 2 for `nodvd` and otherwise 4, unless `olddvd` asks for the older
          way
        * `dualboot_reason` is `dualboot`, on a JTAG image only, zero when it is the
          button XeLL starts on

        A retail image carries XeLL on no button at all and the word is zero, which the
        reference images show; so does a devkit one. The whole block belongs to types 2
        to 5, as x360mcp read at 0x40D700.
        """
        if self.image_type.number not in (2, 3, 4, 5):
            head.boot_flags = 0
            return
        config, jtag = self.config, self.image_type.name == "jtag"
        reason = 0 if config.nodvd or config.olddvd else \
            BUTTONS[config.xellbutton or "eject"]
        second = BUTTONS[config.xellbutton2] if config.xellbutton2 else 0
        options = 1 if (config.cygnos or config.demon) else 0
        if jtag and config.nodvd:
            options |= 2
        elif jtag and not config.olddvd:
            options |= 4
        switch = BUTTONS[config.dualboot] if jtag and config.dualboot else 0
        head.xell_reason = reason
        head.xell_reason2 = 0 if second == reason else second
        head.boot_options = options
        head.dualboot_reason = 0 if switch == reason else switch

    def auto_name(self) -> str:
        """The name the original gives an image when it is given none: the file list's
        version and the `-c` spelling, around the type's word -- `ImageType.image_name`.
        """
        return self.image_type.image_name(self.recipe.version, self.config.console_name)

    def __repr__(self) -> str:
        return "Build(%s, %s)" % (self.image_type.name, self.console.name)


def build_image(config, when: int | None = None) -> str:
    """Image Build Mode, whole: the image written to disk, and its SHA-1 if asked for.

    Everything comes from `config`. `data` is the release, and the per-build directory
    is `per_build`; with neither given the original takes `./data/` for both --
    "WARNING: you did not specify per build directory! Using ./data/" -- and so does
    this. The bootloaders shared by every release are `common/` beside the release.

    The image goes to `out`, and with none to the name the original makes up:
    `<the file list's version>_<word>_<the -c spelling>.bin` -- `17559_g2_trinity.bin`,
    `17559_gg_jasper256.bin`, `17559mfg_g2m_trinitybigffs.bin`, all measured by x360mcp;
    the version is the list's own and not the directory's. `sha_file` asks for a
    SHA-1 of the image beside it, as `sha1sum` writes one -- the digest, " *" and the
    image's name -- in the file it names, or `<out>.sha1` when it is just `True`.

    Returns where the image went. `when` is the build's clock, for reproducing one.
    """
    if config.per_build is None:
        logger.warning("you did not specify per build directory! Using ./data/")
    release = Release(config.data or "data")
    one = Build(config, Material(config.per_build or "data"), release)
    image = one.image(when)
    out = config.out or one.auto_name()
    raw = image.raw
    with open(out, "wb") as handle:
        handle.write(raw)
    logger.info("wrote %s, %#x bytes", out, len(raw))
    if config.sha_file:
        where = out + ".sha1" if config.sha_file is True else config.sha_file
        with open(where, "w") as handle:
            handle.write("%s *%s\n" % (hashlib.sha1(raw).hexdigest(),
                                         os.path.basename(out)))
    return out
