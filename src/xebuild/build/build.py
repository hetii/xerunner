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

import logging

from ..crypto import smc as cipher
from ..image import Dump, Header
from ..smc import Smc
from . import layout

# The copyright line every image carries, with the year a build replaces. Read off the
# sixteen reference images, which carry two different years and nothing else different.
NOTICE = b"\xa9 2004-2010 Microsoft Corporation. All rights reserved."

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

    @property
    def console(self):
        return self.config.console

    @property
    def image_type(self):
        return self.config.image_type

    @property
    def dump(self) -> Dump | None:
        """The console's own flash, or None when the material holds no dump.

        Read once: it is seventeen megabytes and nearly every region asks it
        something.

        **It is read with the flash `-c` names, and refused when the file is not that
        long.** The original does better than this and says so -- "Detecting NAND
        controller type from dump data... NAND dump is from a small block machine / NAND
        dump uses big block controller" -- so it will build for one shape from a dump of
        another. Which field that detection reads has not been measured here, and a dump
        read with the wrong geometry is not an error anything notices: the spare bytes
        are taken out at the wrong stride and every offset into it is then wrong, which
        reads back as a keyvault that will not open rather than as a refusal. So this
        refuses instead, and says what is missing.
        """
        if self._dump is None and self.material.dump is not None:
            wanted = self.console.flash.raw_length
            if len(self.material.dump) != wanted:
                raise ValueError(
                    "this dump is %#x bytes and a %s holds %#x; reading a dump of one "
                    "shape for a console of another needs the controller detection the "
                    "original does and this does not"
                    % (len(self.material.dump), self.console.name, wanted)
                )
            self._dump = Dump(self.material.dump, self.console, self.config.bigffs)
        return self._dump

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
        """The 1BL key, the same way."""
        if self.config.one_bl_key is not None:
            return self.config.one_bl_key
        return self.material.key_in_file("1blkey.txt")

    def smc(self, seed: bytes = b"") -> bytes:
        """The SMC as the image carries it: sealed, and patched if the options ask.

        **The original chooses no image of its own.** It takes `smc.bin` from the
        per-build directory, and where there is none it keeps the console's --
        "reading data/smc.bin failed, using smc.bin from nand dump". Measured three
        ways: with the nineteen shipped images sitting in the per-build directory, in
        the base path's `data/`, and nowhere at all. Forty-six builds over every board
        spelling and three hack types wrote the dump's own SMC, byte for byte, without
        one exception. Which shipped image belongs to a console
        is J-Runner's decision, and it hands it over as this file; the names are
        recorded on the boards for whoever plays that part.

        **`patchsmc` lifts the reset limit and does nothing else**, and the ini
        shipped beside the original says where it does not apply: "will patch clean smc
        to remove 5 reset limit, ignored for retail". Measured both ways -- a JTAG build
        of
        `SMCfzj.bin`, which still has a limit, came out with the two bytes at its
        signature zeroed and nothing else changed; a retail build of
        `TRINITY_CLEAN.bin` kept its limit although the same option was set.

        **The seal takes the console's own seed**, which is the first four bytes of the
        SMC the dump carries. Where nothing patches and nothing replaces it, that means
        the dump's bytes come out unchanged; where an image was replaced or patched, it
        is sealed again under that same seed. Measured on seven images built from a
        plaintext `smc.bin`, all of which carry the dump's seed `fbd75a10`.

        The one reading that looked like an exception was not one: a `xenon` build whose
        image carried a different seed turned out to be a build that never ran -- the
        original stopped at "could not find label [xenonbl] in file list ini" and what
        was read back was the previous build's image, left in the directory. Every build
        that really ran carries the dump's.

        **Two more SMC patches exist and neither is reproduced here.** `smcnoeject` and
        `smcnoblink` each replace a signature, measured in x360mcp along with what the
        original says when the signature is not there. A build that asks for either is
        refused rather than handed an SMC that quietly does not do what was asked.
        """
        plain = self.material.smc
        carried = None
        if plain is None:
            if self.dump is None:
                raise ValueError("this build has neither an smc.bin nor a dump to take "
                                 "an SMC from")
            carried = self.dump.smc
            plain = cipher.opened(carried)
        asked = [name for name in ("smcnoeject", "smcnoblink")
                 if getattr(self.config, name)]
        if asked:
            raise ValueError(
                "%s each patch the SMC at a signature of its own, and neither is "
                "reproduced here yet" % " and ".join(asked)
            )
        if self.config.patchsmc and self.image_type.name != "retail":
            patched = Smc(plain).patched()
            if patched != plain:
                logger.info("patching smc to remove the reset limit")
                plain, carried = patched, None
        if carried is not None:
            return carried
        if not seed:
            if self.dump is None:
                raise ValueError("sealing an SMC needs a seed, and there is no dump to "
                                 "take the console's own from")
            seed = self.dump.smc[:4]
        return cipher.sealed(plain, seed)

    def keyvault(self) -> bytes:
        """The console's keyvault, as the image carries it: sealed under its CPU key.

        `kv.bin` from the per-build directory when there is one, and the dump's own
        otherwise -- "reading data/kv.bin failed, using kv.bin from nand dump". A
        dump's keyvault is already sealed for this console, so it is carried as it
        stands rather than opened and closed again; the derivation is deterministic
        either way, and carrying it means a console whose keyvault this build cannot
        open still gets its own back.

        The original takes a plaintext `kv.bin` as well as a sealed one and says which
        it got; telling them apart is not measured here, so a file is passed through as
        it
        stands, and a build handing over the wrong shape is refused by the console
        rather than by this.
        """
        given = self.material.keyvault
        if given is not None:
            return given
        if self.dump is None:
            raise ValueError("this build has neither a kv.bin nor a dump to take a "
                             "keyvault from")
        return self.dump.sealed_keyvault

    def xell(self) -> bytes | None:
        """The loader, or None for an image type that carries none.

        `xell-gggggg.bin`, verbatim and exactly 0x40000 bytes, which is what every
        image measured carries at 0x70000. The material ships two others --
        `xell-1f.bin` and `xell-2f.bin` -- and which option reaches for them has not
        been measured, so nothing here pretends to choose between them.
        """
        if self.image_type.name == "retail":
            return None
        return self.material.xell("xell-gggggg.bin")

    def patch_slot(self) -> bytes:
        """What goes in the patch slot: one block, and a retail image leaves it erased.

        Sixteen bytes of 0xFF, then the **last** set of the release's patch file as it
        stands, sentinel included, then zeros to the end of the block. Byte-exact on six
        images the original built.

        Two things about which file that set comes from. A `glitch` image on a fat
        console takes it from `patches_fat.bin` while its bootloaders are patched from
        `patches_<board>.bin`: the original's own log says `patches_fat.bin` for every
        fat spelling that builds one -- zephyr, falcon and all six jaspers -- and
        `patches_<board>.bin` for the slim ones, and the bytes agree. A `glitch2`
        image reads the file named after the **family**, so all six jasper spellings
        read `patches_g2jasper.bin`, which is what `Board.section` is.

        And a `glitch2m` image puts a 0x60 prologue in front of the set: twelve fuse
        lines, the console's CPU key with
        each half written twice -- which is measured but not yet understood well enough
        to be produced here, so this refuses that type rather than writing a guess.
        """
        block = layout.BLOCK
        if self.image_type.patches is False:
            return b"\xff" * block
        if self.image_type.name == "glitch2m":
            raise ValueError(
                "a glitch2m patch slot begins with twelve fuse lines, and what fills "
                "two of them is not yet measured for every board"
            )
        fat = self.console.fat and self.image_type.name == "glitch"
        patches = self.release.patches(self.image_type, "fat" if fat else self.console)
        if patches is None:
            raise ValueError("this release ships no patch file for a %s %s image"
                             % (self.console.name, self.image_type.name))
        last = patches.set_raw(len(patches.sets) - 1)
        return (b"\xff" * 0x10 + last).ljust(block, b"\x00")

    def header(self, slots: int, ce_version: int, smc_length: int) -> bytes:
        """The image's first page, built from named fields rather than copied.

        Every byte of it is held against the pages of **sixteen images the original
        built**, and all sixteen agree, so a build with no dump to copy a page from
        produces the same page as one with a dump.

        What the caller says is what the page states about things it cannot see from
        here: where the slots begin, the version word -- which is CE's, 0x0760 for the
        release measured -- and how long the SMC is. Where the SMC goes follows from
        that length, because it ends where the keyvault begins; `layout.smc_at` is the
        rule, and a page stating a place that disagrees with the length is what it
        prevents.

        The rest follows from the console and the type:

        * the magic, and the entry point, which is 0x8000 on every image measured
        * the slot offset, **twice**: at 0x0C and again at 0x64
        * the copyright line, whose year is the board's, and a JTAG image carries the
          other year the board has
        * the word at 0x48: one for every hack measured and zero for retail
        * the boot flags at 0x4C -- see `boot_flags`
        * the keyvault, at 0x4000 and 0x4000 long on all sixteen, the two patch slots
          the page counts, and the keyvault's version word
        * the erase block at 0x70, which is the console's own: a falcon image says zero
          where a trinity one says 0x10000
        * nothing at 0x74, which is where a settings block's address would go; every
          image built leaves it zero and the original then goes looking -- "seeking smc
          config in dump...found at offset 0xf7c000"
        """
        head = Header.blank()
        head.version = ce_version
        head.entrypoint = layout.CHAIN_AT
        head.size = slots
        head.cf_at = slots
        year = self.console.notice_year(self.image_type.name)
        head.notice = NOTICE.replace(b"2010", b"%d" % year)
        head.before_flags = 0 if self.image_type.name == "retail" else 1
        head.boot_flags = self.boot_flags()
        head.keyvault_at = layout.KEYVAULT_AT
        head.keyvault_size = layout.KEYVAULT_AT
        head.patch_slots = 2
        head.keyvault_version = 0x0712
        head.block_size = (
            self.console.flash.block_size if self.console.flash.states_block_size else 0
        )
        head.smc_size = smc_length
        head.smc_at = layout.smc_at(smc_length)
        return bytes(head.image)

    def boot_flags(self) -> int:
        """The word at 0x4C, as far as this has measured it.

        Three readings over sixteen images, with every option that reaches these bytes
        left alone: zero for a retail image, 0x12 for a glitch of any kind -- the eject
        button, which is what a console starts XeLL on when nothing says otherwise --
        and 0x40012 for a JTAG one, whose extra bit is a tray-status check.

        Seven options land in these same bytes and none is reproduced here: `xellbutton`
        and `xellbutton2` name the button, `dualboot` is a byte of its own, and `nodvd`,
        `olddvd`, `cygnos` and `demon` each set or clear a bit. What each is worth was
        measured in x360mcp, a build at a time, and reading it across is its own step.
        Until then a build that sets any of them is refused rather than handed an image
        whose start-up is not what was asked for.
        """
        asked = [
            name for name in ("xellbutton2", "dualboot", "nodvd", "olddvd", "cygnos",
                              "demon")
            if getattr(self.config, name)
        ]
        if self.config.xellbutton != "eject":
            asked.append("xellbutton")
        if asked:
            raise ValueError(
                "%s reach the header's boot flags, and which byte each one writes has "
                "not been measured here yet" % ", ".join(sorted(asked))
            )
        if self.image_type.name == "retail":
            return 0
        return 0x40012 if self.image_type.name == "jtag" else 0x12

    def __repr__(self) -> str:
        return "Build(%s, %s)" % (self.image_type.name, self.console.name)
