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
import os
import time

from .. import boards
from ..boards.flash import PAGE
from ..chain import Fields, sealing
from ..chain.stage import LENGTH as STAGE_HEADER
from ..chain.stage import Stage
from ..config.options import BUTTONS
from ..crypto import smc as cipher
from ..crypto.keys import derive
from ..crypto.rc4 import rc4
from ..image import Dump, Header, Image, Keyvault
from ..image import anchor as anchors
from ..image import dump as dumps
from ..smc import Smc
from . import layout, security
from .filesystem import Filesystem

# The copyright line every image carries, with the year a build replaces. Read off the
# sixteen reference images, which carry two different years and nothing else different.
NOTICE = b"\xa9 2004-2010 Microsoft Corporation. All rights reserved."

# The kinds of stage that make up the chain proper. CF and CG are named by the same list
# and are not in it: they go in the slot behind the chain.
CHAIN_KINDS = ("CB", "CBA", "CBB", "CD", "CE")

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
        self._recipe = None

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
    def dump(self) -> Dump | None:
        """The console's own flash, or None when the material holds no dump.

        Read once: it is seventeen megabytes and nearly every region asks it something.
        **Read with its own geometry**, which `boards.for_dump` works out from the dump,
        and not with the geometry of the console being built for: a trinity dump builds
        a falcon image, and read as a falcon's its settings blobs are scanned at the
        wrong offsets.
        """
        if self._dump is None and self.material.dump is not None:
            raw = self.material.dump
            own = boards.for_dump(raw, self.console)
            bigffs = self.config.bigffs if own is self.console else False
            self._dump = Dump(raw, own, bigffs)
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
        given = self.material.smc
        carried = None
        if given is not None:
            plain = self._smc_in_the_clear(given)
        else:
            if self.dump is None:
                raise ValueError("this build has neither an smc.bin nor a dump to take "
                                 "an SMC from")
            carried = self.dump.smc
            plain = cipher.opened(carried)
        for name in ("smcnoeject", "smcnoblink"):
            if getattr(self.config, name):
                patched = Smc(plain).with_patch(name)
                if patched == plain:
                    logger.warning("could not patch the SMC for %s: its routine is not "
                                   "in this image", name)
                plain, carried = patched, None
        if self.config.patchsmc and self.image_type.name != "retail":
            patched = Smc(plain).patched()
            if patched != plain:
                logger.info("patching smc to remove the reset limit")
                plain, carried = patched, None
        self._check_smc(plain)
        if carried is not None:
            return carried
        if not seed:
            if self.dump is None:
                raise ValueError("sealing an SMC needs a seed, and there is no dump to "
                                 "take the console's own from")
            seed = self.dump.smc[:4]
        return cipher.sealed(plain, seed)

    def _smc_in_the_clear(self, given: bytes) -> bytes:
        """An `smc.bin` as handed over, opened if it was handed over sealed.

        The original's own test, read out of it at 0x41BABC: four zero bytes at the end
        mean the image is in the clear, since every plaintext SMC is padded that way;
        otherwise it says "SMC binary appears to be encrypted, attempting to decrypt..."
        and asks the same question of what comes out. An image that still does not end
        in zeros did not decrypt, which is fatal unless `smcnocheck` waives it.
        """
        if given[-4:] == bytes(4):
            return given
        plain = cipher.opened(given)
        if plain[-4:] != bytes(4) and not self.config.smcnocheck:
            raise ValueError("smc.bin is neither in the clear nor a valid, decryptable "
                             "SMC; smcnocheck builds with it all the same")
        return plain

    def _check_smc(self, plain: bytes) -> None:
        """What the original refuses an SMC for, and what `smcnocheck` waives.

        Its classifier at 0x40BD80, read out by x360mcp, calls an SMC clean when its
        checksum is one of the stock images, and otherwise asks by image type: a glitch
        image's SMC is clean while it still has its reset limit, a JTAG image's while it
        carries neither hack mark, a retail or development one's only when both hold,
        and a devgl one's never. Then three cases are fatal and `smcnocheck` waives
        exactly those three: a retail image over an SMC that is not clean, a JTAG image
        over one that is, and an SMC that would not decrypt. A glitch image over a clean
        SMC only draws a complaint.

        One more refusal is ours and not the original's: an SMC that is nothing but
        0x00 or 0xFF passes every test the original makes and is written, which gives a
        console no SMC at all. Agreed with the user as a deliberate divergence in
        x360mcp, and waived by `smcnocheck` like the rest.
        """
        if self.config.smcnocheck:
            return
        if set(plain) <= {0x00} or set(plain) <= {0xFF}:
            raise ValueError("this SMC is blank -- nothing but 0x00 or 0xFF -- and an "
                             "image built over it would have none; smcnocheck builds "
                             "with it all the same")
        smc, number = Smc(plain), self.image_type.number
        if smc.clean:
            clean = True
        elif number in (4, 5):
            clean = False
        elif number == 3:
            clean = smc.reset_limit >= 0
        elif number == 2:
            clean = not smc.marked
        else:
            clean = smc.reset_limit >= 0 and not smc.marked
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
        sealed = self.dump.sealed_keyvault
        if self.config.dvdkey and self.image_type.name != "retail":
            # The DVD key goes into the keyvault at 0x100 on every type but retail, as
            # the shipped ini says, and the keyvault is sealed again -- its nonce is
            # derived from what it holds, so this is deterministic.
            vault = Keyvault.opened(sealed, self.cpu_key)
            plain = bytearray(vault.plain)
            plain[0x100:0x110] = self.config.dvdkey
            sealed = Keyvault(bytes(plain)).sealed(self.cpu_key)
        return sealed

    def xell(self) -> bytes | None:
        """The loader, or None for an image type that carries none.

        `xell-gggggg.bin` for a glitch image and `xell-2f.bin` for a JTAG one, verbatim
        and exactly 0x40000 bytes: the original's default-name resolver chooses by the
        type alone (x360mcp read it out of the jump table at 0x4501E8), and every
        image measured carries the one it names.
        """
        if self.image_type.name == "retail":
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
        cbb = [one for one in files if one.kind == "CBB"]
        if not cbb:
            raise ValueError("fuses are built from the CB_B, and this chain has none")
        return self.fuses(cbb[0])

    def fuses(self, listed) -> bytes:
        """The fuses a loader hands a console in place of its own: 0x60 bytes.

        Twelve lines of eight bytes, each read out of the original's own code by
        x360mcp -- the template at 0x44A700 and the routines that fill it -- and every
        manufacturing and JTAG reference image agrees to the byte:

            line 0     C0FFFFFFFFFFFFFF
            line 1     six of 0x0F, then two bytes naming the console type
            line 2     one nibble of 0xF for each bit set in the CB's allow word,
                       counted from the top of the line
            lines 3-6  the CPU key, each half written twice
            lines 7-8  the lockdown value in 0xF nibbles, sixteen to a line
            lines 9-11 zero

        The type and the allow word are the big-endian word at 0x3B0 of `listed`, the
        CB the console is bound on: type in the top byte, allow in the low sixteen
        bits. A manufacturing chain's CB_B, a JTAG image's second CB.
        """
        if not self.cpu_key:
            raise ValueError("fuses carry the CPU key, and none was given")
        word = int.from_bytes(self.release.bootloader(listed)[0x3B0:0x3B4], "big")
        kind, allow = word >> 24, word & 0xFFFF
        types = {0: b"\x0f\x0f", 1: b"\x0f\xf0", 2: b"\xf0\x0f", 3: b"\xf0\xf0"}
        if kind not in types:
            raise ValueError("console type %#x is not one the original knows" % kind)
        sequence = 0
        for bit in range(16):
            if allow & (1 << bit):
                sequence |= 0xF << ((15 - bit) * 4)

        def unary(count: int) -> bytes:
            count = max(0, min(16, count))
            return int("F" * count + "0" * (16 - count), 16).to_bytes(8, "big")

        key = self.cpu_key
        return (bytes.fromhex("C0FFFFFFFFFFFFFF") + b"\x0f" * 6 + types[kind]
                + sequence.to_bytes(8, "big") + key[:8] * 2 + key[8:] * 2
                + unary(self.ldv) + unary(self.ldv - 16) + bytes(24))

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
            out += self._stage_body(one, index, len(listed))
        stages = [Stage(out, at) for at in offsets]
        for stage, nonce in zip(stages, self._nonces(stages), strict=True):
            stage.nonce = nonce
        keys = sealing.keys(stages, self.cpu_key or b"", self._second_pass_at(stages))
        binds = sealing.binding_at(stages)
        if binds < 0 and which > 0:
            binds = 0
        if binds >= 0:
            # Under the manufacturing regime the original computes no binding, and the
            # CB_B of an image it built that way carries sixteen zeros where the digest
            # would be. The switch is a bit in CB_A rather than the image type or the
            # file's name, which `Stage.manufacturing` reads.
            bound_to = None if stages[0].manufacturing else self.cpu_key
            at = offsets[binds] + STAGE_HEADER
            out[at:at + Fields.LENGTH * 2] = Fields.write(
                self.dump.pairing, bound_to, keys[binds],
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
            if run and one.kind not in CHAIN_KINDS[:-1]:
                runs.append(run)
                run = []
        if run:
            runs.append(run)
        return runs[which] if which < len(runs) else []

    def _stage_body(self, listed, index: int, of: int) -> bytes:
        """One stage in the clear, patched, and as long as its header will say.

        Padding to `SEAL_ALIGN` is part of what is sealed, so it is part of the stage
        rather than a gap between stages.
        """
        body = bytearray(self.release.bootloader(listed))
        which = self._patch_set_for(listed.kind, of)
        if which is not None:
            patches = self.patches
            if patches is not None and which < len(patches.sets):
                ends = max(one.at + one.length for one in patches.sets[which])
                if ends > len(body):
                    body += bytes(ends - len(body))
                body = bytearray(patches.over(bytes(body), which=which))
                Stage(body, 0).length = len(body) + -len(body) % SEAL_ALIGN
        return bytes(body) + bytes(-len(body) % SEAL_ALIGN)

    def _patch_set_for(self, kind: str, of: int):
        """Which set of the release's patch file this kind of stage takes, if any.

        The first set is CB_B's and the second is CD's. A JTAG image patches no stage of
        its chain, which is measured rather than assumed: its CB, CD and CE come out of
        the reference image as the release's files with nothing laid over them.
        """
        if self.image_type.name == "jtag":
            return None
        if kind == "CBB":
            return 0
        return 1 if kind == "CD" else None

    def _second_pass_at(self, stages) -> int:
        """Which stage runs its key through the console's key a second time.

        The original's own test, at 0x41C760: the chain has no CB_B and the image is
        retail. That is the stage behind the single CB, which is its CD.
        """
        if sealing.binding_at(stages) >= 0 or self.image_type.name != "retail":
            return -1
        return 1 if len(stages) > 1 else -1

    def _nonces(self, stages) -> list:
        """One nonce a stage, the console's own where there is a dump to read.

        **Matched by kind and not by position.** A chain with a single CB takes the
        dump's CB, CD and CE nonces and leaves the dump's CB_B out; taking them in order
        instead hands its CD the nonce of a CB_B, which reads as a chain and is not one.
        Measured on a fat glitch image and a JTAG one, both of which carry exactly the
        dump's CB_A, CD and CE nonces.

        A dump with nothing of that kind left to give, and a build with no dump at all,
        leave the original drawing one -- "initializing random nonces" -- so this draws
        one too.
        """
        left = {}
        if self.dump is not None:
            for stage in self.dump.chain.walked:
                left.setdefault(stage.tag, []).append(stage.nonce)
        out = []
        for stage in stages:
            own = left.get(stage.tag) or []
            if own:
                out.append(own.pop(0))
                continue
            logger.info("this dump has no %s nonce left to carry; drawing one",
                        stage.tag)
            out.append(os.urandom(0x10))
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

        Taken apart on every reference image and put back, the release's CF and CG come
        out changed in these places and nowhere else:

        * **Both nonces are the console's own**, taken from the dump's CF and the CG
          behind it -- the slot the console's values come from, the one with the
          largest lockdown value. Carried across releases: the dump's CF is 17502, the
          image's is 17559, and they share a nonce.
        * **CF says where the rest of CG is**: a count at 0x30 and then that many
          block numbers, one up from the other. The number is the block's place in the
          flash, not in the filesystem -- 0x34 on a 16 MB image and 0xAE0 on a 64 MB
          one, whose filesystem starts there. x360mcp read the routine that writes it,
          at 0x41C910, after first taking the numbers for versions.
        * **CF carries the console's pairing and lockdown value** at 0x21C, which is
          what `chain.Fields.in_cf` reads -- the pairing only where a chain binds to the
          console, zeros otherwise -- and the byte before them says which update slot
          this is.
        * **CF carries sixteen bytes binding it to the console**, at 0x220: an HMAC
          under the CPU key over everything before them, with the nonce replaced by the
          key it derives, so the CF is hashed as it will be read. Not the construction
          CB_B's binding uses; J-Runner's `Nand.calcCFhash` spells out the same one.

        Nothing else. CG's plaintext is the release's, byte for byte.
        """
        if self.dump is None:
            raise ValueError("an update slot carries the console's own values, and "
                             "there is no dump to take them from")
        if not self.cpu_key:
            raise ValueError("a CF binds itself to the console's CPU key, and none was "
                             "given")
        pairs = self._update_pairs()
        which %= len(pairs)
        cf_listed, cg_listed = pairs[which]
        cf = bytearray(self.release.bootloader(cf_listed))
        cg = bytearray(self.release.bootloader(cg_listed))
        own_cf = self.dump.chain.slot
        own_cg = Stage(own_cf.image, own_cf.at + own_cf.length)
        Stage(cf, 0).nonce = own_cf.nonce
        Stage(cg, 0).nonce = own_cg.nonce

        span = layout.slot_span(self.image_type, self.console.flash)
        spill = len(cf) + len(cg) - span
        count = max(0, -(-spill // layout.BLOCK))
        blocks = count.to_bytes(2, "big") + b"".join(
            (tail_at // layout.BLOCK + step).to_bytes(2, "big") for step in range(count)
        )
        cf[0x30:0x68] = blocks.ljust(0x68 - 0x30, b"\x00")
        if which < len(pairs) - 1:
            return self._sealed_pair(cf, cg, own_cg.nonce)
        cf[0x21B] = which
        # The pairing goes in only where a chain binds to the console. A chain with
        # no CB_B binds nowhere, and its CF carries three zeros there and the lockdown
        # value all the same -- measured on a fat glitch image, the one such chain this
        # release builds beside a slot. A JTAG image binds on its second chain's CB.
        binds = (any(one.kind == "CBB" for one in self._chain_files())
                 or bool(self._chain_files(1)))
        cf[0x21C:0x21F] = self.dump.pairing if binds else bytes(3)
        cf[0x21F] = self.ldv
        message = bytearray(cf[:0x220])
        message[0x20:0x30] = derive(sealing.ONE_BL_KEY, own_cf.nonce)
        cf[0x220:0x230] = derive(self.cpu_key, bytes(message))
        return self._sealed_pair(cf, cg, own_cg.nonce)

    @staticmethod
    def _sealed_pair(cf: bytearray, cg: bytearray, cg_nonce: bytes) -> bytes:
        """CF under the 1BL key, and CG under the key CF carries at 0x330."""
        sealed_cf = sealing.under(Stage(bytes(cf), 0), sealing.ONE_BL_KEY)
        # CG is sealed over its padding too, as every stage is: its tail file is ten
        # bytes longer than CG says it is, and those ten are the stream carrying on.
        cg += bytes(-len(cg) % SEAL_ALIGN)
        head = len(Stage(cg, 0).head)
        key = derive(bytes(cf[0x330:0x340]), cg_nonce)
        return sealed_cf + bytes(cg[:head]) + rc4(key, bytes(cg[head:]))

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
        if not pairs:
            raise ValueError("this release names no CF and CG for a %s %s image"
                             % (self.console.name, self.image_type.name))
        return pairs

    def files(self, when: int) -> list:
        """The files the filesystem holds after the CG's tail, as `(name, bytes)`.

        The release's `[flashfs]` list and then its `[security]` list, each in the
        order it names them -- which is the order of every reference image's table.

        A patch file is written under its name with the number of update slots after
        it: `aac.xexp` goes in as `aac.xexp1` and `xenonclatin.xttp` as
        `xenonclatin.xttp1`, all seven of them on every image measured -- and as
        `aac.xexp2` on the JTAG one, which has two.

        A file the list names outside the release that is not there -- `..\\launch.xex`
        and its two neighbours -- is left out, as the original leaves it; its list
        states a checksum of zero, which is how it says the file is optional.
        """
        recipe = self.recipe
        out = []
        suffix = str(len(self._update_pairs()))
        for listed in recipe.firmware:
            body = self.release.firmware(listed)
            if body is None:
                if listed.outside:
                    logger.info("%s is not there and is optional", listed.plain)
                    continue
                raise ValueError("%s is named by the file list and the release does "
                                 "not have it" % listed.plain)
            name = listed.plain
            if name.lower().endswith(("xexp", "xttp")):
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
        content = self.material.bytes_in(name)
        if content is None and name in ("crl.bin", "dae.bin") and \
                not config.nosusecurity and name in self.release.container.held:
            content = self.release.container.read(name)
        if content is None:
            content = own
        cpu, ldv = self.cpu_key, self.ldv
        if name == "crl.bin":
            if content is None:
                return None
            if own is not None:
                iv, key = security.crl_parameters(own, cpu)
            else:
                iv, key = security.COMPILED_IN[name]
            return security.crl(content, cpu, when, ldv, iv, key)
        if name == "dae.bin":
            if content is None:
                return None
            if own is not None:
                head, field = security.dae_parameters(own, cpu)
            else:
                head, field = security.COMPILED_IN[name]
            return security.dae(content, cpu, when, ldv, head, field)
        if name == "extended.bin":
            vault = self.dump.keyvault(cpu).plain
            return security.extended(content, vault[0x10:0x18], cpu)
        if name == "secdata.bin":
            head = b"" if own is not None else security.COMPILED_IN[name]
            return security.secdata(content, cpu, when, ldv, head)
        if name == "fcrt.bin":
            return None if content is None else security.fcrt(content, cpu)
        raise ValueError("%s is not one of the five security files" % name)

    @property
    def ldv(self) -> int:
        """The lockdown value written into the chain's CF and three security files.

        `cfldv` when it is given, the console's own -- read off its CF -- otherwise.
        """
        if self.config.cfldv is not None:
            return self.config.cfldv
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
        flash, bigffs = self.console.flash, self.config.bigffs
        out = Image.blank(flash, bigffs)
        base = flash.base_of(bigffs) * layout.BLOCK

        chain = self.chain()
        chain_end = layout.CHAIN_AT + len(chain)
        second = self.chain(1) if self._chain_files(1) else b""
        where = layout.for_type(self.image_type, flash, chain_end, bigffs, len(second))
        slots, tail_at = where["slot"][0], where["tail"][0]
        smc = self.smc()
        smc_at = layout.smc_at(len(smc))
        page = self.header(slots, self.ce_version, len(smc))
        # Zeros from the page to the SMC, on every reference image.
        out.put(0, page + bytes(smc_at - len(page)))
        out.put(smc_at, smc)
        out.put(layout.KEYVAULT_AT, self.keyvault())
        # The chain's last block is filled out with zeros, as a file's is.
        out.put(layout.CHAIN_AT, chain + bytes(-chain_end % layout.BLOCK))
        xell = self.xell()
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
            # 11 of its spare -- the one page of any image with anything there. See
            # `_jtag_regions`.
            words = len(self._jtag_loader("freeboot.bin")) // 4
            out.mark(where["payload"][0], PAGE, extra=words.to_bytes(4, "big"))

        big = flash.spare is not None and flash.spare.fs_at is not None
        first = (tail_at - base) // layout.BLOCK
        if flash.spare is None:
            # No bad blocks to stand in for, so no pool: an eMMC's table reserves every
            # block from the last one a build may use to the end of the part -- six on
            # the one measured, where the anchors and the settings live.
            held = flash.blocks - (flash.last_block - base // layout.BLOCK)
            fs = Filesystem(flash, first, bigffs, pool=0, held=held)
        else:
            fs = Filesystem(flash, first, bigffs, held=0 if big else 4)
        stamp = self._fat(when)
        # The tail is the first file on every shape of flash, and a JTAG image's two
        # are the first two.
        for index, spill in enumerate(spills):
            fs.add("sysupdate.xexp%d" % (index + 1), spill, stamp=stamp)
        for name, body in self.files(when):
            fs.add(name, body, stamp=stamp)
        fs.over(out)
        start = flash.offset_of(fs.after, bigffs)
        blobs = {} if self.config.nomobile else self._mobiles()
        # The settings blobs get a region of their own after the files, and the table
        # follows it; with none to write there is no region, and the table goes
        # straight after the files -- measured with `nomobile`, and x360mcp saw the same
        # on a build with no dump.
        if blobs:
            # Their region starts on the flash's own step: a jasperbb's files end at
            # 0x38D0000 and its blobs go to 0x38E0000 -- measured, and x360mcp had the
            # same four boards' table. On every other part the files already end on one.
            start += -start % flash.round_to
            fs.skipped = range(fs.after, (start - base) // layout.BLOCK)
        table_at = start + (flash.mobile_region if blobs else 0)
        # On a big block chip the pages of the filesystem carry three bytes of its own
        # and a kind of their own; everywhere else a file's pages carry a block number.
        fields = self._fs_fields(slots) if big else b""
        for entry, blocks, body in fs.placed:
            at = flash.offset_of(entry.sector, bigffs)
            span = blocks * layout.BLOCK
            # A file that fits in one block leaves its padding's fields erased on a big
            # block chip, with a real code over the zeros: measured on four such files
            # in a jasperbb image and seen again here. A longer file's padding is
            # written like the rest of it, and nothing of this on a 16 MB image.
            if big and blocks == 1:
                span = -(-len(body) // PAGE) * PAGE
            out.mark(at, span, 0, 0x2A if big else 0, fs=fields)

        placed = {}
        for index, name in enumerate(sorted(blobs)):
            at = start + index * flash.mobile_stride
            body, kind = blobs[name], 0x31 + "BCDE".index(name[6])
            out.put(at, body)
            placed[kind] = ((at - base) // layout.BLOCK, len(body))
            if flash.spare is None:
                continue
            per = flash.spare.pages_a_block
            pages = max(1, len(body) // PAGE)
            free = per - (at // PAGE) % per - pages
            # A byte does not hold what is free of 256 pages, so a big block chip counts
            # it in fours -- 0x3F, 0x3E, 0x3D, 0x3C down a block, measured.
            free >>= 2 if big else 0
            out.mark(at, pages * PAGE, 1, kind,
                     bytes([len(body) // 0x100, free, 0, 0]),
                     b"\x00" if big else b"")
        fs.table_at = (table_at - base) // layout.BLOCK
        table = fs.table()
        out.put(table_at, table)
        # The table's kind moves with the filesystem's: 0x30 on a 16 MB image, 0x2C on
        # a big block chip, where it keeps the filesystem's three bytes.
        out.mark(table_at, len(table), 1, 0x2C if big else 0x30, fs=fields)

        for at, body, span in self._settings():
            out.put(at, body)
            out.mark(at, span)
        if flash.anchors:
            anchors.lay(out, fs.table_at, placed)
        for name, at in self.config.raw_patches:
            # "[rawpatch]": raw bytes into the flat image, "just before combining spare
            # and finalizing ecc". The spare's fields are already settled by then, so a
            # patch over erased flash leaves its pages' fields erased and only the code
            # follows the new bytes -- measured at 0xC4200. Relative to the release, as
            # the original looks for the file.
            out.put(at, self.release.raw_file(name))
        return out

    def _jtag_regions(self, out: Image, where: dict, second: bytes) -> None:
        """What a JTAG image carries past its slots: the loaders its hack runs on.

        Each at the address the reboot core has compiled into it -- see `layout`.

        * **payload.bin**, the page after the header, with the core's length in words
          written into it at 0x52: the operand of the `li r4` that sets how much it
          copies. "patching payload.bin to load size 0xd40 (0x350 reps)".
        * **freeboot.bin**, the core, with the release's kernel version written over the
          thirty-two X's it carries for one. "patching freeboot.bin with kernel version
          string '17559'". Zeros to the patch list.
        * **the patch list**, the whole patch file -- see `patch_slot` -- and zeros to
          the end of the block. The block after it is erased and still marked written,
          which is the rest of the list's 0x4000: x360mcp measured the eight pages.
        * **the fuses**, from the second chain's CB -- see `fuses`.
        * **the second chain**, and zeros to the end of its block.

        All of it byte for byte against the reference image.
        """
        payload = bytearray(self._jtag_loader("payload.bin"))
        core = bytearray(self._jtag_loader("freeboot.bin"))
        payload[0x52:0x54] = (len(core) // 4).to_bytes(2, "big")
        out.put(where["payload"][0], bytes(payload))
        blank = core.find(b"X" * 0x20)
        if blank < 0:
            # The original says so and carries on; whether anything else follows from
            # it has not been measured.
            logger.error("**** ERROR PATCHING FREEBOOT.BIN for kernel version string!")
        else:
            version = self.recipe.version.encode("ascii")
            core[blank:blank + 0x20] = version.ljust(0x20, b"\x00")[:0x20]
        at, room = where["freeboot"]
        out.put(at, bytes(core).ljust(room, b"\x00"))
        listed = self.patch_slot()
        at, room = where["patches"]
        if len(listed) > room:
            raise ValueError("a patch list of %#x bytes does not fit the %#x the core "
                             "reads" % (len(listed), room))
        out.put(at, listed + bytes(-(at + len(listed)) % layout.BLOCK))
        out.mark(at, room)
        out.put(where["fuses"][0], self.fuses(self._chain_files(1)[0]))
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
        path = os.path.join(os.path.dirname(__file__), "builtin", name)
        with open(path, "rb") as handle:
            return handle.read()

    def _fs_fields(self, slots: int) -> bytes:
        """The three bytes a big block chip's filesystem pages carry at 7.

        free60's FsSize1, FsSize0 and FsPageCount. The first says how much of the flash
        the system area takes, in blocks of 0x20000: all of the first 2 MB on an image
        that carries XeLL -- 0x10, on all three glitch types measured -- and on a retail
        one where its bootloader region ends, the slot and the patch slot included,
        which is 5 on the trinitybb measured. The second is the filesystem's size in
        blocks over 32, and the third is 4 on every image measured.
        """
        flash = self.console.flash
        if self.xell() is not None:
            system = 0x10
        else:
            span = layout.slot_span(self.image_type, flash)
            system = (slots + 2 * span) // 0x20000
        size = flash.last_block - flash.base_of(self.config.bigffs)
        return bytes([system, size >> 5, 4])

    @staticmethod
    def _fat(when: int) -> int:
        """The build's time as a directory entry keeps it: a FAT date and time.

        In UTC and two seconds on, the same two seconds the security files' stamp
        carries -- the reference images' entries say 15:17:50 where the build began at
        15:17:48 UTC. FAT counts seconds in twos.
        """
        at = time.gmtime(when + 2)
        date = ((at.tm_year - 1980) << 9) | (at.tm_mon << 5) | at.tm_mday
        clock = (at.tm_hour << 11) | (at.tm_min << 5) | (at.tm_sec // 2)
        return (date << 16) | clock

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
        if self.dump is None:
            return []
        flash = self.console.flash
        span = 0x1000
        stats_at = flash.smc_config - flash.round_to
        out = []
        if self.dump.manufacturing_written:
            out.append((stats_at - flash.round_to, self.dump.manufacturing, span))
        if not self.config.nomobile:
            out.append((stats_at, self.dump.statistics, span))
        config = self.material.smc_config
        if config is None:
            # Where the dump keeps it is the dump's own flash's business, not the one
            # being built for: a 16 MB dump builds a 64 MB image.
            own = self.dump.flash.smc_config
            config = bytes(self.dump.image.flat[own:own + span])
        out.append((flash.smc_config, self._configured(config), span))
        return out

    def _configured(self, block: bytes) -> bytes:
        """The settings block with the options that land in it written in.

        Each field was found by x360mcp building twice, once with the option and once
        without, and reading the difference; J-Runner's own field table agrees on every
        one it has:

            0x11  CPU fan, 0x12  GPU fan         0x80 | percent; zero leaves it on auto
            0x29..0x2B  CPU, GPU, EDRAM target temperature, Centigrade
            0x2C..0x2E  CPU, GPU, EDRAM overheat temperature
            0x220  MAC address, six bytes
            0x22A  video region, 0x22C  game region, both sixteen bits big-endian
            0x237  DVD region, one byte

        The head then says the block's checksum again, which `image.dump.checksum`
        computes over 0x10 to 0x10C; the fields past 0x220 lie outside it, which is why
        changing them never moved the head in any measurement.
        """
        config = self.config
        out = bytearray(block)
        for at, name in ((0x11, "cpufan"), (0x12, "gpufan")):
            if getattr(config, name):
                out[at] = 0x80 | getattr(config, name)
        for at, name in ((0x29, "cputemp"), (0x2A, "gputemp"), (0x2B, "edramtemp"),
                         (0x2C, "overcputemp"), (0x2D, "overgputemp"),
                         (0x2E, "overedramtemp")):
            if getattr(config, name):
                out[at] = getattr(config, name)
        if config.macid:
            out[0x220:0x226] = config.macid
        for at, name in ((0x22A, "avregion"), (0x22C, "gameregion")):
            if getattr(config, name):
                out[at:at + 2] = getattr(config, name).to_bytes(2, "big")
        if config.dvdregion:
            out[0x237] = config.dvdregion & 0xFF
        if bytes(out) != bytes(block):
            out[0:2] = dumps.checksum(out).to_bytes(2, "little")
        return bytes(out)

    @property
    def ce_version(self) -> int:
        """The version word the image's page states, which is CE's own.

        0x0760 for the release measured, and the page of every reference image says the
        same as the CE the release ships.
        """
        for one in self.stage_list:
            if one.kind == "CE":
                return Stage(self.release.bootloader(one), 0).build
        raise ValueError("this release names no CE for a %s %s image"
                         % (self.console.name, self.image_type.name))

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
        return self.release.patches(self.image_type, "fat" if fat else self.console,
                                    self.config.section_ext or "")

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
        head.version = ce_version
        head.entrypoint = layout.CHAIN_AT
        head.size = slots
        head.cf_at = slots
        year = self.console.notice_year(self.image_type.name)
        head.notice = NOTICE.replace(b"2010", b"%d" % year)
        head.before_flags = 0 if self.image_type.name == "retail" else 1
        head.boot_flags = self.boot_flags()
        head.keyvault_at = layout.KEYVAULT_AT
        if self.console.states_keyvault_size:
            head.keyvault_size = layout.KEYVAULT_AT
        head.patch_slots = 2
        head.keyvault_version = 0x0712
        head.block_size = self.console.stated_block_size()
        if head.block_size and self.image_type.name == "jtag":
            # A JTAG image states the 16 MB step whatever the part's own is: x360mcp
            # measured `-t jtag -c jasper256`, whose flash steps 0x20000 and whose image
            # says 0x10000 here.
            head.block_size = 0x10000
        head.smc_size = smc_length
        head.smc_at = layout.smc_at(smc_length)
        return bytes(head.image)

    def boot_flags(self) -> int:
        """The word at 0x4C: four bytes that decide how the console starts.

        Measured by x360mcp a build at a time, each option against a reference:

            0x4C  the button that makes a two-NAND console switch -- `dualboot`, on a
                  JTAG image only, and zero when it names the button XeLL starts on
            0x4D  a bitfield: 1 for `cygnos` or `demon`, which write the same byte; on a
                  JTAG image 2 for `nodvd` and otherwise 4, the tray check it starts on,
                  unless `olddvd` asks for the older way
            0x4E  a second reason XeLL starts on, `xellbutton2`, zero when it is the
            same 0x4F  the reason XeLL starts on, `xellbutton`; `nodvd` and `olddvd`
            clear it

        A retail image carries XeLL on no button at all and the word is zero, which the
        reference images show.
        """
        if self.image_type.name == "retail":
            return 0
        config, jtag = self.config, self.image_type.name == "jtag"
        if config.nodvd or config.olddvd:
            reason = 0
        else:
            reason = BUTTONS[config.xellbutton or "eject"]
        second = 0
        if config.xellbutton2:
            second = BUTTONS[config.xellbutton2]
            second = 0 if second == reason else second
        speed = 1 if (config.cygnos or config.demon) else 0
        if jtag:
            if config.nodvd:
                speed |= 2
            elif not config.olddvd:
                speed |= 4
        switch = 0
        if jtag and config.dualboot:
            switch = BUTTONS[config.dualboot]
            switch = 0 if switch == reason else switch
        return (switch << 24) | (speed << 16) | (second << 8) | reason

    def __repr__(self) -> str:
        return "Build(%s, %s)" % (self.image_type.name, self.console.name)
